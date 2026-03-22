"""
rag.py — RAG (Retrieval-Augmented Generation) engine + FastAPI router.

Endpoints
---------
  POST   /upload                    — upload tài liệu (PDF / DOCX / TXT)
  GET    /documents                 — danh sách tài liệu đã upload
  DELETE /documents/{doc_id}        — xóa tài liệu
  POST   /v1/rag/chat               — RAG chat với masking tích hợp

RAG pipeline (4 giai đoạn)
---------------------------
  R-1 RAG_RECV     : nhận query gốc, ghi log
  R-2 RAG_RETRIEVE : mask(query) → semantic search → log chunks
  R-3 RAG_MASK_CTX : mask(context) → log [Doc_ID]→[Extracted]→[Masked]
  R-4 RAG_SEND     : LLM call → demask(answer) → return

Lưu trữ
--------
  chroma_db/           — ChromaDB persistent vector store
  chroma_db/registry.json — metadata registry cho GET /documents
"""

import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse

from .masker import TAG_SYSTEM_INSTRUCTION
from .state import masker
from .config import validate_role, get_role_prompt, DEFAULT_ROLE
from .rag_logger import (
    log_rag_recv,
    log_rag_retrieve,
    log_rag_mask_ctx,
    log_rag_send,
    log_rag_error,
)

logger = logging.getLogger("gateway")

# ---------------------------------------------------------------------------
# Cấu hình
# ---------------------------------------------------------------------------

OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")

CHROMA_PATH = Path(os.getenv("CHROMA_PATH", "chroma_db"))
REGISTRY_FILE = CHROMA_PATH / "registry.json"
COLLECTION_NAME = "knowledge_base"

DEFAULT_TOP_K = 4
DEFAULT_MODEL = "gpt-4o-mini"

router = APIRouter(tags=["RAG"])

# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

def _load_registry() -> dict:
    if REGISTRY_FILE.exists():
        try:
            return json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save_registry(registry: dict) -> None:
    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    REGISTRY_FILE.write_text(
        json.dumps(registry, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# ChromaDB / LangChain lazy init
# ---------------------------------------------------------------------------

_vectorstore = None


def _get_vectorstore():
    """Lazy-init ChromaDB vectorstore (tránh import chậm khi khởi động)."""
    global _vectorstore
    if _vectorstore is not None:
        return _vectorstore

    try:
        import chromadb
        from langchain_chroma import Chroma
        from langchain_openai import OpenAIEmbeddings

        CHROMA_PATH.mkdir(parents=True, exist_ok=True)
        chroma_client = chromadb.PersistentClient(path=str(CHROMA_PATH))

        embeddings = OpenAIEmbeddings(
            openai_api_key=OPENAI_API_KEY,
            base_url=OPENAI_BASE_URL if OPENAI_BASE_URL != "https://api.openai.com/v1" else None,
        )

        _vectorstore = Chroma(
            client=chroma_client,
            collection_name=COLLECTION_NAME,
            embedding_function=embeddings,
        )
        logger.info("ChromaDB vectorstore khởi tạo thành công tại %s", CHROMA_PATH)
    except Exception as exc:
        logger.error("Không thể khởi tạo ChromaDB: %s", exc)
        raise RuntimeError(f"ChromaDB init failed: {exc}") from exc

    return _vectorstore


# ---------------------------------------------------------------------------
# Document loaders
# ---------------------------------------------------------------------------

def _load_documents(file_path: str, filename: str) -> list:
    """Load tài liệu từ file vật lý, trả về list[Document]."""
    ext = Path(filename).suffix.lower()

    if ext == ".pdf":
        from langchain_community.document_loaders import PyPDFLoader
        loader = PyPDFLoader(file_path)
    elif ext in (".docx", ".doc"):
        from langchain_community.document_loaders import Docx2txtLoader
        loader = Docx2txtLoader(file_path)
    elif ext == ".txt":
        from langchain_community.document_loaders import TextLoader
        loader = TextLoader(file_path, encoding="utf-8")
    else:
        raise ValueError(f"Định dạng không được hỗ trợ: {ext}. Chỉ hỗ trợ PDF, DOCX, TXT.")

    return loader.load()


def _split_documents(docs: list) -> list:
    """Chia tài liệu thành các chunk nhỏ."""
    from langchain.text_splitter import RecursiveCharacterTextSplitter

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=100,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    return splitter.split_documents(docs)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    description: str = Form(""),
) -> dict:
    """
    Upload tài liệu vào Knowledge Base.
    Hỗ trợ: PDF, DOCX, TXT.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY is not configured.")

    filename = file.filename or "unknown"
    doc_id = uuid.uuid4().hex[:12]
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Lưu file tạm để các loader có thể đọc qua file path
    suffix = Path(filename).suffix.lower()
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # Load + split
        docs = _load_documents(tmp_path, filename)
        chunks = _split_documents(docs)

        if not chunks:
            raise HTTPException(status_code=422, detail="Tài liệu rỗng hoặc không thể đọc.")

        # Gắn metadata doc_id vào mỗi chunk
        for chunk in chunks:
            chunk.metadata["doc_id"] = doc_id
            chunk.metadata["filename"] = filename

        # Nạp vào vectorstore
        vs = _get_vectorstore()
        vs.add_documents(chunks)

        # Cập nhật registry
        registry = _load_registry()
        registry[doc_id] = {
            "doc_id":      doc_id,
            "filename":    filename,
            "description": description,
            "chunk_count": len(chunks),
            "char_count":  sum(len(c.page_content) for c in chunks),
            "uploaded_at": ts,
        }
        _save_registry(registry)

        logger.info(
            "Upload OK  doc_id=%s  file=%s  chunks=%d",
            doc_id, filename, len(chunks),
        )
        return {
            "doc_id":      doc_id,
            "filename":    filename,
            "chunk_count": len(chunks),
            "uploaded_at": ts,
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Upload FAIL  file=%s  error=%s", filename, exc)
        raise HTTPException(status_code=500, detail=f"Lỗi xử lý tài liệu: {exc}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.get("/documents")
async def list_documents() -> list:
    """Danh sách tất cả tài liệu đã upload."""
    registry = _load_registry()
    return list(registry.values())


@router.delete("/documents/{doc_id}")
async def delete_document(doc_id: str) -> dict:
    """Xóa tài liệu khỏi Knowledge Base và ChromaDB."""
    registry = _load_registry()
    if doc_id not in registry:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy doc_id '{doc_id}'")

    try:
        vs = _get_vectorstore()
        # Xóa tất cả chunk có doc_id này
        vs.delete(where={"doc_id": doc_id})
    except Exception as exc:
        logger.warning("Không thể xóa chunk từ ChromaDB: %s", exc)

    info = registry.pop(doc_id)
    _save_registry(registry)

    logger.info("Deleted doc_id=%s  file=%s", doc_id, info.get("filename"))
    return {"deleted": doc_id, "filename": info.get("filename")}


# ---------------------------------------------------------------------------
# RAG Chat endpoint
# ---------------------------------------------------------------------------

@router.post("/v1/rag/chat")
async def rag_chat(request: Request) -> JSONResponse:
    """
    RAG chat với masking tích hợp.

    Body JSON:
      {
        "query":      "câu hỏi",
        "session_id": "abc123",          // tuỳ chọn
        "model":      "gpt-4o-mini",     // tuỳ chọn
        "top_k":      4,                 // tuỳ chọn
        "messages":   [...],             // lịch sử chat tuỳ chọn
        "temperature": 0.7,             // tuỳ chọn
        "max_tokens":  2048,            // tuỳ chọn
      }
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY is not configured.")

    body: dict[str, Any] = await request.json()

    query: str = body.get("query", "").strip()
    if not query:
        raise HTTPException(status_code=422, detail="'query' field is required.")

    session_id: str = body.get("session_id") or uuid.uuid4().hex[:8]
    model: str = body.get("model", DEFAULT_MODEL)
    top_k: int = int(body.get("top_k", DEFAULT_TOP_K))
    history: list[dict] = body.get("messages", [])
    temperature: float = float(body.get("temperature", 0.7))
    max_tokens: int = int(body.get("max_tokens", 2048))
    role: str = validate_role(body.get("role", DEFAULT_ROLE))

    request_id: str = uuid.uuid4().hex[:8].upper()

    # ── R-1: RAG_RECV ─────────────────────────────────────────────────────────
    log_rag_recv(request_id, session_id, query, model, top_k)

    # ── R-2: RAG_RETRIEVE ─────────────────────────────────────────────────────
    masked_query = masker.mask(query, session_id, request_id)

    try:
        vs = _get_vectorstore()
        results = vs.similarity_search_with_score(masked_query, k=top_k)
    except Exception as exc:
        log_rag_error(request_id, session_id, "RETRIEVE", str(exc))
        raise HTTPException(status_code=500, detail=f"Lỗi tìm kiếm vector: {exc}")

    chunks_log = []
    for doc, score in results:
        chunks_log.append({
            "doc_id":   doc.metadata.get("doc_id", "unknown"),
            "filename": doc.metadata.get("filename", ""),
            "score":    round(float(score), 4),
            "content":  doc.page_content[:200],
        })
    log_rag_retrieve(request_id, session_id, masked_query, chunks_log)

    # ── R-3: RAG_MASK_CTX ─────────────────────────────────────────────────────
    context_parts = []
    context_mapping = []

    for doc, score in results:
        doc_id = doc.metadata.get("doc_id", "unknown")
        original_ctx = doc.page_content
        masked_ctx = masker.mask(original_ctx, session_id, request_id)
        changed = original_ctx != masked_ctx

        context_parts.append(
            f"[Nguồn: {doc.metadata.get('filename', doc_id)}]\n{masked_ctx}"
        )
        context_mapping.append({
            "doc_id":    doc_id,
            "filename":  doc.metadata.get("filename", ""),
            "extracted": original_ctx[:200],
            "masked":    masked_ctx[:200],
            "changed":   changed,
        })

    log_rag_mask_ctx(request_id, session_id, context_mapping)

    context_block = "\n\n---\n\n".join(context_parts)

    # ── R-4: RAG_SEND — gọi LLM ───────────────────────────────────────────────
    role_prompt = get_role_prompt(role)
    system_content = (
        role_prompt
        + "\n\n"
        + TAG_SYSTEM_INSTRUCTION
        + "\n\nBạn có quyền truy cập vào Knowledge Base nội bộ. "
        "Hãy trả lời câu hỏi DỰA TRÊN ngữ cảnh được cung cấp. "
        "Nếu ngữ cảnh không đủ thông tin, hãy nói rõ điều đó thay vì bịa đặt.\n\n"
        f"=== NGỮ CẢNH TỪ KNOWLEDGE BASE ===\n{context_block}\n=== KẾT THÚC NGỮ CẢNH ==="
    )

    messages_to_send: list[dict] = [{"role": "system", "content": system_content}]
    # Thêm lịch sử chat (đã mask trong các lượt trước)
    for msg in history:
        content = msg.get("content", "")
        if isinstance(content, str) and content:
            messages_to_send.append({
                **msg,
                "content": masker.mask(content, session_id, request_id),
            })
        else:
            messages_to_send.append(msg)
    # Thêm query đã mask
    messages_to_send.append({"role": "user", "content": masked_query})

    payload = {
        "model":       model,
        "messages":    messages_to_send,
        "temperature": temperature,
        "max_tokens":  max_tokens,
    }

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            oai_resp = await client.post(
                f"{OPENAI_BASE_URL}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
    except httpx.TimeoutException as exc:
        log_rag_error(request_id, session_id, "LLM", f"TimeoutException: {exc}")
        raise HTTPException(status_code=504, detail="LLM không phản hồi trong 120s.")
    except httpx.RequestError as exc:
        log_rag_error(request_id, session_id, "LLM", str(exc))
        raise HTTPException(status_code=502, detail=f"Không kết nối được LLM: {exc}")

    if oai_resp.status_code != 200:
        log_rag_error(request_id, session_id, "LLM", f"HTTP {oai_resp.status_code}", oai_resp.text[:500])
        raise HTTPException(status_code=oai_resp.status_code, detail=oai_resp.text)

    oai_result: dict = oai_resp.json()
    answer_masked: str = oai_result.get("choices", [{}])[0].get("message", {}).get("content", "")
    answer_final: str = masker.demask(answer_masked, session_id)

    usage = oai_result.get("usage", {})
    log_rag_send(
        request_id, session_id, answer_masked, answer_final,
        {
            "prompt_tokens":     usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens":      usage.get("total_tokens", 0),
        },
    )

    # Trả về response theo định dạng OpenAI-compatible
    oai_result["choices"][0]["message"]["content"] = answer_final

    return JSONResponse(content={
        **oai_result,
        "_rag_meta": {
            "request_id":  request_id,
            "session_id":  session_id,
            "chunks_used": len(results),
            "top_k":       top_k,
        },
    })
