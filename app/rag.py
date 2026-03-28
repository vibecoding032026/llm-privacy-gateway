"""
rag.py — RAG (Retrieval-Augmented Generation) engine + FastAPI router.

Endpoints
---------
  POST   /upload                    — upload tài liệu (PDF / DOCX / TXT / ảnh)
  GET    /documents                 — danh sách tài liệu đã upload
  DELETE /documents/{doc_id}        — xóa tài liệu
  POST   /v1/rag/chat               — RAG chat với masking tích hợp

Định dạng hỗ trợ
----------------
  Văn bản : PDF (có text layer), DOCX, DOC, TXT
  Ảnh     : PNG, JPG, JPEG, TIFF, WEBP, BMP
  PDF scan: PDF không có text layer → tự động nhận diện và OCR bằng OpenAI Vision

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

import base64
import io
import json
import logging
import os
import re
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Tắt noise log từ bug ChromaDB telemetry (chromadb 0.5.x + posthog API mismatch)
logging.getLogger("chromadb.telemetry").setLevel(logging.CRITICAL)

import httpx
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse

from .masker import TAG_SYSTEM_INSTRUCTION
from .state import masker
from .config import validate_role, get_role_prompt, DEFAULT_ROLE, ROLE_NAMES
from .dependencies import CurrentUser, AdminUser, require_admin
from .audit_logger import audit_upload_doc, audit_delete_doc, audit_access_doc
from .usage_logger import log_usage
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

OPENAI_API_KEY: str  = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OCR_MODEL: str       = os.getenv("OCR_MODEL", "gpt-4o-mini")   # model vision để OCR

# Các định dạng ảnh được hỗ trợ trực tiếp
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".webp", ".bmp"}
# Ngưỡng ký tự trung bình/trang để phát hiện PDF scan (không có text layer)
_SCAN_THRESHOLD = 80

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
        settings = chromadb.Settings(anonymized_telemetry=False)
        chroma_client = chromadb.PersistentClient(path=str(CHROMA_PATH), settings=settings)

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
# OCR via OpenAI Vision
# ---------------------------------------------------------------------------

def _image_bytes_to_base64(image_bytes: bytes, mime: str = "image/jpeg") -> str:
    return f"data:{mime};base64,{base64.b64encode(image_bytes).decode()}"


def _ocr_page(image_bytes: bytes, page_label: str) -> str:
    """
    Trích xuất văn bản từ ảnh bằng OpenAI Vision API.
    Dùng cho: ảnh trực tiếp hoặc từng trang PDF scan.
    """
    from openai import OpenAI

    client = OpenAI(
        api_key=OPENAI_API_KEY,
        base_url=OPENAI_BASE_URL if OPENAI_BASE_URL != "https://api.openai.com/v1" else None,
    )
    # Xác định MIME type từ magic bytes
    mime = "image/jpeg"
    if image_bytes[:4] == b"\x89PNG":
        mime = "image/png"
    elif image_bytes[:4] in (b"II*\x00", b"MM\x00*"):
        mime = "image/tiff"
    elif image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP":
        mime = "image/webp"

    try:
        resp = client.chat.completions.create(
            model=OCR_MODEL,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Trích xuất toàn bộ nội dung văn bản từ ảnh này. "
                            "Giữ nguyên cấu trúc, xuống dòng và thứ tự nội dung. "
                            "Chỉ trả về nội dung văn bản thuần, không thêm giải thích hay chú thích."
                        ),
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": _image_bytes_to_base64(image_bytes, mime)},
                    },
                ],
            }],
            max_tokens=4096,
        )
        text = resp.choices[0].message.content or ""
        logger.info("OCR  %s → %d ký tự", page_label, len(text))
        return text
    except Exception as exc:
        logger.warning("OCR thất bại trang %s: %s", page_label, exc)
        return ""


def _pdf_to_image_bytes(pdf_path: str, dpi: int = 200) -> list[bytes]:
    """Chuyển từng trang PDF thành ảnh JPEG bytes (dùng pdf2image + poppler)."""
    from pdf2image import convert_from_path

    pages = convert_from_path(pdf_path, dpi=dpi, fmt="jpeg")
    result = []
    for page in pages:
        buf = io.BytesIO()
        page.save(buf, format="JPEG", quality=85)
        result.append(buf.getvalue())
    return result


def _is_scanned_pdf(docs: list) -> bool:
    """
    Trả về True nếu PDF không có (đủ) text layer — có thể là bản scan.
    Tiêu chí: trung bình < _SCAN_THRESHOLD ký tự / trang.
    """
    if not docs:
        return True
    total = sum(len(d.page_content.strip()) for d in docs)
    avg = total / len(docs)
    return avg < _SCAN_THRESHOLD


def _ocr_pdf_to_docs(pdf_path: str, filename: str) -> list:
    """Chuyển PDF scan → ảnh → OCR → list[Document]."""
    from langchain_core.documents import Document

    logger.info("OCR PDF scan: %s", filename)
    page_images = _pdf_to_image_bytes(pdf_path)
    if not page_images:
        raise ValueError("Không thể chuyển đổi PDF thành ảnh.")

    docs = []
    for i, img_bytes in enumerate(page_images, start=1):
        text = _ocr_page(img_bytes, f"{filename}:p{i}")
        if text.strip():
            docs.append(Document(
                page_content=text,
                metadata={"source": filename, "page": i, "ocr": True},
            ))
    return docs


def _ocr_image_to_docs(image_path: str, filename: str) -> list:
    """Đọc file ảnh → OCR → list[Document]."""
    from langchain_core.documents import Document

    with open(image_path, "rb") as f:
        img_bytes = f.read()
    text = _ocr_page(img_bytes, filename)
    if not text.strip():
        raise ValueError("Không trích xuất được văn bản từ ảnh.")
    return [Document(
        page_content=text,
        metadata={"source": filename, "page": 1, "ocr": True},
    )]


# ---------------------------------------------------------------------------
# Document loaders
# ---------------------------------------------------------------------------

def _load_documents(file_path: str, filename: str) -> list:
    """
    Load tài liệu từ file vật lý, trả về list[Document].

    Luồng xử lý:
      - TXT / DOCX / DOC  → loader thông thường
      - PDF có text layer  → PyPDFLoader
      - PDF scan (ít text) → pdf2image + OpenAI Vision OCR
      - Ảnh (PNG/JPG/...)  → OpenAI Vision OCR trực tiếp
    """
    ext = Path(filename).suffix.lower()

    # ── Ảnh trực tiếp ────────────────────────────────────────────────────────
    if ext in IMAGE_EXTENSIONS:
        logger.info("Nhận dạng file ảnh: %s → OCR", filename)
        return _ocr_image_to_docs(file_path, filename)

    # ── TXT ──────────────────────────────────────────────────────────────────
    if ext == ".txt":
        from langchain_community.document_loaders import TextLoader
        return TextLoader(file_path, encoding="utf-8").load()

    # ── DOCX / DOC ────────────────────────────────────────────────────────────
    if ext in (".docx", ".doc"):
        from langchain_community.document_loaders import Docx2txtLoader
        return Docx2txtLoader(file_path).load()

    # ── PDF ───────────────────────────────────────────────────────────────────
    if ext == ".pdf":
        from langchain_community.document_loaders import PyPDFLoader
        try:
            docs = PyPDFLoader(file_path).load()
        except Exception:
            docs = []

        if _is_scanned_pdf(docs):
            logger.info("PDF scan phát hiện (%d trang, text thấp) → OCR", len(docs))
            return _ocr_pdf_to_docs(file_path, filename)
        return docs

    raise ValueError(
        f"Định dạng không được hỗ trợ: '{ext}'. "
        f"Hỗ trợ: PDF, DOCX, TXT, PNG, JPG, JPEG, TIFF, WEBP, BMP."
    )


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

def _parse_allowed_roles(allowed_roles_str: str) -> str:
    """
    Chuẩn hoá chuỗi allowed_roles.
    "all" → "all"
    "SOC,HR" → "SOC,HR"
    Bỏ qua các role không hợp lệ; nếu rỗng → "all"
    """
    s = allowed_roles_str.strip().lower()
    if not s or s == "all":
        return "all"
    valid = []
    for part in s.split(","):
        part = part.strip()
        for r in ROLE_NAMES:
            if part == r.lower():
                valid.append(r)
                break
    return ",".join(valid) if valid else "all"


def _role_can_access(user_role: str, allowed_roles_str: str) -> bool:
    """Kiểm tra xem user_role có được phép truy cập chunk này không."""
    if allowed_roles_str == "all":
        return True
    allowed = [r.strip() for r in allowed_roles_str.split(",")]
    return user_role in allowed


@router.post("/upload")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    description: str = Form(""),
    allowed_roles: str = Form("all"),   # "all" | "SOC" | "SOC,HR" | ...
    admin: dict = Depends(require_admin),
) -> dict:
    """
    Upload tài liệu vào Knowledge Base (chỉ Admin).
    Trường allowed_roles: "all" hoặc danh sách role cách nhau dấu phẩy,
    ví dụ: "SOC,HR" — chỉ SOC và HR mới thấy tài liệu này.
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY is not configured.")

    # Kiểm tra định dạng file
    filename = file.filename or "unknown"
    ext = Path(filename).suffix.lower()
    supported = {".pdf", ".docx", ".doc", ".txt"} | IMAGE_EXTENSIONS
    if ext not in supported:
        raise HTTPException(
            status_code=422,
            detail=f"Định dạng '{ext}' không được hỗ trợ. Hỗ trợ: PDF, DOCX, TXT, PNG, JPG, JPEG, TIFF, WEBP, BMP.",
        )

    ip = request.client.host if request and request.client else ""
    doc_id = uuid.uuid4().hex[:12]
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    normalized_roles = _parse_allowed_roles(allowed_roles)

    suffix = ext
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        docs = _load_documents(tmp_path, filename)
        chunks = _split_documents(docs)

        if not chunks:
            raise HTTPException(status_code=422, detail="Tài liệu rỗng hoặc không thể đọc.")

        for chunk in chunks:
            chunk.metadata["doc_id"]        = doc_id
            chunk.metadata["filename"]      = filename
            chunk.metadata["allowed_roles"] = normalized_roles  # ← RBAC metadata

        vs = _get_vectorstore()
        vs.add_documents(chunks)

        is_ocr = any(c.metadata.get("ocr") for c in chunks)
        ocr_pages = len({c.metadata.get("page", 1) for c in chunks if c.metadata.get("ocr")})

        registry = _load_registry()
        registry[doc_id] = {
            "doc_id":        doc_id,
            "filename":      filename,
            "description":   description,
            "allowed_roles": normalized_roles,
            "chunk_count":   len(chunks),
            "char_count":    sum(len(c.page_content) for c in chunks),
            "uploaded_at":   ts,
            "uploaded_by":   admin["email"],
            "ocr":           is_ocr,
            "ocr_pages":     ocr_pages if is_ocr else 0,
        }
        _save_registry(registry)

        audit_upload_doc(admin["email"], doc_id, filename, normalized_roles, ip)
        logger.info("Upload OK  doc_id=%s  file=%s  roles=%s  chunks=%d  ocr=%s",
                    doc_id, filename, normalized_roles, len(chunks), is_ocr)
        return {
            "doc_id":        doc_id,
            "filename":      filename,
            "allowed_roles": normalized_roles,
            "chunk_count":   len(chunks),
            "uploaded_at":   ts,
            "ocr":           is_ocr,
            "ocr_pages":     ocr_pages if is_ocr else 0,
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Upload FAIL  file=%s  error=%s", filename, exc)
        raise HTTPException(status_code=500, detail=f"Lỗi xử lý tài liệu: {exc}")
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.get("/documents")
async def list_documents(current_user: CurrentUser) -> list:
    """
    Danh sách tài liệu mà user hiện tại được phép thấy.
    Admin thấy tất cả; user thường chỉ thấy tài liệu phù hợp với role của mình.
    """
    from .dependencies import ADMIN_EMAILS
    registry = _load_registry()
    is_admin = current_user["email"].lower() in ADMIN_EMAILS
    user_role = current_user["role"]

    result = []
    for doc in registry.values():
        if is_admin or _role_can_access(user_role, doc.get("allowed_roles", "all")):
            result.append(doc)
    return result


@router.delete("/documents/{doc_id}")
async def delete_document(
    doc_id: str,
    request: Request,
    admin: dict = Depends(require_admin),
) -> dict:
    """Xóa tài liệu khỏi Knowledge Base và ChromaDB (chỉ Admin)."""
    ip = request.client.host if request.client else ""
    registry = _load_registry()
    if doc_id not in registry:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy doc_id '{doc_id}'")

    try:
        vs = _get_vectorstore()
        # LangChain Chroma.delete() chỉ nhận ids — cần lấy IDs trước rồi mới xóa
        results = vs._collection.get(where={"doc_id": doc_id})
        chunk_ids = results.get("ids", [])
        if chunk_ids:
            vs._collection.delete(ids=chunk_ids)
            logger.info("Đã xóa %d chunk từ ChromaDB cho doc_id=%s", len(chunk_ids), doc_id)
        else:
            logger.warning("Không tìm thấy chunk nào cho doc_id=%s trong ChromaDB", doc_id)
    except Exception as exc:
        logger.warning("Không thể xóa chunk từ ChromaDB: %s", exc)

    info = registry.pop(doc_id)
    _save_registry(registry)

    audit_delete_doc(admin["email"], doc_id, info.get("filename", ""), ip)
    logger.info("Deleted doc_id=%s  file=%s", doc_id, info.get("filename"))
    return {"deleted": doc_id, "filename": info.get("filename")}


# ---------------------------------------------------------------------------
# RAG Chat endpoint
# ---------------------------------------------------------------------------

@router.post("/v1/rag/chat")
async def rag_chat(
    request: Request,
    current_user: CurrentUser,
) -> JSONResponse:
    """
    RAG chat với masking tích hợp và RAG Isolation theo role.

    Luồng: Query → mask(query) → semantic_search (filtered by role)
           → mask(context) → LLM → demask(answer) → client
    """
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY is not configured.")

    body: dict[str, Any] = await request.json()
    ip = request.client.host if request.client else ""

    query: str = body.get("query", "").strip()
    if not query:
        raise HTTPException(status_code=422, detail="'query' field is required.")

    session_id: str = body.get("session_id") or uuid.uuid4().hex[:8]
    model: str = body.get("model", DEFAULT_MODEL)
    top_k: int = int(body.get("top_k", DEFAULT_TOP_K))
    history: list[dict] = body.get("messages", [])
    temperature: float = float(body.get("temperature", 0.7))
    max_tokens: int = int(body.get("max_tokens", 2048))
    # Role luôn lấy từ JWT — không nhận từ body
    role: str = current_user["role"]

    request_id: str = uuid.uuid4().hex[:8].upper()

    # ── R-1: RAG_RECV ─────────────────────────────────────────────────────────
    log_rag_recv(request_id, session_id, query, model, top_k)

    # ── R-2: RAG_RETRIEVE ─────────────────────────────────────────────────────
    masked_query = masker.mask(query, session_id, request_id)

    try:
        vs = _get_vectorstore()
        # Lấy nhiều hơn top_k để còn lọc theo role
        raw_results = vs.similarity_search_with_score(masked_query, k=top_k * 5)
    except Exception as exc:
        log_rag_error(request_id, session_id, "RETRIEVE", str(exc))
        raise HTTPException(status_code=500, detail=f"Lỗi tìm kiếm vector: {exc}")

    # ── RAG Isolation: lọc chunk theo role người dùng ────────────────────────
    results = []
    for doc, score in raw_results:
        allowed = doc.metadata.get("allowed_roles", "all")
        if _role_can_access(role, allowed):
            results.append((doc, score))
        if len(results) >= top_k:
            break

    if not results:
        # Không có tài liệu nào phù hợp với role này
        log_rag_error(request_id, session_id, "RETRIEVE",
                      f"Không có tài liệu nào phù hợp với role={role}")
        return JSONResponse(content={
            "choices": [{"message": {"role": "assistant",
                "content": "Không tìm thấy tài liệu nào trong Knowledge Base phù hợp với quyền truy cập của bạn."
            }, "finish_reason": "stop", "index": 0}],
            "_rag_meta": {"request_id": request_id, "session_id": session_id,
                          "chunks_used": 0, "top_k": top_k, "role": role},
        })

    # Audit log: ghi lại các doc_id được truy cập
    accessed_doc_ids = list({doc.metadata.get("doc_id", "") for doc, _ in results})
    audit_access_doc(current_user["email"], accessed_doc_ids, query, ip)

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

    _t0 = time.monotonic()
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

    # Ghi usage log
    _latency_ms = int((time.monotonic() - _t0) * 1000)
    _masked_count = sum(
        len(re.findall(r'\[[A-Z]+_\d+\]', m.get("masked", "")))
        for m in context_mapping
    ) + len(re.findall(r'\[[A-Z]+_\d+\]', masked_query))
    log_usage(
        user=current_user,
        request_id=request_id,
        session_id=session_id,
        usage_type="RAG_CHAT",
        model=model,
        prompt_tokens=usage.get("prompt_tokens", 0),
        completion_tokens=usage.get("completion_tokens", 0),
        total_tokens=usage.get("total_tokens", 0),
        latency_ms=_latency_ms,
        masked_entities=_masked_count,
        chunks_used=len(results),
        ok=True,
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
            "role":        role,
        },
    })
