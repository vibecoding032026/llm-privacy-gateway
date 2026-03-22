"""
rag_logger.py — Ghi log 4 giai đoạn xử lý RAG của mỗi request.

Mỗi request RAG được ghi thành 4 bản ghi liên tiếp trong file JSONL:

  Stage R-1 — RAG_RECV     : Query gốc nhận từ client (dữ liệu thật)
  Stage R-2 — RAG_RETRIEVE : Kết quả tìm kiếm semantic (danh sách chunk)
  Stage R-3 — RAG_MASK_CTX : Context sau khi mask, kèm mapping [Doc_ID]→[Extracted]→[Masked]
  Stage R-4 — RAG_SEND     : Response cuối cùng sau de-mask gửi về client

File log
--------
  logs/requests/YYYY-MM-DD.jsonl   — cùng file với request_logger.py
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
_REQUEST_LOG_DIR = _LOG_DIR / "requests"
_REQUEST_LOG_DIR.mkdir(parents=True, exist_ok=True)

_console = logging.getLogger("gateway")


def _today_file() -> Path:
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _REQUEST_LOG_DIR / f"{date_str}.jsonl"


def _write_jsonl(entry: dict) -> None:
    with _today_file().open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def log_rag_recv(
    request_id: str,
    session_id: str,
    query: str,
    model: str,
    top_k: int,
) -> None:
    """Stage R-1: Query gốc từ client, chứa dữ liệu nhạy cảm thật."""
    entry = {
        "timestamp":  _now(),
        "stage":      "RAG_RECV",
        "request_id": request_id,
        "session_id": session_id,
        "model":      model,
        "top_k":      top_k,
        "query":      query,
    }
    _write_jsonl(entry)
    _console.info(
        "[%s] ── RAG_RECV ──  session=%-16s  query_len=%d",
        request_id, session_id, len(query),
    )


def log_rag_retrieve(
    request_id: str,
    session_id: str,
    masked_query: str,
    chunks: list[dict],
) -> None:
    """Stage R-2: Kết quả tìm kiếm semantic từ ChromaDB."""
    entry = {
        "timestamp":    _now(),
        "stage":        "RAG_RETRIEVE",
        "request_id":   request_id,
        "session_id":   session_id,
        "masked_query": masked_query,
        "chunk_count":  len(chunks),
        "chunks":       chunks,
    }
    _write_jsonl(entry)
    _console.info(
        "[%s] ── RAG_RETRIEVE ──  %d chunk(s) retrieved  |  masked_query_len=%d",
        request_id, len(chunks), len(masked_query),
    )


def log_rag_mask_ctx(
    request_id: str,
    session_id: str,
    context_mapping: list[dict],
) -> None:
    """Stage R-3: Context đã mask, kèm mapping [Doc_ID]→[Extracted]→[Masked]."""
    entry = {
        "timestamp":       _now(),
        "stage":           "RAG_MASK_CTX",
        "request_id":      request_id,
        "session_id":      session_id,
        "context_mapping": context_mapping,
    }
    _write_jsonl(entry)
    _console.info(
        "[%s] ── RAG_MASK_CTX ──  %d context segment(s) processed",
        request_id, len(context_mapping),
    )
    for item in context_mapping:
        if item.get("changed"):
            _console.info(
                "[%s]              [%s]  '%s'  →  '%s'",
                request_id,
                item.get("doc_id", "?"),
                item.get("extracted", "")[:60],
                item.get("masked", "")[:60],
            )


def log_rag_send(
    request_id: str,
    session_id: str,
    answer_masked: str,
    answer_final: str,
    usage: dict,
) -> None:
    """Stage R-4: Response cuối cùng sau de-mask, trả về cho client."""
    entry = {
        "timestamp":    _now(),
        "stage":        "RAG_SEND",
        "request_id":   request_id,
        "session_id":   session_id,
        "answer_masked": answer_masked,
        "answer_final":  answer_final,
        "demasked":      answer_masked != answer_final,
        "usage":         usage,
    }
    _write_jsonl(entry)
    _console.info(
        "[%s] ── RAG_SEND ──  demasked=%s  answer_len=%d",
        request_id, entry["demasked"], len(answer_final),
    )


def log_rag_error(
    request_id: str,
    session_id: str,
    stage: str,
    error: str,
    detail: Any = None,
) -> None:
    """Ghi log lỗi trong pipeline RAG."""
    entry = {
        "timestamp":  _now(),
        "stage":      f"RAG_ERROR_{stage}",
        "request_id": request_id,
        "session_id": session_id,
        "error":      error,
        "detail":     detail,
    }
    _write_jsonl(entry)
    _console.error("[%s] ── RAG_ERROR [%s] ── %s", request_id, stage, error)
