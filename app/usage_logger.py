"""
usage_logger.py — Ghi log sử dụng của từng request vào JSONL.

File: logs/usage/YYYY-MM-DD.jsonl
Mỗi entry ghi: user, role, type (CHAT/RAG_CHAT), model, tokens, latency, masked_entities
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("gateway.usage")

_USAGE_DIR = Path(os.getenv("LOG_DIR", "logs")) / "usage"


def _write(entry: dict) -> None:
    _USAGE_DIR.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = _USAGE_DIR / f"{date_str}.jsonl"
    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def log_usage(
    *,
    user: dict,
    request_id: str,
    session_id: str,
    usage_type: str,            # "CHAT" | "RAG_CHAT"
    model: str,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    total_tokens: int = 0,
    latency_ms: int = 0,
    masked_entities: int = 0,
    chunks_used: int = 0,       # RAG only
    ok: bool = True,
) -> None:
    entry = {
        "timestamp":         datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user_id":           user.get("user_id") or user.get("sub"),
        "email":             user.get("email", ""),
        "role":              user.get("role", "Normal"),
        "session_id":        session_id,
        "request_id":        request_id,
        "type":              usage_type,
        "model":             model,
        "prompt_tokens":     prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens":      total_tokens,
        "latency_ms":        latency_ms,
        "masked_entities":   masked_entities,
        "chunks_used":       chunks_used,
        "ok":                ok,
    }
    _write(entry)
    logger.info(
        "[%s] USAGE %-8s  user=%s  role=%s  tokens=%d  latency=%dms  ok=%s",
        request_id, usage_type, entry["email"], entry["role"],
        total_tokens, latency_ms, ok,
    )
