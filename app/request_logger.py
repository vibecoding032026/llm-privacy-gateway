"""
request_logger.py — Ghi log đầy đủ 4 giai đoạn xử lý của mỗi request.

Mỗi request được ghi thành 4 bản ghi liên tiếp trong file JSONL:

  Stage 1 — RECV   : Request gốc nhận từ client (chứa dữ liệu thật)
  Stage 2 — MASK   : Request sau khi mask, chuẩn bị gửi lên OpenAI
  Stage 3 — OAPI   : Response thô nhận từ OpenAI (chứa tag [IP_1]...)
  Stage 4 — SEND   : Response sau khi de-mask, trả về cho client

File log
--------
  logs/requests/YYYY-MM-DD.jsonl   — mỗi dòng là 1 JSON object
  logs/gateway.log                 — log dạng text thuần (console-style)

Xem log
-------
  # Theo dõi realtime
  tail -f logs/requests/$(date +%Y-%m-%d).jsonl | python3 -m json.tool

  # Lọc theo request_id
  grep "A1B2C3D4" logs/requests/2026-03-22.jsonl | python3 -m json.tool

  # Chỉ xem stage MASK
  grep '"stage":"MASK"' logs/requests/2026-03-22.jsonl
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Cấu hình thư mục log
# ---------------------------------------------------------------------------

_LOG_DIR = Path(os.getenv("LOG_DIR", "logs"))
_REQUEST_LOG_DIR = _LOG_DIR / "requests"
_REQUEST_LOG_DIR.mkdir(parents=True, exist_ok=True)

# Logger console dùng chung toàn ứng dụng
_console = logging.getLogger("gateway")


# ---------------------------------------------------------------------------
# Helpers nội bộ
# ---------------------------------------------------------------------------

def _today_file() -> Path:
    """Trả về đường dẫn file JSONL của ngày hôm nay."""
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _REQUEST_LOG_DIR / f"{date_str}.jsonl"


def _write_jsonl(entry: dict) -> None:
    """Ghi một dòng JSON vào file log của ngày hôm nay."""
    with _today_file().open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _safe_messages(messages: list[dict]) -> list[dict]:
    """Clone danh sách messages để tránh mutate object gốc khi lưu log."""
    return [dict(m) for m in messages]


def _token_usage(oai_result: dict) -> dict:
    usage = oai_result.get("usage", {})
    return {
        "prompt_tokens":     usage.get("prompt_tokens", 0),
        "completion_tokens": usage.get("completion_tokens", 0),
        "total_tokens":      usage.get("total_tokens", 0),
    }


def _masked_summary(messages_before: list[dict], messages_after: list[dict]) -> list[dict]:
    """
    So sánh từng message trước/sau masking.
    Trả về danh sách các thay đổi: {role, original, masked, changed}.
    """
    summary = []
    for before, after in zip(messages_before, messages_after):
        original = before.get("content", "")
        masked   = after.get("content", "")
        summary.append({
            "role":     before.get("role"),
            "original": original,
            "masked":   masked,
            "changed":  original != masked,
        })
    return summary


# ---------------------------------------------------------------------------
# API công khai
# ---------------------------------------------------------------------------

def log_recv(
    request_id: str,
    session_id: str,
    model: str,
    messages: list[dict],
    role: str = "Normal",
    extra: dict | None = None,
) -> None:
    """
    Stage 1 — RECV: Request gốc từ client, chứa dữ liệu nhạy cảm thật.
    """
    entry = {
        "timestamp":  _now(),
        "stage":      "RECV",
        "request_id": request_id,
        "session_id": session_id,
        "role":       role,
        "model":      model,
        "turns":      len(messages),
        "messages":   _safe_messages(messages),
        **(extra or {}),
    }
    _write_jsonl(entry)
    _console.info(
        "[%s] ── RECV ──  session=%-16s  role=%-10s  model=%-14s  turns=%d",
        request_id, session_id, role, model, len(messages),
    )


def log_mask(
    request_id: str,
    session_id: str,
    messages_before: list[dict],
    messages_after: list[dict],
    mapping_snapshot: dict,
) -> None:
    """
    Stage 2 — MASK: Payload đã được ẩn danh, sẵn sàng gửi lên OpenAI.
    Ghi kèm bảng mapping và chi tiết từng thay đổi.
    """
    diff = _masked_summary(messages_before, messages_after)
    changed_count = sum(1 for d in diff if d["changed"])

    entry = {
        "timestamp":       _now(),
        "stage":           "MASK",
        "request_id":      request_id,
        "session_id":      session_id,
        "changed_messages": changed_count,
        "diff":            diff,
        "mapping_table":   mapping_snapshot,
        "masked_messages": _safe_messages(messages_after),
    }
    _write_jsonl(entry)
    _console.info(
        "[%s] ── MASK ──  %d/%d message(s) chứa dữ liệu nhạy cảm  |  "
        "Bảng mapping: %d giá trị",
        request_id, changed_count, len(diff), len(mapping_snapshot),
    )

    # In chi tiết từng cặp thay đổi ra console
    for item in diff:
        if item["changed"]:
            _console.info(
                "[%s]            role=%-10s  '%s'  →  '%s'",
                request_id,
                item["role"],
                item["original"][:80],
                item["masked"][:80],
            )


def log_oapi(
    request_id: str,
    session_id: str,
    oai_result: dict,
    status_code: int,
) -> None:
    """
    Stage 3 — OAPI: Response thô từ OpenAI (còn chứa các tag [IP_1]...).
    """
    choices_raw = []
    for choice in oai_result.get("choices", []):
        choices_raw.append({
            "index":         choice.get("index"),
            "finish_reason": choice.get("finish_reason"),
            "role":          choice.get("message", {}).get("role"),
            "content":       choice.get("message", {}).get("content", ""),
        })

    entry = {
        "timestamp":   _now(),
        "stage":       "OAPI",
        "request_id":  request_id,
        "session_id":  session_id,
        "status_code": status_code,
        "model":       oai_result.get("model", ""),
        "usage":       _token_usage(oai_result),
        "choices":     choices_raw,
    }
    _write_jsonl(entry)

    usage = entry["usage"]
    _console.info(
        "[%s] ── OAPI ──  HTTP %d  |  tokens: prompt=%d  completion=%d  total=%d",
        request_id, status_code,
        usage["prompt_tokens"], usage["completion_tokens"], usage["total_tokens"],
    )
    for c in choices_raw:
        _console.info(
            "[%s]            choice[%d]  finish=%s  content_len=%d chars",
            request_id, c["index"], c["finish_reason"], len(c["content"]),
        )


def log_send(
    request_id: str,
    session_id: str,
    choices_before: list[dict],
    choices_after: list[dict],
) -> None:
    """
    Stage 4 — SEND: Response sau khi de-mask, trả về cho client.
    Ghi kèm cặp nội dung trước/sau để kiểm chứng.
    """
    diff = []
    for before, after in zip(choices_before, choices_after):
        content_before = before.get("message", {}).get("content", "")
        content_after  = after.get("message", {}).get("content", "")
        diff.append({
            "index":          before.get("index"),
            "content_masked": content_before,
            "content_final":  content_after,
            "demasked":       content_before != content_after,
        })

    entry = {
        "timestamp":  _now(),
        "stage":      "SEND",
        "request_id": request_id,
        "session_id": session_id,
        "choices":    diff,
    }
    _write_jsonl(entry)

    demasked_count = sum(1 for d in diff if d["demasked"])
    _console.info(
        "[%s] ── SEND ──  %d choice(s) đã de-mask  →  trả về client",
        request_id, demasked_count,
    )
    for d in diff:
        if d["demasked"]:
            _console.info(
                "[%s]            choice[%d]  '%s'  →  '%s'",
                request_id, d["index"],
                d["content_masked"][:80],
                d["content_final"][:80],
            )


def log_error(
    request_id: str,
    session_id: str,
    stage: str,
    error: str,
    detail: Any = None,
) -> None:
    """Ghi log khi có lỗi xảy ra ở bất kỳ giai đoạn nào."""
    entry = {
        "timestamp":  _now(),
        "stage":      f"ERROR_{stage}",
        "request_id": request_id,
        "session_id": session_id,
        "error":      error,
        "detail":     detail,
    }
    _write_jsonl(entry)
    _console.error("[%s] ── ERROR [%s] ── %s", request_id, stage, error)
