"""
server.py — LLM Privacy Gateway (FastAPI)

Request flow (4 giai đoạn được ghi log đầy đủ)
-----------------------------------------------
  [1] RECV  : Nhận request gốc từ client
  [2] MASK  : Mask dữ liệu nhạy cảm → gửi lên OpenAI
  [3] OAPI  : Nhận response thô từ OpenAI
  [4] SEND  : De-mask response → trả về client

Endpoints
---------
  POST   /v1/chat/completions          — endpoint chính
  GET    /health                       — health check
  GET    /v1/session/{id}/stats        — xem bảng masking
  DELETE /v1/session/{id}             — xóa session
  GET    /v1/logs                      — danh sách file log
  GET    /v1/logs/{date}               — xem log theo ngày (YYYY-MM-DD)
  GET    /v1/logs/{date}/{request_id}  — xem đầy đủ 4 giai đoạn của 1 request
"""

import asyncio
import copy
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

# load_dotenv() PHẢI chạy trước khi import các module app khác,
# vì dependencies.py đọc ADMIN_EMAILS từ env tại module-level.
load_dotenv()

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .masker import TAG_SYSTEM_INSTRUCTION
from .state import masker
from .config import validate_role, get_role_prompt, DEFAULT_ROLE
from .request_logger import log_error, log_mask, log_oapi, log_recv, log_send
from .rag import router as rag_router
from .auth_router import router as auth_router
from .admin_router import router as admin_router
from .stats_router import router as stats_router
from .apikey_router import router as apikey_router
from .register_router import router as register_router
from .dependencies import CurrentUser, get_current_user
from .db import init_db
from .usage_logger import log_usage

# ---------------------------------------------------------------------------
# System prompt phân tích log block
# ---------------------------------------------------------------------------

LOG_BLOCK_SYSTEM_INSTRUCTION = """
Người dùng đang cung cấp một ĐOẠN LOG gồm nhiều dòng để phân tích.
Hãy phân tích theo các bước sau:

1. **Chuỗi thời gian**: Sắp xếp các sự kiện theo thứ tự thời gian, xác định điểm khởi đầu của vấn đề.
2. **Phân loại mức độ**: Phân nhóm các dòng log theo mức độ (ERROR, WARN, INFO, DEBUG) và đánh giá mức độ nghiêm trọng.
3. **Tương quan ngữ cảnh**: Tìm mối liên hệ giữa các dòng log khác nhau — một lỗi ở dòng trước có thể là nguyên nhân của lỗi ở dòng sau.
4. **Xác định nguyên nhân gốc rễ**: Dựa trên toàn bộ đoạn log, chỉ ra nguyên nhân gốc rễ (root cause) có khả năng cao nhất.
5. **Đề xuất hành động**: Đưa ra các bước khắc phục cụ thể, ưu tiên theo mức độ khẩn cấp.

Lưu ý quan trọng:
- Giữ nguyên cấu trúc và định dạng log khi trích dẫn để dễ đối chiếu.
- Nếu có các placeholder tag (ví dụ [IP_1], [HOST_1]) thì sử dụng ĐÚNG tag đó, không suy đoán giá trị thật.
- Phân tích phải bao quát TOÀN BỘ đoạn log, không chỉ một dòng đơn lẻ.
"""

# ---------------------------------------------------------------------------
# Khởi động
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)

app = FastAPI(title="LLM Privacy Gateway", version="1.4.0")
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(stats_router)
app.include_router(rag_router)
app.include_router(apikey_router)
app.include_router(register_router)

@app.on_event("startup")
async def _startup() -> None:
    init_db()
    logging.getLogger("gateway").info("Database khởi tạo thành công.")

OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
_LOG_DIR = Path(os.getenv("LOG_DIR", "logs")) / "requests"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Regex nhận dạng dòng log điển hình
_LOG_LINE_RE = re.compile(
    r"(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2})"   # timestamp ISO/common
    r"|\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}"               # Apache/Nginx timestamp
    r"|\b(ERROR|WARN(?:ING)?|INFO|DEBUG|FATAL|CRITICAL|NOTICE|TRACE)\b"  # log levels
    r"|\bHTTP/[12]\.[01]\b"                                 # HTTP protocol
    r"|\b[45]\d{2}\b"                                       # HTTP error codes
    r"|\b(?:Exception|Traceback|stacktrace|at\s+\w+\.)\b"  # stack traces
    r"|\d+\s+(?:ms|seconds?|bytes?)\b",                     # metrics
    re.IGNORECASE,
)


def _is_log_block(content: str) -> bool:
    """
    Trả về True nếu nội dung là đoạn log nhiều dòng.
    Tiêu chí: có ít nhất 2 dòng và ít nhất 2 dòng khớp với pattern log.
    """
    lines = [ln for ln in content.splitlines() if ln.strip()]
    if len(lines) < 2:
        return False
    matched = sum(1 for ln in lines if _LOG_LINE_RE.search(ln))
    return matched >= 2


def _inject_role_prompt(messages: list[dict], role_prompt: str) -> list[dict]:
    """
    Đặt role system prompt làm system message đầu tiên.
    Nếu đã có system message thì prepend vào trước nội dung cũ.
    """
    result = list(messages)
    for i, msg in enumerate(result):
        if msg.get("role") == "system":
            result[i] = {**msg, "content": role_prompt + "\n\n" + msg["content"]}
            return result
    result.insert(0, {"role": "system", "content": role_prompt})
    return result


def _inject_system_instructions(messages: list[dict], include_log_analysis: bool) -> list[dict]:
    """
    Gắn TAG_SYSTEM_INSTRUCTION (luôn có) và tùy chọn LOG_BLOCK_SYSTEM_INSTRUCTION
    vào system message. Nếu chưa có system message thì tạo mới.
    """
    combined = TAG_SYSTEM_INSTRUCTION
    if include_log_analysis:
        combined += "\n\n" + LOG_BLOCK_SYSTEM_INSTRUCTION

    result = list(messages)
    for i, msg in enumerate(result):
        if msg.get("role") == "system":
            result[i] = {**msg, "content": msg["content"].rstrip() + "\n\n" + combined}
            return result
    result.insert(0, {"role": "system", "content": combined})
    return result


def _mask_messages(messages: list[dict], session_id: str, request_id: str) -> list[dict]:
    masked = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str) and content:
            masked.append({**msg, "content": masker.mask(content, session_id, request_id)})
        else:
            masked.append(msg)
    return masked


# ---------------------------------------------------------------------------
# Endpoint chính
# ---------------------------------------------------------------------------

@app.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    current_user: CurrentUser,
) -> JSONResponse:
    body: dict[str, Any] = await request.json()

    request_id: str = uuid.uuid4().hex[:8].upper()
    session_id: str = (
        body.get("session_id")
        or body.get("conversation_id")
        or request_id
    )
    model: str = body.get("model", "unknown")
    messages: list[dict] = body.get("messages", [])
    # Role luôn lấy từ JWT (đã được đồng bộ với DB trong dependency)
    role: str = current_user["role"]

    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY is not configured.")
    if not isinstance(messages, list):
        raise HTTPException(status_code=422, detail="'messages' phải là array.")
    if not messages:
        raise HTTPException(status_code=422, detail="'messages' array is required.")

    # Phát hiện log block: ưu tiên cờ từ client, fallback tự động detect
    is_log_block: bool = bool(body.get("log_block")) or _is_log_block(
        "\n".join(m.get("content", "") for m in messages if m.get("role") == "user")
    )

    # ── Stage 1: RECV — request gốc từ client ─────────────────────────────────
    log_recv(
        request_id=request_id,
        session_id=session_id,
        model=model,
        messages=messages,
        role=role,
        extra={"log_block": is_log_block},
    )

    # ── Stage 2: MASK — ẩn danh dữ liệu nhạy cảm ─────────────────────────────
    # Strip system messages từ client — ngăn prompt injection qua role system
    # Gateway tự inject role prompt, không cho phép client override system context
    messages = [m for m in messages if m.get("role") != "system"]

    # Inject role prompt trước → rồi mới mask (để mask được cả nội dung role prompt nếu có)
    messages_with_role = _inject_role_prompt(list(messages), get_role_prompt(role))
    messages_before_mask = copy.deepcopy(messages_with_role)
    masked_messages = _mask_messages(messages_with_role, session_id, request_id)
    masked_messages = _inject_system_instructions(masked_messages, include_log_analysis=is_log_block)

    # Bỏ qua system message (inject) khi so sánh diff
    masked_without_system = [m for m in masked_messages if m.get("role") != "system"]

    log_mask(
        request_id=request_id,
        session_id=session_id,
        messages_before=messages_before_mask,
        messages_after=masked_without_system,
        mapping_snapshot=masker.session_stats(session_id).get("mappings", {}),
    )

    # ── Gửi lên OpenAI ────────────────────────────────────────────────────────
    openai_payload = {k: v for k, v in body.items() if k not in ("session_id", "conversation_id", "log_block", "role")}
    openai_payload["messages"] = masked_messages

    # Log block phức tạp cần thêm thời gian → tăng timeout lên 180s
    oai_timeout = 180.0 if is_log_block else 90.0

    # Bắt đầu đo latency từ lúc gửi lên OpenAI
    _t0 = time.monotonic()

    # Retry với exponential backoff cho lỗi mạng tạm thời (DNS, connection reset...)
    _MAX_RETRIES = 3
    _RETRY_DELAYS = [1.0, 3.0, 7.0]   # giây: 1s → 3s → 7s
    _RETRYABLE = (httpx.ConnectError, httpx.RemoteProtocolError)

    oai_response = None
    last_exc: Exception | None = None

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=oai_timeout) as client:
                oai_response = await client.post(
                    f"{OPENAI_BASE_URL}/chat/completions",
                    json=openai_payload,
                    headers={
                        "Authorization": f"Bearer {OPENAI_API_KEY}",
                        "Content-Type": "application/json",
                    },
                )
            break   # thành công → thoát vòng lặp

        except httpx.TimeoutException as exc:
            # Timeout không nên retry vì request đã được gửi
            err_msg = f"TimeoutException sau {oai_timeout:.0f}s (attempt {attempt})"
            log_error(request_id, session_id, "OAPI", err_msg)
            raise HTTPException(
                status_code=504,
                detail=f"OpenAI không phản hồi trong {oai_timeout:.0f}s. Thử rút ngắn đoạn log.",
            )

        except _RETRYABLE as exc:
            last_exc = exc
            err_msg = f"{type(exc).__name__} (attempt {attempt}/{_MAX_RETRIES}): {exc}"
            log_error(request_id, session_id, "OAPI", err_msg)

            if attempt < _MAX_RETRIES:
                delay = _RETRY_DELAYS[attempt - 1]
                logging.getLogger("gateway").warning(
                    "[%s] Lỗi mạng tạm thời, thử lại sau %.0fs... (%d/%d)",
                    request_id, delay, attempt, _MAX_RETRIES,
                )
                await asyncio.sleep(delay)
            else:
                raise HTTPException(
                    status_code=502,
                    detail=f"Không thể kết nối OpenAI sau {_MAX_RETRIES} lần thử: {exc}",
                )

        except httpx.RequestError as exc:
            err_msg = f"{type(exc).__name__}: {exc}"
            log_error(request_id, session_id, "OAPI", err_msg)
            raise HTTPException(status_code=502, detail=f"Không kết nối được OpenAI: {exc}")

    # ── Stage 3: OAPI — response thô từ OpenAI ────────────────────────────────
    if oai_response.status_code != 200:
        log_error(
            request_id, session_id, "OAPI",
            f"HTTP {oai_response.status_code}",
            oai_response.text[:500],
        )
        raise HTTPException(status_code=oai_response.status_code, detail=oai_response.text)

    result: dict[str, Any] = oai_response.json()

    log_oapi(
        request_id=request_id,
        session_id=session_id,
        oai_result=result,
        status_code=oai_response.status_code,
    )

    # ── Stage 4: SEND — de-mask và trả về client ──────────────────────────────
    choices_before = copy.deepcopy(result.get("choices", []))

    for choice in result.get("choices", []):
        raw: str = choice.get("message", {}).get("content") or ""
        if raw:
            choice["message"]["content"] = masker.demask(raw, session_id)

    log_send(
        request_id=request_id,
        session_id=session_id,
        choices_before=choices_before,
        choices_after=result.get("choices", []),
    )

    # Ghi usage log
    _latency_ms = int((time.monotonic() - _t0) * 1000)
    _usage_info  = result.get("usage", {})
    _masked_count = sum(
        len(re.findall(r'\[[A-Z]+_\d+\]', m.get("content", "")))
        for m in masked_without_system
    )
    log_usage(
        user=current_user,
        request_id=request_id,
        session_id=session_id,
        usage_type="CHAT",
        model=model,
        prompt_tokens=_usage_info.get("prompt_tokens", 0),
        completion_tokens=_usage_info.get("completion_tokens", 0),
        total_tokens=_usage_info.get("total_tokens", 0),
        latency_ms=_latency_ms,
        masked_entities=_masked_count,
        ok=True,
    )

    return JSONResponse(content=result)


# ---------------------------------------------------------------------------
# Endpoints vận hành
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "active_sessions": masker.active_sessions}


@app.get("/v1/session/{session_id}/stats")
async def session_stats(session_id: str, _: CurrentUser) -> dict:
    stats = masker.session_stats(session_id)
    if not stats:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return stats


@app.delete("/v1/session/{session_id}")
async def clear_session(session_id: str, _: CurrentUser) -> dict:
    masker.clear_session(session_id)
    return {"cleared": session_id}


# ---------------------------------------------------------------------------
# Endpoints xem log
# ---------------------------------------------------------------------------

@app.get("/v1/logs")
async def list_logs() -> dict:
    """Danh sách các file log hiện có."""
    if not _LOG_DIR.exists():
        return {"files": []}
    files = sorted(_LOG_DIR.glob("*.jsonl"), reverse=True)
    return {
        "files": [
            {
                "date":     f.stem,
                "filename": f.name,
                "size_kb":  round(f.stat().st_size / 1024, 1),
            }
            for f in files
        ]
    }


@app.get("/v1/logs/{date}")
async def get_log_by_date(date: str, stage: str | None = None, session: str | None = None) -> list:
    """
    Xem toàn bộ log của một ngày.
    Query params tuỳ chọn:
      ?stage=MASK          — lọc theo giai đoạn (RECV/MASK/OAPI/SEND)
      ?session=abc123      — lọc theo session_id
    """
    log_file = _LOG_DIR / f"{date}.jsonl"
    if not log_file.exists():
        raise HTTPException(status_code=404, detail=f"Không có log ngày {date}")

    entries = []
    with log_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if stage and entry.get("stage") != stage.upper():
                    continue
                if session and entry.get("session_id") != session:
                    continue
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    return entries


@app.get("/v1/logs/{date}/{request_id}")
async def get_request_trace(date: str, request_id: str) -> dict:
    """
    Xem đầy đủ 4 giai đoạn xử lý của một request_id cụ thể.
    """
    log_file = _LOG_DIR / f"{date}.jsonl"
    if not log_file.exists():
        raise HTTPException(status_code=404, detail=f"Không có log ngày {date}")

    stages: dict[str, Any] = {}
    with log_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or request_id.upper() not in line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("request_id", "").upper() == request_id.upper():
                    stages[entry["stage"]] = entry
            except json.JSONDecodeError:
                continue

    if not stages:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy request_id '{request_id}'")

    return {
        "request_id": request_id.upper(),
        "date":       date,
        "stages":     stages,
    }
