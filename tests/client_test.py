"""
client_test.py — Interactive chat client cho LLM Privacy Gateway.

Chế độ sử dụng
--------------
  python tests/client_test.py            # chat tương tác (mặc định)
  python tests/client_test.py --test     # chạy kịch bản test tự động

Lệnh đặc biệt trong chat
-------------------------
  /quit hoặc /exit   — thoát chương trình
  /new               — bắt đầu cuộc trò chuyện mới (xóa lịch sử)
  /stats             — xem bảng masking của session hiện tại
  /history           — xem lại lịch sử hội thoại
  /clear             — xóa màn hình
"""

import os
import re
import sys
import uuid
import textwrap

import requests

# ---------------------------------------------------------------------------
# Cấu hình
# ---------------------------------------------------------------------------

GATEWAY_URL  = os.getenv("GATEWAY_URL", "http://localhost:8000/v1/chat/completions")
GATEWAY_BASE = GATEWAY_URL.rsplit("/v1/", 1)[0]
MODEL        = os.getenv("MODEL", "gpt-4o-mini")
TAG_PREFIXES = ["[IP_", "[HOST_", "[EMAIL_", "[PATH_"]

# ---------------------------------------------------------------------------
# Màu sắc terminal (ANSI)
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
BLUE   = "\033[94m"


def _color(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET


# ---------------------------------------------------------------------------
# Giao tiếp với Gateway
# ---------------------------------------------------------------------------

def _send(messages: list[dict], session_id: str, log_block: bool = False) -> dict:
    payload = {
        "model": MODEL,
        "messages": messages,
        "session_id": session_id,
        "log_block": log_block,
        "temperature": 0.7,
        "max_tokens": 2048,
    }
    resp = requests.post(GATEWAY_URL, json=payload, timeout=90)
    resp.raise_for_status()
    return resp.json()


def _reply_text(result: dict) -> str:
    return result["choices"][0]["message"]["content"]


def _get_stats(session_id: str) -> dict | None:
    try:
        r = requests.get(f"{GATEWAY_BASE}/v1/session/{session_id}/stats", timeout=5)
        return r.json() if r.ok else None
    except Exception:
        return None


def _clear_session(session_id: str) -> None:
    try:
        requests.delete(f"{GATEWAY_BASE}/v1/session/{session_id}", timeout=5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Hiển thị
# ---------------------------------------------------------------------------

def _collect_log_block() -> str:
    """
    Chế độ nhập log nhiều dòng.
    Người dùng gõ/paste từng dòng log, kết thúc bằng dòng trống hoặc /end.
    Trả về toàn bộ nội dung log dưới dạng chuỗi nhiều dòng.
    """
    print(_color("\n  ┌─ Chế độ nhập LOG BLOCK ─────────────────────────────", YELLOW))
    print(_color("  │  Nhập/paste từng dòng log.", YELLOW))
    print(_color("  │  Gõ /end hoặc để trống 1 dòng rồi Enter để kết thúc.", YELLOW))
    print(_color("  └──────────────────────────────────────────────────────\n", YELLOW))

    lines: list[str] = []
    line_num = 1
    try:
        while True:
            raw = input(_color(f"  {line_num:>3} │ ", DIM))
            if raw.strip() in ("/end", "") and lines:
                break
            lines.append(raw)
            line_num += 1
    except (EOFError, KeyboardInterrupt):
        pass

    if not lines:
        print(_color("  (Không có nội dung log — đã huỷ)", DIM))
        return ""

    block = "\n".join(lines)
    print(_color(f"\n  ✓  Đã nhận {len(lines)} dòng log\n", GREEN))
    return block


def _print_log_block_header(line_count: int) -> None:
    print()
    print(_color(f"  [LOG BLOCK — {line_count} dòng]", YELLOW, BOLD))
    print(_color("  Đang phân tích ngữ cảnh toàn bộ đoạn log...", DIM))


def _print_banner() -> None:
    print(_color("╔══════════════════════════════════════════════════╗", CYAN, BOLD))
    print(_color("║         LLM Privacy Gateway — Interactive        ║", CYAN, BOLD))
    print(_color("╚══════════════════════════════════════════════════╝", CYAN, BOLD))
    print(_color("  Dữ liệu nhạy cảm (IP, hostname, email, path)", DIM))
    print(_color("  được tự động mask trước khi gửi lên OpenAI.\n", DIM))
    print(_color("  Lệnh: /log  /new  /stats  /history  /clear  /quit\n", YELLOW))
    print(_color("  /log  → nhập đoạn log nhiều dòng để phân tích theo ngữ cảnh\n", DIM))


def _print_separator() -> None:
    print(_color("  " + "─" * 50, DIM))


def _print_assistant(text: str) -> None:
    print()
    print(_color("  Assistant", GREEN, BOLD))
    _print_separator()
    # Wrap từng đoạn văn giữ nguyên xuống dòng
    for paragraph in text.split("\n"):
        if paragraph.strip():
            wrapped = textwrap.fill(paragraph, width=70, initial_indent="  ", subsequent_indent="  ")
            print(wrapped)
        else:
            print()
    print()


def _print_stats(session_id: str) -> None:
    stats = _get_stats(session_id)
    if not stats:
        print(_color("  (Chưa có dữ liệu nào được mask trong session này)", DIM))
        return

    print(_color(f"\n  Bảng Masking — session: {session_id}", YELLOW, BOLD))
    print(_color("  " + "─" * 48, DIM))
    print(f"  {'Giá trị gốc':<30}  {'Tag được gửi lên LLM'}")
    print(_color("  " + "─" * 48, DIM))
    for orig, tag in stats.get("mappings", {}).items():
        print(f"  {_color(orig, CYAN):<39}  {_color(tag, YELLOW)}")
    counters = stats.get("counters", {})
    print(_color(f"\n  Tổng: {stats['mapped_values']} giá trị  |  {counters}", DIM))
    print()


def _print_history(messages: list[dict]) -> None:
    if not messages:
        print(_color("  (Chưa có lịch sử hội thoại)", DIM))
        return
    print(_color(f"\n  Lịch sử hội thoại ({len(messages)} lượt)", YELLOW, BOLD))
    print(_color("  " + "─" * 48, DIM))
    for i, msg in enumerate(messages, 1):
        role = msg["role"].upper()
        color = CYAN if msg["role"] == "user" else GREEN
        prefix = _color(f"  [{i}] {role}", color, BOLD)
        content_preview = msg["content"][:120].replace("\n", " ")
        if len(msg["content"]) > 120:
            content_preview += "..."
        print(f"{prefix}: {content_preview}")
    print()


# ---------------------------------------------------------------------------
# Vòng lặp chat tương tác
# ---------------------------------------------------------------------------

def run_interactive() -> None:
    _print_banner()

    session_id = str(uuid.uuid4())[:8]
    messages: list[dict] = []
    turn = 0

    print(_color(f"  Session ID: {session_id}", DIM))
    print(_color(f"  Model:      {MODEL}\n", DIM))

    while True:
        # ── Nhận input từ người dùng ─────────────────────────────────────────
        try:
            user_input = input(_color("  Bạn: ", CYAN, BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print(_color("\n\n  Tạm biệt!\n", YELLOW))
            _clear_session(session_id)
            break

        if not user_input:
            continue

        # ── Xử lý lệnh đặc biệt ──────────────────────────────────────────────
        cmd = user_input.lower()

        if cmd in ("/quit", "/exit"):
            print(_color("\n  Tạm biệt!\n", YELLOW))
            _clear_session(session_id)
            break

        if cmd == "/new":
            _clear_session(session_id)
            session_id = str(uuid.uuid4())[:8]
            messages = []
            turn = 0
            print(_color(f"\n  Cuộc trò chuyện mới bắt đầu. Session: {session_id}\n", YELLOW))
            continue

        if cmd == "/stats":
            _print_stats(session_id)
            continue

        if cmd == "/history":
            _print_history(messages)
            continue

        if cmd == "/clear":
            os.system("clear" if os.name != "nt" else "cls")
            _print_banner()
            continue

        # ── Chế độ nhập Log Block nhiều dòng ─────────────────────────────────
        is_log_block = False
        if cmd == "/log":
            log_content = _collect_log_block()
            if not log_content:
                continue
            # Nếu có câu hỏi kèm theo
            try:
                question = input(_color("  Câu hỏi kèm theo (Enter để bỏ qua): ", CYAN)).strip()
            except (EOFError, KeyboardInterrupt):
                question = ""
            if question:
                user_input = f"{question}\n\nĐoạn log cần phân tích:\n```\n{log_content}\n```"
            else:
                user_input = f"Phân tích đoạn log sau:\n```\n{log_content}\n```"
            is_log_block = True
            _print_log_block_header(len(log_content.splitlines()))
        else:
            # Tự động phát hiện nếu người dùng paste thẳng log nhiều dòng
            # (không qua lệnh /log) — phát hiện qua ký tự newline trong clipboard paste
            is_log_block = False

        # ── Gửi request đến Gateway ───────────────────────────────────────────
        turn += 1
        messages.append({"role": "user", "content": user_input})

        if not is_log_block:
            print(_color("  Đang xử lý...", DIM), end="\r")

        try:
            result = _send(messages, session_id, log_block=is_log_block)
        except requests.exceptions.ConnectionError:
            print(_color("  [LỖI] Không kết nối được Gateway tại " + GATEWAY_URL, RED))
            messages.pop()
            continue
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            try:
                detail = e.response.json().get("detail", str(e))
            except Exception:
                detail = str(e)
            hints = {
                502: "Lỗi kết nối tới OpenAI (có thể do mạng). Thử lại sau vài giây.",
                504: "OpenAI phản hồi quá chậm. Thử rút ngắn đoạn log hoặc thử lại.",
                429: "Đã vượt giới hạn rate limit OpenAI. Chờ một chút rồi thử lại.",
                500: "Lỗi nội bộ Gateway. Kiểm tra log server.",
            }
            hint = hints.get(status, "")
            print(_color(f"  [LỖI {status}] {detail}", RED))
            if hint:
                print(_color(f"  → {hint}", YELLOW))
            messages.pop()
            continue

        reply = _reply_text(result)
        messages.append({"role": "assistant", "content": reply})

        # Kiểm tra tag bị rò rỉ (cảnh báo nếu có)
        if any(prefix in reply for prefix in TAG_PREFIXES):
            leaked = re.findall(r'\[[A-Z]+_\d+\]', reply)
            print(_color(f"  ⚠  Cảnh báo: Tag bị rò rỉ trong response: {leaked}", RED))

        _print_assistant(reply)

        # Gợi ý xem stats sau mỗi 3 lượt
        if turn % 3 == 0:
            print(_color("  (Gõ /stats để xem bảng dữ liệu đã được mask)", DIM))
            print()


# ---------------------------------------------------------------------------
# Kịch bản test tự động (--test)
# ---------------------------------------------------------------------------

def run_test() -> bool:
    SENSITIVE_VALUES = {
        "srv-web-01":              "server name",
        "10.0.0.5":                "IP address",
        "admin@internal.corp":     "admin e-mail",
        "/var/log/nginx/error.log": "log file path",
    }

    session_id = "auto-test-" + str(uuid.uuid4())[:6]
    all_replies: list[str] = []

    def _banner(title: str) -> None:
        print("\n" + _color("═" * 65, BLUE))
        print(_color(f"  {title}", BLUE, BOLD))
        print(_color("═" * 65, BLUE))

    _banner("TEST TỰ ĐỘNG — LLM Privacy Gateway")
    print(_color(f"  Session: {session_id}\n", DIM))

    scenarios = [
        "Check log cho server srv-web-01 tại IP 10.0.0.5. "
        "Tại sao nó bị lỗi 500? Log file ở /var/log/nginx/error.log. "
        "Liên hệ admin@internal.corp nếu cần hỗ trợ.",

        "Cấu hình firewall cho server đó như thế nào? "
        "Có port nào đang mở trên IP đó không?",

        "Hãy tóm tắt lại vấn đề với server srv-web-01 và IP 10.0.0.5.",
    ]

    messages: list[dict] = []
    for i, user_msg in enumerate(scenarios, 1):
        _banner(f"TURN {i}")
        print(f"  {_color('[USER]', CYAN, BOLD)} {user_msg}\n")

        messages.append({"role": "user", "content": user_msg})
        result = _send(messages, session_id)
        reply = _reply_text(result)
        messages.append({"role": "assistant", "content": reply})
        all_replies.append(reply)

        print(f"  {_color('[ASSISTANT]', GREEN, BOLD)}")
        for line in reply.split("\n")[:6]:
            print(f"  {line}")
        if reply.count("\n") > 6:
            print(_color("  ...(truncated)", DIM))

    # ── Verification ──────────────────────────────────────────────────────────
    _banner("VERIFICATION")
    all_text = " ".join(all_replies)
    passed = True

    print(f"  {'KIỂM TRA':<42} {'KẾT QUẢ'}")
    print("  " + "─" * 55)

    tag_leaked = any(p in all_text for p in TAG_PREFIXES)
    status = _color("FAIL ✗", RED) if tag_leaked else _color("PASS ✓", GREEN)
    print(f"  {'Không rò rỉ tag ra client':<42} {status}")
    if tag_leaked:
        passed = False

    print()
    print("  Dữ liệu gốc xuất hiện trong response:")
    for value, label in SENSITIVE_VALUES.items():
        found = value.lower() in all_text.lower()
        mark = _color("YES ✓", GREEN) if found else _color("không được LLM đề cập", DIM)
        print(f"  {'['+label+']':<42} {mark}")

    _print_stats(session_id)
    _clear_session(session_id)

    _banner("KẾT QUẢ CUỐI")
    if passed:
        print(_color("  Tất cả kiểm tra PASS. Gateway hoạt động chính xác.\n", GREEN, BOLD))
    else:
        print(_color("  Một số kiểm tra THẤT BẠI. Xem log ở trên.\n", RED, BOLD))

    return passed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        if "--test" in sys.argv:
            ok = run_test()
            sys.exit(0 if ok else 1)
        else:
            run_interactive()
    except requests.exceptions.ConnectionError:
        print(
            _color(
                "\n[LỖI] Không kết nối được Gateway tại http://localhost:8000\n"
                "Khởi động server trước:\n\n"
                "    uvicorn app.server:app --reload --port 8000\n",
                RED,
            )
        )
        sys.exit(2)
