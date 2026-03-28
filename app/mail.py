"""
mail.py — Built-in email sender (không cần mail server bên ngoài).

Chiến lược:
  1. Thử gửi qua SMTP (SMTP_HOST:SMTP_PORT, default localhost:25)
  2. Nếu SMTP thất bại → ghi fallback vào logs/mail/<timestamp>.eml
     để admin có thể đọc link activation thủ công

Biến môi trường:
  SMTP_HOST     — SMTP relay host    (default: localhost)
  SMTP_PORT     — SMTP relay port    (default: 25)
  SMTP_FROM     — From address       (default: noreply@vsec.com.vn)
  SMTP_USER     — SMTP auth user     (optional)
  SMTP_PASS     — SMTP auth password (optional)
  SMTP_TLS      — Dùng SSL/TLS       (default: false)
  APP_BASE_URL  — FastAPI base URL   (default: http://localhost:8000)
  APP_UI_URL    — Streamlit UI URL   (default: http://localhost:8501)
"""
import email.mime.multipart
import email.mime.text
import logging
import os
import smtplib
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("gateway.mail")

SMTP_HOST    = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT    = int(os.getenv("SMTP_PORT", "25"))
SMTP_FROM    = os.getenv("SMTP_FROM", "noreply@vsec.com.vn")
SMTP_USER    = os.getenv("SMTP_USER", "")
SMTP_PASS    = os.getenv("SMTP_PASS", "")
SMTP_TLS     = os.getenv("SMTP_TLS", "false").lower() == "true"
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")
APP_UI_URL   = os.getenv("APP_UI_URL",   "http://localhost:8501")

_MAIL_DIR = Path(os.getenv("LOG_DIR", "logs")) / "mail"


def _build_activation_message(to: str, full_name: str, token: str) -> email.mime.multipart.MIMEMultipart:
    activate_url = f"{APP_BASE_URL}/auth/activate?token={token}"
    login_url    = APP_UI_URL

    subject = "Kích hoạt tài khoản LLM Privacy Gateway - VSEC"
    html_body = f"""<!DOCTYPE html>
<html><body style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:20px">
<h2 style="color:#1976D2">🔐 LLM Privacy Gateway</h2>
<p>Xin chào <b>{full_name}</b>,</p>
<p>Bạn đã đăng ký tài khoản tại <b>LLM Privacy Gateway</b> của VSEC.</p>
<p>Nhấp vào nút bên dưới để kích hoạt tài khoản (link có hiệu lực trong <b>24 giờ</b>):</p>
<p style="text-align:center;margin:30px 0">
  <a href="{activate_url}"
     style="background:#1976D2;color:#fff;padding:14px 28px;border-radius:6px;
            text-decoration:none;font-size:16px;font-weight:bold;display:inline-block">
    ✅ Kích hoạt tài khoản
  </a>
</p>
<p>Hoặc copy link sau vào trình duyệt:</p>
<p style="background:#f5f5f5;padding:10px;border-radius:4px;word-break:break-all">
  <a href="{activate_url}">{activate_url}</a>
</p>
<p>Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email.</p>
<hr style="margin-top:30px">
<p style="color:#888;font-size:12px">VSEC Security Team — LLM Privacy Gateway</p>
</body></html>"""

    text_body = (
        f"Xin chào {full_name},\n\n"
        f"Vui lòng kích hoạt tài khoản tại link sau (hiệu lực 24 giờ):\n"
        f"{activate_url}\n\n"
        f"Sau khi kích hoạt, đăng nhập tại: {login_url}\n\n"
        f"Nếu bạn không đăng ký, vui lòng bỏ qua email này.\n\n"
        f"VSEC Security Team"
    )

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"LLM Privacy Gateway <{SMTP_FROM}>"
    msg["To"]      = to
    msg["Date"]    = datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg.attach(email.mime.text.MIMEText(text_body, "plain", "utf-8"))
    msg.attach(email.mime.text.MIMEText(html_body, "html",  "utf-8"))
    return msg


def _save_fallback(msg: email.mime.multipart.MIMEMultipart, token: str) -> str:
    """Lưu email vào logs/mail/ khi SMTP không khả dụng."""
    _MAIL_DIR.mkdir(parents=True, exist_ok=True)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = f"{ts}_{token[:12]}.eml"
    path = _MAIL_DIR / name
    path.write_text(msg.as_string(), encoding="utf-8")
    return str(path)


def send_activation_email(to: str, full_name: str, token: str) -> bool:
    """
    Gửi email kích hoạt tài khoản.
    Returns True nếu gửi SMTP thành công, False nếu phải dùng fallback file.
    Không raise exception — luôn xử lý nội bộ.
    """
    msg = _build_activation_message(to, full_name, token)
    activate_url = f"{APP_BASE_URL}/auth/activate?token={token}"

    try:
        if SMTP_TLS:
            smtp_cls = smtplib.SMTP_SSL
        else:
            smtp_cls = smtplib.SMTP

        with smtp_cls(SMTP_HOST, SMTP_PORT, timeout=5) as s:
            if not SMTP_TLS:
                try:
                    s.starttls()
                except smtplib.SMTPException:
                    pass  # server không hỗ trợ STARTTLS — ok
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, [to], msg.as_bytes())

        log.info("Mail SMTP OK → %s | link=%s", to, activate_url)
        return True

    except Exception as exc:
        path = _save_fallback(msg, token)
        log.warning(
            "SMTP thất bại (%s: %s) — đã lưu fallback: %s | link=%s",
            type(exc).__name__, exc, path, activate_url,
        )
        return False


def list_mail_fallbacks() -> list[dict]:
    """Trả về danh sách các file .eml trong logs/mail/ cho admin xem."""
    import email as _email_mod
    import quopri
    import base64 as _base64
    import re as _re

    if not _MAIL_DIR.exists():
        return []
    files = sorted(_MAIL_DIR.glob("*.eml"), reverse=True)
    result = []
    for f in files:
        try:
            raw = f.read_bytes()
            msg = _email_mod.message_from_bytes(raw)
            subject = msg.get("Subject", "")
            to      = msg.get("To", "")

            # Decode quoted-printable subject if needed
            try:
                from email.header import decode_header
                decoded_parts = decode_header(subject)
                subject = "".join(
                    (part.decode(enc or "utf-8") if isinstance(part, bytes) else part)
                    for part, enc in decoded_parts
                )
            except Exception:
                pass

            # Tìm activation link trong body (text/plain hoặc text/html)
            link = ""
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        body_text = payload.decode("utf-8", errors="replace")
                        found = _re.search(r'https?://\S+/auth/activate\?token=\S+', body_text)
                        if found:
                            link = found.group(0).rstrip("\"'>")
                            break
                    except Exception:
                        pass

            result.append({
                "file":    f.name,
                "to":      to.strip(),
                "subject": subject.strip(),
                "link":    link.strip(),
                "size_kb": round(f.stat().st_size / 1024, 1),
            })
        except Exception:
            result.append({"file": f.name, "to": "", "subject": "", "link": "", "size_kb": 0})
    return result
