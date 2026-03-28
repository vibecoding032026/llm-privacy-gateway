"""
register_router.py — Đăng ký tài khoản tự phục vụ.

Endpoints:
  POST /auth/register   — gửi yêu cầu đăng ký + email kích hoạt
  GET  /auth/activate   — kích hoạt tài khoản từ token trong email
"""
import asyncio
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator

from .auth import hash_password
from .audit_logger import audit_register, audit_activate
from .db import (
    create_pending_registration,
    create_user,
    get_pending_by_email,
    get_pending_by_token,
    get_user_by_email,
    delete_pending_registration,
    cleanup_expired_pending,
)
from .mail import send_activation_email, APP_UI_URL

router = APIRouter(tags=["Auth"])

ALLOWED_DOMAIN       = os.getenv("REGISTER_DOMAIN", "vsec.com.vn")
TOKEN_EXPIRE_HOURS   = int(os.getenv("ACTIVATION_TOKEN_TTL_HOURS", "24"))


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

def _html_page(title: str, icon: str, color: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="vi"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — LLM Privacy Gateway</title>
<style>
  body{{font-family:Arial,sans-serif;background:#f5f7fa;display:flex;
       justify-content:center;align-items:center;min-height:100vh;margin:0}}
  .card{{background:#fff;border-radius:12px;padding:40px 48px;
         max-width:480px;width:90%;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center}}
  h1{{font-size:1.6rem;margin-bottom:8px;color:{color}}}
  p{{color:#555;line-height:1.6}}
  a.btn{{display:inline-block;margin-top:24px;padding:12px 28px;background:{color};
          color:#fff;border-radius:6px;text-decoration:none;font-weight:bold}}
  .icon{{font-size:3rem;margin-bottom:12px}}
</style>
</head><body>
<div class="card">
  <div class="icon">{icon}</div>
  <h1>{title}</h1>
  {body}
  <a class="btn" href="{APP_UI_URL}">Đăng nhập ngay</a>
</div>
</body></html>"""


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: str
    full_name: str
    password: str

    @field_validator("email")
    @classmethod
    def _email_vsec(cls, v: str) -> str:
        v = v.lower().strip()
        if "@" not in v:
            raise ValueError("Email không hợp lệ.")
        domain = v.split("@", 1)[1]
        if domain != ALLOWED_DOMAIN:
            raise ValueError(f"Chỉ chấp nhận email @{ALLOWED_DOMAIN}.")
        return v

    @field_validator("full_name")
    @classmethod
    def _name_len(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Họ tên phải có ít nhất 2 ký tự.")
        return v

    @field_validator("password")
    @classmethod
    def _pwd_len(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Mật khẩu phải có ít nhất 8 ký tự.")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/auth/register", status_code=202)
async def register(body: RegisterRequest, request: Request) -> dict:
    ip = request.client.host if request.client else ""

    cleanup_expired_pending()

    if get_user_by_email(body.email):
        return {"message": f"Email kích hoạt đã được gửi đến {body.email}."}

    pending = get_pending_by_email(body.email)
    if pending:
        return {"message": f"Email kích hoạt đã được gửi đến {body.email}."}

    token      = secrets.token_urlsafe(32)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)).isoformat(timespec="seconds")
    hashed     = await asyncio.to_thread(hash_password, body.password)

    create_pending_registration(
        email=body.email,
        full_name=body.full_name,
        hashed_password=hashed,
        token=token,
        expires_at=expires_at,
    )

    asyncio.get_event_loop().run_in_executor(
        None, send_activation_email, body.email, body.full_name, token
    )

    audit_register(body.email, ip)
    return {"message": f"Email kích hoạt đã được gửi đến {body.email}. Kiểm tra hộp thư và click link trong vòng {TOKEN_EXPIRE_HOURS} giờ."}


@router.get("/auth/activate", response_class=HTMLResponse)
async def activate(token: str, request: Request) -> HTMLResponse:
    ip = request.client.host if request.client else ""

    pending = get_pending_by_token(token)
    if not pending:
        html = _html_page(
            "Link không hợp lệ", "❌", "#e53935",
            "<p>Link kích hoạt không tồn tại hoặc đã được sử dụng.</p>"
            "<p>Vui lòng đăng ký lại nếu bạn chưa có tài khoản.</p>",
        )
        return HTMLResponse(content=html, status_code=400)

    expires = datetime.fromisoformat(pending["expires_at"])
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires:
        delete_pending_registration(pending["id"])
        html = _html_page(
            "Link đã hết hạn", "⏰", "#F57C00",
            f"<p>Link kích hoạt đã hết hạn sau {TOKEN_EXPIRE_HOURS} giờ.</p>"
            "<p>Vui lòng quay lại trang đăng ký để tạo yêu cầu mới.</p>",
        )
        return HTMLResponse(content=html, status_code=400)

    if get_user_by_email(pending["email"]):
        delete_pending_registration(pending["id"])
        html = _html_page(
            "Đã kích hoạt", "✅", "#388E3C",
            "<p>Tài khoản này đã được kích hoạt trước đó.</p>",
        )
        return HTMLResponse(content=html, status_code=200)

    create_user(
        email=pending["email"],
        hashed_password=pending["hashed_password"],
        full_name=pending["full_name"],
        role="Normal",
        created_by="self-register",
    )
    delete_pending_registration(pending["id"])
    audit_activate(pending["email"], ip)

    html = _html_page(
        "Kích hoạt thành công!", "🎉", "#1976D2",
        f"<p>Tài khoản <b>{pending['email']}</b> đã được kích hoạt.</p>"
        f"<p>Xin chào <b>{pending['full_name']}</b>! Nhấp vào nút bên dưới để đăng nhập.</p>",
    )
    return HTMLResponse(content=html, status_code=200)
