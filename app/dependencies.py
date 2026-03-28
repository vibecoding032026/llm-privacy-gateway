"""
dependencies.py — FastAPI dependencies cho xác thực JWT / API Key và phân quyền RBAC.

Hỗ trợ 2 phương thức xác thực qua header Authorization: Bearer <token>:
  1. JWT token  — token thông thường, hết hạn sau JWT_EXPIRE_HOURS giờ
  2. API Key    — prefix "sk-gw-", không hết hạn (trừ khi set expires_at)

Sử dụng
-------
  from .dependencies import get_current_user, require_admin, CurrentUser

  @app.get("/protected")
  async def endpoint(user: CurrentUser = Depends(get_current_user)):
      ...

  @app.post("/admin/action")
  async def admin_action(user: CurrentUser = Depends(require_admin)):
      ...
"""

import os
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .auth import decode_token
from .audit_logger import audit_api_key_auth
from .db import get_api_key_by_hash, get_user_by_email, is_api_key, touch_api_key

# ---------------------------------------------------------------------------
# Cấu hình
# ---------------------------------------------------------------------------

_ADMIN_EMAILS_RAW: str = os.getenv("ADMIN_EMAILS", "")
ADMIN_EMAILS: set[str] = {
    e.strip().lower()
    for e in _ADMIN_EMAILS_RAW.split(",")
    if e.strip()
}

_bearer = HTTPBearer(auto_error=True)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
    request: Request,
) -> dict:
    """
    Xác thực qua JWT hoặc API Key (Authorization: Bearer <token>).
    - Token bắt đầu bằng "sk-gw-" → API Key path
    - Còn lại → JWT path
    Trả về payload dict thống nhất: {user_id, email, role, full_name, auth_method}
    """
    token = credentials.credentials
    ip = request.client.host if request.client else ""

    # ── API Key path ──────────────────────────────────────────────────────────
    if is_api_key(token):
        key_record = get_api_key_by_hash(token)

        if not key_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key không hợp lệ, đã bị thu hồi hoặc hết hạn.",
            )
        if not key_record["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key đã bị thu hồi.",
            )
        if not key_record["user_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tài khoản đã bị khóa.",
            )

        # Cập nhật last_used_at bất đồng bộ (không block response)
        import asyncio
        asyncio.get_event_loop().run_in_executor(
            None, touch_api_key, key_record["id"]
        )
        audit_api_key_auth(key_record["email"], key_record["key_prefix"], ip)

        return {
            "user_id":     key_record["user_id"],
            "email":       key_record["email"],
            "full_name":   key_record["full_name"],
            "role":        key_record["role"],
            "auth_method": "api_key",
            "key_id":      key_record["id"],
            "key_prefix":  key_record["key_prefix"],
        }

    # ── JWT path ──────────────────────────────────────────────────────────────
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token đã hết hạn. Vui lòng đăng nhập lại.",
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token không hợp lệ: {e}",
        )

    # Đồng bộ role mới nhất từ DB
    user_db = get_user_by_email(payload["email"])
    if not user_db or not user_db["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tài khoản đã bị khóa hoặc không tồn tại.",
        )

    payload["role"]        = user_db["role"]
    payload["full_name"]   = user_db["full_name"]
    payload["user_id"]     = user_db["id"]
    payload["auth_method"] = "jwt"
    return payload


async def require_admin(
    user: Annotated[dict, Depends(get_current_user)],
) -> dict:
    """
    Chỉ cho phép các email được chỉ định trong ADMIN_EMAILS.
    Raise 403 nếu không phải admin.
    """
    if user["email"].lower() not in ADMIN_EMAILS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Chỉ Admin mới được thực hiện thao tác này.",
        )
    return user


# Type alias tiện dụng
CurrentUser = Annotated[dict, Depends(get_current_user)]
AdminUser   = Annotated[dict, Depends(require_admin)]
