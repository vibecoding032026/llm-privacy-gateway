"""
auth_router.py — Endpoints xác thực người dùng.

  POST /auth/login            — đăng nhập, trả về JWT token
  GET  /auth/me               — thông tin user hiện tại
  POST /auth/change-password  — đổi mật khẩu (user tự đổi)
"""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator

from .auth import create_token, hash_password, verify_password
from .audit_logger import audit_change_password, audit_login, audit_login_fail
from .db import get_user_by_email, update_user
from .dependencies import CurrentUser

router = APIRouter(prefix="/auth", tags=["Auth"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Mật khẩu mới phải có ít nhất 8 ký tự.")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/login")
async def login(body: LoginRequest, request: Request) -> dict:
    """
    Đăng nhập bằng email và mật khẩu.
    Trả về JWT access_token khi thành công.
    """
    ip = request.client.host if request.client else ""
    email = body.email.lower().strip()

    user = get_user_by_email(email)

    # Kiểm tra user tồn tại và active
    if not user:
        audit_login_fail(email, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email hoặc mật khẩu không đúng.",
        )

    if not user["is_active"]:
        audit_login_fail(email, ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tài khoản đã bị khóa. Liên hệ Admin để được hỗ trợ.",
        )

    # Xác thực mật khẩu — chạy trong thread pool để không block event loop
    ok = await asyncio.to_thread(verify_password, body.password, user["hashed_password"])
    if not ok:
        audit_login_fail(email, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email hoặc mật khẩu không đúng.",
        )

    token = create_token(
        user_id=user["id"],
        email=user["email"],
        role=user["role"],
        full_name=user["full_name"],
    )
    audit_login(email, ip)

    return {
        "access_token": token,
        "token_type":   "bearer",
        "user": {
            "id":        user["id"],
            "email":     user["email"],
            "full_name": user["full_name"],
            "role":      user["role"],
        },
    }


@router.get("/me")
async def get_me(user: CurrentUser) -> dict:
    """Trả về thông tin user đang đăng nhập (lấy từ JWT + DB)."""
    return {
        "id":        user["user_id"],
        "email":     user["email"],
        "full_name": user["full_name"],
        "role":      user["role"],
    }


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    user: CurrentUser,
    request: Request,
) -> dict:
    """Người dùng tự đổi mật khẩu của mình."""
    ip = request.client.host if request.client else ""

    # Lấy hashed_password từ DB (token không chứa)
    user_db = get_user_by_email(user["email"])
    if not user_db:
        raise HTTPException(status_code=404, detail="User không tồn tại.")

    ok = await asyncio.to_thread(verify_password, body.current_password, user_db["hashed_password"])
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mật khẩu hiện tại không đúng.",
        )

    new_hash = await asyncio.to_thread(hash_password, body.new_password)
    update_user(user["user_id"], hashed_password=new_hash)
    audit_change_password(user["email"], ip)
    return {"message": "Đổi mật khẩu thành công."}
