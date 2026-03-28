"""
admin_router.py — Endpoints quản lý người dùng (chỉ Admin).

  GET    /admin/users                  — danh sách users
  POST   /admin/users                  — tạo user mới
  GET    /admin/users/{user_id}        — chi tiết user
  PUT    /admin/users/{user_id}        — cập nhật role / full_name
  POST   /admin/users/{user_id}/reset-password  — reset mật khẩu
  POST   /admin/users/{user_id}/lock   — khóa tài khoản
  POST   /admin/users/{user_id}/unlock — mở khóa tài khoản
  DELETE /admin/users/{user_id}        — xóa user
  GET    /admin/audit-logs             — xem audit log
  GET    /admin/audit-logs/{date}      — xem audit log theo ngày
"""

import json
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from .audit_logger import (
    audit_activate,
    audit_create_user,
    audit_delete_user,
    audit_lock_user,
    audit_reset_password,
    audit_unlock_user,
    audit_update_user,
)
from .auth import hash_password
from .config import ROLE_NAMES
from .db import (
    count_users,
    create_user,
    delete_user,
    delete_pending_registration,
    get_user_by_email,
    get_user_by_id,
    list_pending_registrations,
    list_users,
    update_user,
)
from .dependencies import AdminUser

router = APIRouter(prefix="/admin", tags=["Admin"])

_AUDIT_DIR = Path(os.getenv("LOG_DIR", "logs")) / "audit"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CreateUserRequest(BaseModel):
    email: str
    password: str
    full_name: str
    role: str = "Normal"

    @field_validator("email")
    @classmethod
    def _email_fmt(cls, v: str) -> str:
        v = v.lower().strip()
        if "@" not in v:
            raise ValueError("Email không hợp lệ.")
        return v

    @field_validator("password")
    @classmethod
    def _pwd_len(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Mật khẩu phải có ít nhất 8 ký tự.")
        return v

    @field_validator("role")
    @classmethod
    def _role_valid(cls, v: str) -> str:
        for r in ROLE_NAMES:
            if v.lower() == r.lower():
                return r
        raise ValueError(f"Role không hợp lệ. Chọn: {ROLE_NAMES}")


class UpdateUserRequest(BaseModel):
    full_name: str | None = None
    role: str | None = None

    @field_validator("role")
    @classmethod
    def _role_valid(cls, v: str | None) -> str | None:
        if v is None:
            return v
        for r in ROLE_NAMES:
            if v.lower() == r.lower():
                return r
        raise ValueError(f"Role không hợp lệ. Chọn: {ROLE_NAMES}")


class ResetPasswordRequest(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _min_len(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Mật khẩu mới phải có ít nhất 8 ký tự.")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/users")
async def list_all_users(admin: AdminUser) -> list:
    """Danh sách toàn bộ users (không bao gồm hashed_password)."""
    return list_users()


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_new_user(
    body: CreateUserRequest,
    admin: AdminUser,
    request: Request,
) -> dict:
    """Admin tạo user mới với mật khẩu khởi tạo."""
    ip = request.client.host if request.client else ""

    if get_user_by_email(body.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Email '{body.email}' đã tồn tại.",
        )

    hashed = hash_password(body.password)
    user = create_user(
        email=body.email,
        hashed_password=hashed,
        full_name=body.full_name,
        role=body.role,
        created_by=admin["email"],
    )
    audit_create_user(admin["email"], body.email, body.role, ip)

    # Trả về không có hashed_password
    return {k: v for k, v in user.items() if k != "hashed_password"}


@router.get("/users/{user_id}")
async def get_user(user_id: int, admin: AdminUser) -> dict:
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại.")
    return {k: v for k, v in user.items() if k != "hashed_password"}


@router.put("/users/{user_id}")
async def update_user_info(
    user_id: int,
    body: UpdateUserRequest,
    admin: AdminUser,
    request: Request,
) -> dict:
    """Cập nhật full_name và/hoặc role."""
    ip = request.client.host if request.client else ""
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại.")

    changes = {}
    if body.full_name is not None:
        changes["full_name"] = body.full_name
    if body.role is not None:
        changes["role"] = body.role

    updated = update_user(user_id, **changes)
    audit_update_user(admin["email"], user["email"], changes, ip)
    return {k: v for k, v in updated.items() if k != "hashed_password"}


@router.post("/users/{user_id}/reset-password")
async def reset_password(
    user_id: int,
    body: ResetPasswordRequest,
    admin: AdminUser,
    request: Request,
) -> dict:
    """Admin reset mật khẩu cho user."""
    ip = request.client.host if request.client else ""
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại.")

    update_user(user_id, hashed_password=hash_password(body.new_password))
    audit_reset_password(admin["email"], user["email"], ip)
    return {"message": f"Đã reset mật khẩu cho '{user['email']}'."}


@router.post("/users/{user_id}/lock")
async def lock_user(user_id: int, admin: AdminUser, request: Request) -> dict:
    """Khóa tài khoản ngay lập tức."""
    ip = request.client.host if request.client else ""
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại.")
    if user["email"].lower() in {e.lower() for e in [admin["email"]]}:
        raise HTTPException(status_code=400, detail="Không thể tự khóa tài khoản của mình.")

    update_user(user_id, is_active=False)
    audit_lock_user(admin["email"], user["email"], ip)
    return {"message": f"Đã khóa tài khoản '{user['email']}'."}


@router.post("/users/{user_id}/unlock")
async def unlock_user(user_id: int, admin: AdminUser, request: Request) -> dict:
    """Mở khóa tài khoản."""
    ip = request.client.host if request.client else ""
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại.")

    update_user(user_id, is_active=True)
    audit_unlock_user(admin["email"], user["email"], ip)
    return {"message": f"Đã mở khóa tài khoản '{user['email']}'."}


@router.delete("/users/{user_id}")
async def remove_user(user_id: int, admin: AdminUser, request: Request) -> dict:
    """Xóa vĩnh viễn user."""
    ip = request.client.host if request.client else ""
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại.")
    if user["email"].lower() == admin["email"].lower():
        raise HTTPException(status_code=400, detail="Không thể xóa tài khoản Admin đang dùng.")

    delete_user(user_id)
    audit_delete_user(admin["email"], user["email"], ip)
    return {"deleted": user["email"]}


# ---------------------------------------------------------------------------
# Audit log viewer
# ---------------------------------------------------------------------------

@router.get("/audit-logs")
async def list_audit_logs(admin: AdminUser) -> dict:
    """Danh sách file audit log hiện có."""
    if not _AUDIT_DIR.exists():
        return {"files": []}
    files = sorted(_AUDIT_DIR.glob("*.jsonl"), reverse=True)
    return {
        "files": [
            {"date": f.stem, "size_kb": round(f.stat().st_size / 1024, 1)}
            for f in files
        ]
    }


@router.get("/audit-logs/{date}")
async def get_audit_log(
    date: str,
    admin: AdminUser,
    action: str | None = None,
    actor: str | None = None,
) -> list:
    """
    Xem audit log theo ngày.
    Query params: ?action=CREATE_USER  ?actor=admin@vsec.com.vn
    """
    log_file = _AUDIT_DIR / f"{date}.jsonl"
    if not log_file.exists():
        raise HTTPException(status_code=404, detail=f"Không có audit log ngày {date}")

    entries = []
    with log_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if action and entry.get("action") != action.upper():
                    continue
                if actor and entry.get("actor", "").lower() != actor.lower():
                    continue
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    return entries


# ---------------------------------------------------------------------------
# Pending Registrations — Admin endpoints
# ---------------------------------------------------------------------------

@router.get("/pending-registrations")
async def list_pending(admin: AdminUser) -> list:
    """Danh sách các yêu cầu đăng ký đang chờ kích hoạt."""
    return list_pending_registrations()


@router.delete("/pending-registrations/{pid}")
async def delete_pending(pid: int, admin: AdminUser, request: Request) -> dict:
    """Xóa một yêu cầu đăng ký đang chờ."""
    deleted = delete_pending_registration(pid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Yêu cầu đăng ký không tồn tại.")
    return {"deleted": pid}


@router.post("/pending-registrations/{pid}/activate")
async def admin_activate_pending(pid: int, admin: AdminUser, request: Request) -> dict:
    """Admin kích hoạt thủ công một yêu cầu đăng ký đang chờ."""
    from .db import get_pending_by_token, list_pending_registrations

    ip = request.client.host if request.client else ""

    # Tìm pending theo id
    all_pending = list_pending_registrations()
    pending = next((p for p in all_pending if p["id"] == pid), None)

    if not pending:
        raise HTTPException(status_code=404, detail="Yêu cầu đăng ký không tồn tại.")

    # Lấy full record kèm hashed_password
    from .db import get_pending_by_email as _get_pending_full
    pending_full = _get_pending_full(pending["email"])
    if not pending_full:
        raise HTTPException(status_code=404, detail="Yêu cầu đăng ký không tồn tại.")

    if get_user_by_email(pending_full["email"]):
        delete_pending_registration(pid)
        return {"message": f"Tài khoản {pending_full['email']} đã tồn tại — pending đã được dọn dẹp."}

    create_user(
        email=pending_full["email"],
        hashed_password=pending_full["hashed_password"],
        full_name=pending_full["full_name"],
        role="Normal",
        created_by=f"admin:{admin['email']}",
    )
    delete_pending_registration(pid)
    audit_activate(pending_full["email"], ip)

    return {"message": f"Đã kích hoạt tài khoản {pending_full['email']} thành công."}


@router.get("/mail")
async def list_mail_outbox(admin: AdminUser) -> list:
    """Admin xem các email fallback chưa gửi được qua SMTP (trong logs/mail/)."""
    from .mail import list_mail_fallbacks
    return list_mail_fallbacks()
