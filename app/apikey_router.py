"""
apikey_router.py — Quản lý API Keys cho LLM Privacy Gateway.

Chỉ Admin mới được tạo, xem và xóa API keys.

  GET    /admin/api-keys             — danh sách toàn bộ API keys
  POST   /admin/api-keys             — tạo key cho bất kỳ user nào
  DELETE /admin/api-keys/{key_id}    — xóa key bất kỳ
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from .audit_logger import audit_create_api_key, audit_delete_api_key
from .db import create_api_key, delete_api_key, get_user_by_id, list_api_keys
from .dependencies import AdminUser

router = APIRouter(tags=["API Keys"])


class AdminCreateKeyRequest(BaseModel):
    user_id: int
    name: str = ""
    expires_at: Optional[str] = None


@router.get("/admin/api-keys")
async def list_all_api_keys(admin: AdminUser) -> list[dict]:
    """Danh sách toàn bộ API keys (Admin only)."""
    return list_api_keys()


@router.post("/admin/api-keys", status_code=status.HTTP_201_CREATED)
async def admin_create_api_key(
    body: AdminCreateKeyRequest,
    admin: AdminUser,
    request: Request,
) -> dict:
    """Admin tạo API key cho bất kỳ user nào."""
    ip = request.client.host if request.client else ""
    target = get_user_by_id(body.user_id)
    if not target:
        raise HTTPException(status_code=404, detail=f"User id={body.user_id} không tồn tại.")

    result = create_api_key(
        user_id=body.user_id,
        name=body.name,
        expires_at=body.expires_at,
    )
    audit_create_api_key(
        actor=admin["email"],
        key_prefix=result["key_prefix"],
        target_email=target["email"],
        name=body.name,
        ip=ip,
    )
    return result


@router.delete("/admin/api-keys/{key_id}")
async def admin_delete_api_key(
    key_id: int,
    admin: AdminUser,
    request: Request,
) -> dict:
    """Admin xóa vĩnh viễn một API key."""
    ip = request.client.host if request.client else ""

    keys = list_api_keys()
    key_info = next((k for k in keys if k["id"] == key_id), None)
    target_email = key_info["email"] if key_info else "unknown"

    ok = delete_api_key(key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Không tìm thấy API key.")

    audit_delete_api_key(actor=admin["email"], key_id=key_id,
                         target_email=target_email, ip=ip)
    return {"deleted": key_id}
