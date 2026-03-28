"""
audit_logger.py — Ghi Audit Log cho mọi hành động quan trọng trong hệ thống.

Mỗi sự kiện ghi 1 dòng JSON vào: logs/audit/YYYY-MM-DD.jsonl

Format mỗi bản ghi
------------------
{
  "timestamp": "2026-03-22T14:30:00+00:00",
  "actor":     "admin@vsec.com.vn",          ← người thực hiện
  "action":    "CREATE_USER",
  "target":    "nhanvien@vsec.com.vn",        ← đối tượng bị tác động
  "detail":    {"role": "SOC", ...},          ← chi tiết tuỳ action
  "ip":        "127.0.0.1"                    ← IP của request (nếu có)
}

Các action được định nghĩa
--------------------------
  AUTH_LOGIN            — đăng nhập thành công
  AUTH_LOGIN_FAIL       — đăng nhập thất bại (sai mật khẩu)
  AUTH_CHANGE_PASSWORD  — đổi mật khẩu
  CREATE_USER           — admin tạo user mới
  UPDATE_USER           — admin cập nhật thông tin user
  RESET_PASSWORD        — admin reset mật khẩu user
  LOCK_USER             — admin khóa tài khoản
  UNLOCK_USER           — admin mở khóa tài khoản
  DELETE_USER           — admin xóa user
  UPLOAD_DOC            — upload tài liệu vào Knowledge Base
  DELETE_DOC            — xóa tài liệu khỏi Knowledge Base
  ACCESS_DOC            — user truy cập/hỏi về tài liệu (RAG)
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_AUDIT_DIR = Path(os.getenv("LOG_DIR", "logs")) / "audit"
_AUDIT_DIR.mkdir(parents=True, exist_ok=True)

_console = logging.getLogger("gateway.audit")


def _today_file() -> Path:
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return _AUDIT_DIR / f"{date_str}.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_audit(
    action: str,
    actor: str,
    target: str = "",
    detail: dict[str, Any] | None = None,
    ip: str = "",
) -> None:
    """Ghi một sự kiện audit vào file JSONL và console."""
    entry = {
        "timestamp": _now(),
        "actor":     actor,
        "action":    action,
        "target":    target,
        "detail":    detail or {},
        "ip":        ip,
    }
    with _today_file().open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    _console.info(
        "[AUDIT] %s  |  actor=%-30s  |  target=%s  |  %s",
        action, actor, target,
        json.dumps(detail or {}, ensure_ascii=False)[:120],
    )


# ---------------------------------------------------------------------------
# Shortcut helpers
# ---------------------------------------------------------------------------

def audit_login(email: str, ip: str = "") -> None:
    log_audit("AUTH_LOGIN", actor=email, ip=ip)

def audit_login_fail(email: str, ip: str = "") -> None:
    log_audit("AUTH_LOGIN_FAIL", actor=email, ip=ip)

def audit_change_password(email: str, ip: str = "") -> None:
    log_audit("AUTH_CHANGE_PASSWORD", actor=email, ip=ip)

def audit_create_user(admin: str, new_email: str, role: str, ip: str = "") -> None:
    log_audit("CREATE_USER", actor=admin, target=new_email, detail={"role": role}, ip=ip)

def audit_update_user(admin: str, target_email: str, changes: dict, ip: str = "") -> None:
    log_audit("UPDATE_USER", actor=admin, target=target_email, detail=changes, ip=ip)

def audit_reset_password(admin: str, target_email: str, ip: str = "") -> None:
    log_audit("RESET_PASSWORD", actor=admin, target=target_email, ip=ip)

def audit_lock_user(admin: str, target_email: str, ip: str = "") -> None:
    log_audit("LOCK_USER", actor=admin, target=target_email, ip=ip)

def audit_unlock_user(admin: str, target_email: str, ip: str = "") -> None:
    log_audit("UNLOCK_USER", actor=admin, target=target_email, ip=ip)

def audit_delete_user(admin: str, target_email: str, ip: str = "") -> None:
    log_audit("DELETE_USER", actor=admin, target=target_email, ip=ip)

def audit_upload_doc(actor: str, doc_id: str, filename: str, allowed_roles: str, ip: str = "") -> None:
    log_audit("UPLOAD_DOC", actor=actor, target=doc_id,
              detail={"filename": filename, "allowed_roles": allowed_roles}, ip=ip)

def audit_delete_doc(actor: str, doc_id: str, filename: str, ip: str = "") -> None:
    log_audit("DELETE_DOC", actor=actor, target=doc_id, detail={"filename": filename}, ip=ip)

def audit_access_doc(actor: str, doc_ids: list[str], query_preview: str, ip: str = "") -> None:
    log_audit("ACCESS_DOC", actor=actor, target=",".join(doc_ids),
              detail={"query": query_preview[:100]}, ip=ip)

def audit_create_api_key(actor: str, key_prefix: str, target_email: str, name: str, ip: str = "") -> None:
    log_audit("CREATE_API_KEY", actor=actor, target=target_email,
              detail={"key_prefix": key_prefix, "name": name}, ip=ip)

def audit_revoke_api_key(actor: str, key_id: int, target_email: str, ip: str = "") -> None:
    log_audit("REVOKE_API_KEY", actor=actor, target=target_email,
              detail={"key_id": key_id}, ip=ip)

def audit_delete_api_key(actor: str, key_id: int, target_email: str, ip: str = "") -> None:
    log_audit("DELETE_API_KEY", actor=actor, target=target_email,
              detail={"key_id": key_id}, ip=ip)

def audit_api_key_auth(email: str, key_prefix: str, ip: str = "") -> None:
    log_audit("API_KEY_AUTH", actor=email, detail={"key_prefix": key_prefix}, ip=ip)

def audit_register(email: str, ip: str = "") -> None:
    log_audit("SELF_REGISTER", actor=email, target=email, ip=ip)

def audit_activate(email: str, ip: str = "") -> None:
    log_audit("SELF_ACTIVATE", actor=email, target=email, detail={"role": "Normal"}, ip=ip)
