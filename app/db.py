"""
db.py — SQLite database cho hệ thống quản lý người dùng và API keys.

Schema
------
  users(
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    email         TEXT     UNIQUE NOT NULL,
    hashed_password TEXT   NOT NULL,
    full_name     TEXT     NOT NULL,
    role          TEXT     NOT NULL  DEFAULT 'Normal',
    is_active     INTEGER  NOT NULL  DEFAULT 1,
    created_at    TEXT     NOT NULL,
    created_by    TEXT     NOT NULL  DEFAULT 'system'
  )

  api_keys(
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    key_hash      TEXT     UNIQUE NOT NULL,  -- SHA-256 của key thật
    key_prefix    TEXT     NOT NULL,          -- 12 ký tự đầu để nhận dạng (sk-gw-XXXXXX)
    user_id       INTEGER  NOT NULL REFERENCES users(id),
    name          TEXT     NOT NULL DEFAULT '',
    is_active     INTEGER  NOT NULL DEFAULT 1,
    created_at    TEXT     NOT NULL,
    last_used_at  TEXT,
    expires_at    TEXT                         -- NULL = không hết hạn
  )

File DB mặc định: users.db (cấu hình qua biến môi trường DB_PATH)
"""

import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path(os.getenv("DB_PATH", "users.db"))


# ---------------------------------------------------------------------------
# Kết nối
# ---------------------------------------------------------------------------

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")   # hỗ trợ đọc/ghi đồng thời
    return c


# ---------------------------------------------------------------------------
# Khởi tạo schema
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Tạo bảng users, api_keys và pending_registrations nếu chưa tồn tại."""
    with _conn() as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER  PRIMARY KEY AUTOINCREMENT,
            email           TEXT     UNIQUE NOT NULL,
            hashed_password TEXT     NOT NULL,
            full_name       TEXT     NOT NULL,
            role            TEXT     NOT NULL DEFAULT 'Normal',
            is_active       INTEGER  NOT NULL DEFAULT 1,
            created_at      TEXT     NOT NULL,
            created_by      TEXT     NOT NULL DEFAULT 'system'
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id           INTEGER  PRIMARY KEY AUTOINCREMENT,
            key_hash     TEXT     UNIQUE NOT NULL,
            key_prefix   TEXT     NOT NULL,
            user_id      INTEGER  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name         TEXT     NOT NULL DEFAULT '',
            is_active    INTEGER  NOT NULL DEFAULT 1,
            created_at   TEXT     NOT NULL,
            last_used_at TEXT,
            expires_at   TEXT
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS pending_registrations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT    UNIQUE NOT NULL,
            full_name       TEXT    NOT NULL,
            hashed_password TEXT    NOT NULL,
            token           TEXT    UNIQUE NOT NULL,
            created_at      TEXT    NOT NULL,
            expires_at      TEXT    NOT NULL
        )
        """)
        c.commit()


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["is_active"] = bool(d["is_active"])
    return d


def create_user(
    email: str,
    hashed_password: str,
    full_name: str,
    role: str = "Normal",
    created_by: str = "system",
) -> dict:
    """Tạo user mới. Raise ValueError nếu email đã tồn tại."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with _conn() as c:
            c.execute(
                """
                INSERT INTO users (email, hashed_password, full_name, role, is_active, created_at, created_by)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (email.lower().strip(), hashed_password, full_name, role, ts, created_by),
            )
            c.commit()
            return get_user_by_email(email)
    except sqlite3.IntegrityError:
        raise ValueError(f"Email '{email}' đã tồn tại.")


def get_user_by_email(email: str) -> Optional[dict]:
    """Trả về dict user hoặc None nếu không tìm thấy."""
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_dict(row) if row else None


def list_users() -> list[dict]:
    """Danh sách toàn bộ users (không bao gồm hashed_password)."""
    with _conn() as c:
        rows = c.execute(
            "SELECT id, email, full_name, role, is_active, created_at, created_by FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def update_user(
    user_id: int,
    *,
    full_name: Optional[str] = None,
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    hashed_password: Optional[str] = None,
) -> Optional[dict]:
    """Cập nhật một hoặc nhiều trường. Trả về dict user sau cập nhật."""
    fields, values = [], []
    if full_name is not None:
        fields.append("full_name = ?"); values.append(full_name)
    if role is not None:
        fields.append("role = ?"); values.append(role)
    if is_active is not None:
        fields.append("is_active = ?"); values.append(1 if is_active else 0)
    if hashed_password is not None:
        fields.append("hashed_password = ?"); values.append(hashed_password)

    if not fields:
        return get_user_by_id(user_id)

    values.append(user_id)
    with _conn() as c:
        c.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
        c.commit()
    return get_user_by_id(user_id)


def delete_user(user_id: int) -> bool:
    with _conn() as c:
        cur = c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        c.commit()
    return cur.rowcount > 0


def count_users() -> int:
    with _conn() as c:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]


# ---------------------------------------------------------------------------
# API Keys — helpers
# ---------------------------------------------------------------------------

_API_KEY_PREFIX = "sk-gw-"


def _hash_key(raw_key: str) -> str:
    """SHA-256 của key thật — dùng để lưu DB và tra cứu."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> str:
    """Tạo API key mới dạng sk-gw-<32 hex chars>."""
    return _API_KEY_PREFIX + secrets.token_hex(16)


def is_api_key(token: str) -> bool:
    """Kiểm tra token có phải API key không (dựa trên prefix)."""
    return token.startswith(_API_KEY_PREFIX)


# ---------------------------------------------------------------------------
# API Keys — CRUD
# ---------------------------------------------------------------------------

def create_api_key(
    user_id: int,
    name: str = "",
    expires_at: Optional[str] = None,
) -> dict:
    """
    Tạo API key mới cho user_id.
    Trả về dict gồm cả `key` (plaintext — chỉ hiển thị 1 lần).
    """
    raw_key  = generate_api_key()
    key_hash = _hash_key(raw_key)
    prefix   = raw_key[:12]          # "sk-gw-XXXXXX" — 12 ký tự
    ts       = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with _conn() as c:
        cur = c.execute(
            """
            INSERT INTO api_keys (key_hash, key_prefix, user_id, name, is_active, created_at, expires_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (key_hash, prefix, user_id, name.strip(), ts, expires_at),
        )
        key_id = cur.lastrowid
        c.commit()

    return {
        "id":          key_id,
        "key":         raw_key,      # plaintext — trả về 1 lần duy nhất
        "key_prefix":  prefix,
        "user_id":     user_id,
        "name":        name.strip(),
        "is_active":   True,
        "created_at":  ts,
        "last_used_at": None,
        "expires_at":  expires_at,
    }


def get_api_key_by_hash(raw_key: str) -> Optional[dict]:
    """
    Tra cứu API key theo giá trị thật (hash SHA-256 để so sánh).
    Trả về None nếu không tồn tại hoặc không active hoặc đã hết hạn.
    """
    key_hash = _hash_key(raw_key)
    with _conn() as c:
        row = c.execute(
            """
            SELECT k.*, u.email, u.full_name, u.role, u.is_active AS user_active
            FROM api_keys k
            JOIN users u ON u.id = k.user_id
            WHERE k.key_hash = ?
            """,
            (key_hash,),
        ).fetchone()
    if not row:
        return None

    d = dict(row)
    d["is_active"]   = bool(d["is_active"])
    d["user_active"] = bool(d["user_active"])

    # Kiểm tra hết hạn
    if d["expires_at"]:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if d["expires_at"] < now:
            return None

    return d


def touch_api_key(key_id: int) -> None:
    """Cập nhật last_used_at khi key được dùng thành công."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _conn() as c:
        c.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (ts, key_id))
        c.commit()


def list_api_keys(user_id: Optional[int] = None) -> list[dict]:
    """
    Danh sách API keys.
    Nếu user_id != None → chỉ keys của user đó.
    Không trả về key_hash.
    """
    with _conn() as c:
        if user_id is not None:
            rows = c.execute(
                """
                SELECT k.id, k.key_prefix, k.user_id, k.name, k.is_active,
                       k.created_at, k.last_used_at, k.expires_at,
                       u.email, u.full_name
                FROM api_keys k JOIN users u ON u.id = k.user_id
                WHERE k.user_id = ?
                ORDER BY k.id DESC
                """,
                (user_id,),
            ).fetchall()
        else:
            rows = c.execute(
                """
                SELECT k.id, k.key_prefix, k.user_id, k.name, k.is_active,
                       k.created_at, k.last_used_at, k.expires_at,
                       u.email, u.full_name
                FROM api_keys k JOIN users u ON u.id = k.user_id
                ORDER BY k.id DESC
                """
            ).fetchall()

    result = []
    for r in rows:
        d = dict(r)
        d["is_active"] = bool(d["is_active"])
        result.append(d)
    return result


def revoke_api_key(key_id: int, user_id: Optional[int] = None) -> bool:
    """
    Thu hồi API key (set is_active = 0).
    Nếu user_id cung cấp → chỉ cho phép revoke key của chính user đó.
    Trả về True nếu thành công.
    """
    with _conn() as c:
        if user_id is not None:
            cur = c.execute(
                "UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?",
                (key_id, user_id),
            )
        else:
            cur = c.execute(
                "UPDATE api_keys SET is_active = 0 WHERE id = ?",
                (key_id,),
            )
        c.commit()
    return cur.rowcount > 0


def delete_api_key(key_id: int, user_id: Optional[int] = None) -> bool:
    """Xóa vĩnh viễn API key. Admin có thể xóa bất kỳ key."""
    with _conn() as c:
        if user_id is not None:
            cur = c.execute(
                "DELETE FROM api_keys WHERE id = ? AND user_id = ?",
                (key_id, user_id),
            )
        else:
            cur = c.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        c.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Pending Registrations — CRUD
# ---------------------------------------------------------------------------

def create_pending_registration(
    email: str,
    full_name: str,
    hashed_password: str,
    token: str,
    expires_at: str,
) -> dict:
    """Tạo bản ghi đăng ký chờ kích hoạt. Raise ValueError nếu email đã tồn tại."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with _conn() as c:
            c.execute(
                """
                INSERT INTO pending_registrations
                    (email, full_name, hashed_password, token, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (email.lower().strip(), full_name, hashed_password, token, ts, expires_at),
            )
            c.commit()
    except sqlite3.IntegrityError:
        raise ValueError(f"Email '{email}' đã có yêu cầu đăng ký đang chờ.")
    return get_pending_by_email(email)


def get_pending_by_token(token: str) -> Optional[dict]:
    """Trả về dict pending hoặc None nếu không tìm thấy."""
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM pending_registrations WHERE token = ?", (token,)
        ).fetchone()
    return dict(row) if row else None


def get_pending_by_email(email: str) -> Optional[dict]:
    """Trả về dict pending hoặc None nếu không tìm thấy."""
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM pending_registrations WHERE email = ?",
            (email.lower().strip(),),
        ).fetchone()
    return dict(row) if row else None


def delete_pending_registration(pending_id: int) -> bool:
    """Xóa bản ghi pending theo id. Trả về True nếu thành công."""
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM pending_registrations WHERE id = ?", (pending_id,)
        )
        c.commit()
    return cur.rowcount > 0


def list_pending_registrations() -> list[dict]:
    """Danh sách toàn bộ pending registrations (không bao gồm hashed_password)."""
    with _conn() as c:
        rows = c.execute(
            """
            SELECT id, email, full_name, token, created_at, expires_at
            FROM pending_registrations
            ORDER BY id DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


def cleanup_expired_pending() -> int:
    """Xóa các bản ghi pending đã hết hạn. Trả về số bản ghi đã xóa."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _conn() as c:
        cur = c.execute(
            "DELETE FROM pending_registrations WHERE expires_at < ?", (now,)
        )
        c.commit()
    return cur.rowcount
