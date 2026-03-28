"""
auth.py — JWT + bcrypt utilities.

  hash_password(plain)          → bcrypt hash
  verify_password(plain, hash)  → bool
  create_token(user)            → JWT string
  decode_token(token)           → payload dict
"""

import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

JWT_SECRET: str    = os.getenv("JWT_SECRET", "change-me-please-set-in-dotenv")
JWT_ALGORITHM      = "HS256"
JWT_EXPIRE_HOURS   = int(os.getenv("JWT_EXPIRE_HOURS", "8"))


# ---------------------------------------------------------------------------
# Password
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# JWT Token
# ---------------------------------------------------------------------------

def create_token(user_id: int, email: str, role: str, full_name: str) -> str:
    """Tạo JWT token hợp lệ trong JWT_EXPIRE_HOURS giờ."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub":       str(user_id),
        "email":     email,
        "role":      role,
        "full_name": full_name,
        "iat":       now,
        "exp":       now + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Giải mã và xác thực JWT.
    Raise jwt.ExpiredSignatureError hoặc jwt.InvalidTokenError nếu không hợp lệ.
    """
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
