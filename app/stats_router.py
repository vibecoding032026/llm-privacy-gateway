"""
stats_router.py — API thống kê sử dụng (Admin only).

Endpoints
---------
  GET /admin/stats/summary?days=30        — tổng quan hệ thống
  GET /admin/stats/users?days=30          — thống kê theo cá nhân
  GET /admin/stats/departments?days=30    — thống kê theo bộ phận (role)
  GET /admin/stats/daily?days=30          — xu hướng sử dụng theo ngày
"""

import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Query
from .dependencies import AdminUser

router = APIRouter(tags=["Stats"])

_USAGE_DIR = Path(os.getenv("LOG_DIR", "logs")) / "usage"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_entries(days: int) -> list[dict]:
    """Đọc tất cả usage entries trong `days` ngày gần nhất."""
    entries = []
    today = datetime.now(timezone.utc).date()
    for i in range(days):
        d = today - timedelta(days=i)
        f = _USAGE_DIR / f"{d.isoformat()}.jsonl"
        if not f.exists():
            continue
        with f.open(encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/admin/stats/summary")
async def stats_summary(
    _: AdminUser,
    days: int = Query(30, ge=1, le=365),
) -> dict:
    """Tổng quan hệ thống trong N ngày gần nhất."""
    entries = _read_entries(days)
    ok_entries = [e for e in entries if e.get("ok")]
    total = len(entries)

    unique_users  = len({e["email"] for e in entries})
    total_tokens  = sum(e.get("total_tokens", 0) for e in entries)
    total_masked  = sum(e.get("masked_entities", 0) for e in entries)
    avg_latency   = (
        round(sum(e.get("latency_ms", 0) for e in ok_entries) / len(ok_entries))
        if ok_entries else 0
    )
    success_rate  = round(len(ok_entries) / total * 100, 1) if total else 0
    chat_count    = sum(1 for e in entries if e.get("type") == "CHAT")
    rag_count     = sum(1 for e in entries if e.get("type") == "RAG_CHAT")

    return {
        "period_days":       days,
        "total_requests":    total,
        "chat_requests":     chat_count,
        "rag_requests":      rag_count,
        "unique_users":      unique_users,
        "total_tokens":      total_tokens,
        "total_masked":      total_masked,
        "avg_latency_ms":    avg_latency,
        "success_rate":      success_rate,
    }


@router.get("/admin/stats/users")
async def stats_users(
    _: AdminUser,
    days: int = Query(30, ge=1, le=365),
) -> list:
    """Thống kê sử dụng theo từng cá nhân."""
    entries = _read_entries(days)
    agg: dict = defaultdict(lambda: {
        "email": "", "role": "",
        "requests": 0, "total_tokens": 0, "masked_entities": 0,
        "latency_sum": 0, "latency_count": 0,
        "errors": 0, "chat": 0, "rag": 0,
        "last_active": "",
    })

    for e in entries:
        email = e["email"]
        a = agg[email]
        a["email"] = email
        a["role"]  = e.get("role", "Normal")
        a["requests"] += 1
        a["total_tokens"]    += e.get("total_tokens", 0)
        a["masked_entities"] += e.get("masked_entities", 0)
        if e.get("type") == "CHAT":
            a["chat"] += 1
        elif e.get("type") == "RAG_CHAT":
            a["rag"] += 1
        if e.get("ok"):
            a["latency_sum"]   += e.get("latency_ms", 0)
            a["latency_count"] += 1
        else:
            a["errors"] += 1
        ts = e.get("timestamp", "")
        if ts > a["last_active"]:
            a["last_active"] = ts

    result = []
    for a in agg.values():
        avg_lat = (
            round(a["latency_sum"] / a["latency_count"])
            if a["latency_count"] else 0
        )
        success = (
            round((a["requests"] - a["errors"]) / a["requests"] * 100, 1)
            if a["requests"] else 0
        )
        result.append({
            "email":           a["email"],
            "role":            a["role"],
            "requests":        a["requests"],
            "chat":            a["chat"],
            "rag":             a["rag"],
            "total_tokens":    a["total_tokens"],
            "avg_latency_ms":  avg_lat,
            "success_rate":    success,
            "errors":          a["errors"],
            "masked_entities": a["masked_entities"],
            "last_active":     a["last_active"][:10] if a["last_active"] else "",
        })
    return sorted(result, key=lambda x: x["requests"], reverse=True)


@router.get("/admin/stats/departments")
async def stats_departments(
    _: AdminUser,
    days: int = Query(30, ge=1, le=365),
) -> list:
    """Thống kê sử dụng theo bộ phận (role)."""
    entries = _read_entries(days)
    agg: dict = defaultdict(lambda: {
        "role": "",
        "requests": 0, "total_tokens": 0,
        "users": set(), "errors": 0,
        "masked_entities": 0, "chat": 0, "rag": 0,
    })

    for e in entries:
        role = e.get("role", "Normal")
        a = agg[role]
        a["role"] = role
        a["requests"] += 1
        a["total_tokens"]    += e.get("total_tokens", 0)
        a["masked_entities"] += e.get("masked_entities", 0)
        a["users"].add(e["email"])
        if e.get("type") == "CHAT":
            a["chat"] += 1
        elif e.get("type") == "RAG_CHAT":
            a["rag"] += 1
        if not e.get("ok"):
            a["errors"] += 1

    result = []
    for a in agg.values():
        result.append({
            "role":            a["role"],
            "requests":        a["requests"],
            "chat":            a["chat"],
            "rag":             a["rag"],
            "total_tokens":    a["total_tokens"],
            "unique_users":    len(a["users"]),
            "errors":          a["errors"],
            "masked_entities": a["masked_entities"],
        })
    return sorted(result, key=lambda x: x["requests"], reverse=True)


@router.get("/admin/stats/daily")
async def stats_daily(
    _: AdminUser,
    days: int = Query(30, ge=1, le=365),
) -> list:
    """Xu hướng sử dụng theo ngày."""
    entries = _read_entries(days)
    agg: dict = defaultdict(lambda: {
        "date": "",
        "requests": 0, "chat": 0, "rag": 0,
        "total_tokens": 0, "unique_users": set(),
        "masked_entities": 0,
    })

    for e in entries:
        date = e.get("timestamp", "")[:10]
        if not date:
            continue
        a = agg[date]
        a["date"] = date
        a["requests"] += 1
        a["total_tokens"]    += e.get("total_tokens", 0)
        a["masked_entities"] += e.get("masked_entities", 0)
        a["unique_users"].add(e["email"])
        if e.get("type") == "CHAT":
            a["chat"] += 1
        elif e.get("type") == "RAG_CHAT":
            a["rag"] += 1

    result = []
    for a in agg.values():
        result.append({
            "date":            a["date"],
            "requests":        a["requests"],
            "chat":            a["chat"],
            "rag":             a["rag"],
            "total_tokens":    a["total_tokens"],
            "unique_users":    len(a["unique_users"]),
            "masked_entities": a["masked_entities"],
        })

    # Điền các ngày không có dữ liệu (requests=0) để biểu đồ liền mạch
    today = datetime.now(timezone.utc).date()
    date_set = {r["date"] for r in result}
    for i in range(days):
        d = (today - timedelta(days=i)).isoformat()
        if d not in date_set:
            result.append({
                "date": d, "requests": 0, "chat": 0, "rag": 0,
                "total_tokens": 0, "unique_users": 0, "masked_entities": 0,
            })

    return sorted(result, key=lambda x: x["date"])
