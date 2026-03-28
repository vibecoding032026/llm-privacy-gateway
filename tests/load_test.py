"""
load_test.py — Kiểm tra khả năng xử lý đồng thời của LLM Privacy Gateway.

Kịch bản:
  - N người dùng gửi request cùng lúc (asyncio + httpx)
  - Mỗi user gửi 3 request liên tiếp: /health, /auth/login, /v1/chat/completions
  - Đo: latency (p50/p95/p99), throughput, error rate

Chạy:
  python3 tests/load_test.py --users 20 --skip-llm
  python3 tests/load_test.py --users 20            # Gọi OpenAI thật
"""

import argparse
import asyncio
import statistics
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

BASE = "http://localhost:8000"
ADMIN_EMAIL = "admin@vsec.com.vn"
ADMIN_PASS  = "Admin@2026"


@dataclass
class Result:
    user_id: int
    step: str
    status: int
    latency_ms: float
    error: Optional[str] = None


async def run_user(client: httpx.AsyncClient, user_id: int, skip_llm: bool) -> list[Result]:
    results = []

    # ── Bước 1: Health check ──────────────────────────────────────────
    t0 = time.monotonic()
    try:
        r = await client.get(f"{BASE}/health", timeout=10)
        results.append(Result(user_id, "health", r.status_code, (time.monotonic()-t0)*1000))
    except Exception as e:
        results.append(Result(user_id, "health", 0, (time.monotonic()-t0)*1000, str(e)))
        return results  # Không thể tiếp tục nếu gateway down

    # ── Bước 2: Login ─────────────────────────────────────────────────
    t0 = time.monotonic()
    token = None
    try:
        r = await client.post(f"{BASE}/auth/login",
                              json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
                              timeout=10)
        lat = (time.monotonic()-t0)*1000
        results.append(Result(user_id, "login", r.status_code, lat))
        if r.status_code == 200:
            token = r.json().get("access_token")
    except Exception as e:
        results.append(Result(user_id, "login", 0, (time.monotonic()-t0)*1000, str(e)))

    if not token:
        return results

    headers = {"Authorization": f"Bearer {token}"}

    # ── Bước 3: Chat (hoặc mock nếu --skip-llm) ───────────────────────
    if skip_llm:
        # Gọi /auth/me thay thế (không tốn token)
        t0 = time.monotonic()
        try:
            r = await client.get(f"{BASE}/auth/me", headers=headers, timeout=10)
            results.append(Result(user_id, "auth_me", r.status_code, (time.monotonic()-t0)*1000))
        except Exception as e:
            results.append(Result(user_id, "auth_me", 0, (time.monotonic()-t0)*1000, str(e)))

        # Gọi /documents (kiểm tra DB + ChromaDB path)
        t0 = time.monotonic()
        try:
            r = await client.get(f"{BASE}/documents", headers=headers, timeout=10)
            results.append(Result(user_id, "documents", r.status_code, (time.monotonic()-t0)*1000))
        except Exception as e:
            results.append(Result(user_id, "documents", 0, (time.monotonic()-t0)*1000, str(e)))

    else:
        # Gọi OpenAI thật
        payload = {
            "model": "gpt-4o-mini",
            "session_id": f"load-test-{user_id}",
            "messages": [{"role": "user",
                          "content": f"Server srv-web-{user_id:02d} tại 10.0.{user_id}.1 báo lỗi 500. Tóm tắt ngắn gọn."}],
            "max_tokens": 60,
        }
        t0 = time.monotonic()
        try:
            r = await client.post(f"{BASE}/v1/chat/completions",
                                  json=payload, headers=headers, timeout=60)
            results.append(Result(user_id, "chat", r.status_code, (time.monotonic()-t0)*1000))
        except Exception as e:
            results.append(Result(user_id, "chat", 0, (time.monotonic()-t0)*1000, str(e)))

    return results


def print_report(all_results: list[Result], total_time_s: float, n_users: int, skip_llm: bool):
    print()
    print("=" * 62)
    print(f"  LOAD TEST REPORT — {n_users} users đồng thời")
    print("=" * 62)

    # Nhóm theo step
    by_step: dict[str, list[Result]] = {}
    for r in all_results:
        by_step.setdefault(r.step, []).append(r)

    total_req = len(all_results)
    total_err = sum(1 for r in all_results if r.status not in (200, 201, 204) or r.error)
    all_lat   = [r.latency_ms for r in all_results if not r.error]

    print(f"\n  Tổng requests : {total_req}")
    print(f"  Lỗi           : {total_err}  ({total_err/total_req*100:.1f}%)")
    print(f"  Tổng thời gian: {total_time_s:.2f}s")
    if all_lat:
        tput = total_req / total_time_s
        print(f"  Throughput    : {tput:.1f} req/s")

    print()
    print(f"  {'Step':<14} {'Count':>5}  {'Err':>4}  {'p50(ms)':>8}  {'p95(ms)':>8}  {'p99(ms)':>8}  {'max(ms)':>8}")
    print(f"  {'-'*14}  {'-'*5}  {'-'*4}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}")

    for step, reqs in by_step.items():
        lats = sorted(r.latency_ms for r in reqs if not r.error)
        errs = sum(1 for r in reqs if r.status not in (200, 201, 204) or r.error)
        if lats:
            p50 = statistics.median(lats)
            p95 = lats[int(len(lats)*0.95)] if len(lats) > 1 else lats[0]
            p99 = lats[int(len(lats)*0.99)] if len(lats) > 1 else lats[0]
            mx  = max(lats)
            print(f"  {step:<14} {len(reqs):>5}  {errs:>4}  {p50:>8.0f}  {p95:>8.0f}  {p99:>8.0f}  {mx:>8.0f}")
        else:
            print(f"  {step:<14} {len(reqs):>5}  {errs:>4}  {'N/A':>8}")

    # Đánh giá
    print()
    chat_step = "chat" if not skip_llm else "auth_me"
    key_lats = [r.latency_ms for r in by_step.get(chat_step, []) if not r.error]
    login_lats = [r.latency_ms for r in by_step.get("login", []) if not r.error]

    print("  KẾT LUẬN:")
    verdict = "✅ ĐẠT"

    if total_err / total_req > 0.05:
        verdict = "❌ KHÔNG ĐẠT"
        print(f"  ❌ Error rate {total_err/total_req*100:.1f}% > 5% ngưỡng cho phép")

    if login_lats:
        p95_login = sorted(login_lats)[int(len(login_lats)*0.95)] if len(login_lats) > 1 else login_lats[0]
        if p95_login > 2000:
            verdict = "⚠️  CẦN TỐI ƯU"
            print(f"  ⚠️  Login p95 = {p95_login:.0f}ms > 2000ms")

    if key_lats and not skip_llm:
        p95_chat = sorted(key_lats)[int(len(key_lats)*0.95)] if len(key_lats) > 1 else key_lats[0]
        if p95_chat > 30000:
            print(f"  ⚠️  Chat p95 = {p95_chat:.0f}ms (phụ thuộc OpenAI latency)")

    if verdict == "✅ ĐẠT":
        print(f"  ✅ Gateway xử lý {n_users} users đồng thời — không lỗi, latency chấp nhận được")

    print(f"\n  {verdict}")
    print("=" * 62)

    # Liệt kê lỗi cụ thể nếu có
    errors = [r for r in all_results if r.error or r.status not in (200, 201, 204)]
    if errors:
        print("\n  Chi tiết lỗi:")
        for r in errors[:10]:
            msg = r.error or f"HTTP {r.status}"
            print(f"    user={r.user_id:>3}  step={r.step:<12}  {msg}")


async def main(n_users: int, skip_llm: bool):
    print(f"Bắt đầu load test: {n_users} users đồng thời  [skip_llm={skip_llm}]")
    print(f"Gateway: {BASE}")
    print()

    # Tạo tất cả tasks đồng thời
    async with httpx.AsyncClient() as client:
        t_start = time.monotonic()
        tasks = [run_user(client, i+1, skip_llm) for i in range(n_users)]
        results_nested = await asyncio.gather(*tasks)
        total_time = time.monotonic() - t_start

    all_results = [r for user_results in results_nested for r in user_results]
    print_report(all_results, total_time, n_users, skip_llm)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=20, help="Số user đồng thời")
    parser.add_argument("--skip-llm", action="store_true", help="Bỏ qua gọi OpenAI")
    args = parser.parse_args()
    asyncio.run(main(args.users, args.skip_llm))
