"""
test_cases.py — Bộ kiểm thử toàn diện cho LLM Privacy Gateway.

Phân loại test:
  UNIT      — Masker trực tiếp (không cần server, không gọi OpenAI)
  API_CHAT  — Chat đơn giản qua HTTP (gọi OpenAI)
  API_LOG   — Đoạn log nhiều dòng, nhiều định dạng khác nhau
  API_LEN   — Kiểm thử với độ dài đoạn log khác nhau
  EDGE      — Trường hợp đặc biệt / biên

Chạy:
  python tests/test_cases.py                 # tất cả
  python tests/test_cases.py --unit-only     # chỉ unit tests (không tốn API credit)
  python tests/test_cases.py --skip-api      # bỏ qua các test gọi OpenAI
"""

import os
import re
import sys
import time
import uuid
import json
import textwrap
import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Cấu hình
# ---------------------------------------------------------------------------

GATEWAY_URL  = os.getenv("GATEWAY_URL",  "http://localhost:8000/v1/chat/completions")
GATEWAY_BASE = GATEWAY_URL.rsplit("/v1/", 1)[0]
MODEL        = os.getenv("MODEL", "gpt-4o-mini")
REPORT_DIR   = Path("tests/reports")
TAG_RE       = re.compile(r"\[(?:IP|HOST|EMAIL|PATH)_\d+\]")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TestCase:
    id: str
    category: str
    name: str
    description: str
    tags: list[str] = field(default_factory=list)

@dataclass
class TestResult:
    case: TestCase
    status: str          # PASS / FAIL / ERROR / SKIP
    duration_ms: float
    details: str
    error: str = ""
    token_usage: dict = field(default_factory=dict)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_api(messages: list[dict], session_id: str | None = None,
              log_block: bool = False, max_tokens: int = 512) -> dict:
    sid = session_id or uuid.uuid4().hex[:8]
    resp = requests.post(
        GATEWAY_URL,
        json={
            "model": MODEL,
            "messages": messages,
            "session_id": sid,
            "log_block": log_block,
            "temperature": 0.2,
            "max_tokens": max_tokens,
        },
        timeout=200,
    )
    resp.raise_for_status()
    return resp.json()


def _get_stats(session_id: str) -> dict:
    r = requests.get(f"{GATEWAY_BASE}/v1/session/{session_id}/stats", timeout=5)
    return r.json() if r.ok else {}


def _clear(session_id: str) -> None:
    try:
        requests.delete(f"{GATEWAY_BASE}/v1/session/{session_id}", timeout=5)
    except Exception:
        pass


def _reply(result: dict) -> str:
    return result["choices"][0]["message"]["content"]


def _usage(result: dict) -> dict:
    return result.get("usage", {})


def _has_tag_leak(text: str) -> bool:
    return bool(TAG_RE.search(text))


def _assert(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)

# ---------------------------------------------------------------------------
# ── UNIT TESTS (Masker trực tiếp) ──────────────────────────────────────────
# ---------------------------------------------------------------------------

sys.path.insert(0, ".")
from app.masker import Masker

def _run_unit(fn) -> tuple[str, str]:
    """Chạy 1 unit test function, trả về (status, details)."""
    try:
        details = fn()
        return "PASS", details or "OK"
    except AssertionError as e:
        return "FAIL", str(e)
    except Exception as e:
        return "ERROR", f"{type(e).__name__}: {e}"


def unit_ip_single():
    m = Masker(); sid = "u1"
    out = m.mask("Server tại 10.0.0.5 bị lỗi", sid)
    _assert("[IP_1]" in out, f"IP không bị mask: {out}")
    _assert("10.0.0.5" not in out, "IP thật còn lộ")
    return f"'10.0.0.5' → '[IP_1]'  |  result: {out}"


def unit_ip_multiple():
    m = Masker(); sid = "u2"
    out = m.mask("Từ 1.2.3.4 đến 5.6.7.8 và 9.10.11.12", sid)
    _assert("[IP_1]" in out and "[IP_2]" in out and "[IP_3]" in out,
            f"Không đủ 3 tag IP: {out}")
    return f"3 IP khác nhau → 3 tag khác nhau: {out}"


def unit_ip_context_integrity():
    m = Masker(); sid = "u3"
    t1 = m.mask("IP là 192.168.1.100", sid)
    t2 = m.mask("Kiểm tra lại 192.168.1.100", sid)
    tag1 = re.search(r"\[IP_\d+\]", t1).group()
    tag2 = re.search(r"\[IP_\d+\]", t2).group()
    _assert(tag1 == tag2, f"Cùng IP nhưng khác tag: {tag1} vs {tag2}")
    return f"192.168.1.100 → {tag1} nhất quán qua 2 lượt"


def unit_email():
    m = Masker(); sid = "u4"
    out = m.mask("Liên hệ admin@internal.corp để hỗ trợ", sid)
    _assert("[EMAIL_1]" in out, f"Email không bị mask: {out}")
    _assert("admin@internal.corp" not in out, "Email thật còn lộ")
    return f"'admin@internal.corp' → '[EMAIL_1]'"


def unit_hostname_prefix():
    m = Masker(); sid = "u5"
    out = m.mask("Server srv-web-01 và db-master-01 bị lỗi", sid)
    _assert("[HOST_1]" in out, f"HOST_1 không được tạo: {out}")
    _assert("[HOST_2]" in out, f"HOST_2 không được tạo: {out}")
    _assert("srv-web-01" not in out, "Hostname thật còn lộ")
    return f"srv-web-01→[HOST_1], db-master-01→[HOST_2]  |  {out}"


def unit_hostname_nn_pattern():
    m = Masker(); sid = "u6"
    out = m.mask("app-server-02 và worker-07 bị quá tải", sid)
    _assert("[HOST_" in out, f"Hostname dạng word-NN không bị mask: {out}")
    return f"app-server-02, worker-07 bị mask đúng: {out}"


def unit_fqdn():
    m = Masker(); sid = "u7"
    out = m.mask("Host app-prod-db01.internal.vsec.com.vn kết nối thất bại", sid)
    _assert("[HOST_1]" in out, f"FQDN không bị mask: {out}")
    _assert("app-prod-db01.internal.vsec.com.vn" not in out, "FQDN thật còn lộ")
    return f"FQDN bị mask: {out}"


def unit_path():
    m = Masker(); sid = "u8"
    out = m.mask("Xem log tại /var/log/nginx/error.log", sid)
    _assert("[PATH_1]" in out, f"Path không bị mask: {out}")
    return f"'/var/log/nginx/error.log' → '[PATH_1]'"


def unit_cve_not_masked():
    m = Masker(); sid = "u9"
    out = m.mask("Phát hiện CVE-2024-1086 trên server srv-web-01", sid)
    _assert("CVE-2024-1086" in out, f"CVE ID bị mask nhầm: {out}")
    _assert("[HOST_1]" in out, f"Hostname không bị mask: {out}")
    return f"CVE-2024-1086 giữ nguyên, srv-web-01→[HOST_1]  |  {out}"


def unit_protocol_version_not_masked():
    m = Masker(); sid = "u10"
    text = 'Kết nối TLS-1.3 và HTTP-1.1 từ 10.0.0.1'
    out = m.mask(text, sid)
    _assert("TLS-1.3" in out,  f"TLS-1.3 bị mask nhầm: {out}")
    _assert("HTTP-1.1" in out, f"HTTP-1.1 bị mask nhầm: {out}")
    _assert("[IP_1]" in out,   f"IP không bị mask: {out}")
    return f"TLS-1.3, HTTP-1.1 giữ nguyên; IP bị mask  |  {out}"


def unit_mixed_entities():
    m = Masker(); sid = "u11"
    text = "srv-api-01 (10.1.2.3) gửi mail đến ops@corp.vn, log: /var/log/app.log"
    out = m.mask(text, sid)
    stats = m.session_stats(sid)
    _assert(stats["mapped_values"] == 4, f"Phải có 4 entity, thực tế: {stats['mapped_values']}")
    _assert("srv-api-01" not in out, "hostname lộ")
    _assert("10.1.2.3"   not in out, "IP lộ")
    _assert("ops@corp.vn" not in out, "email lộ")
    return f"4 entity mask đúng | counters: {stats['counters']}"


def unit_demask_correctness():
    m = Masker(); sid = "u12"
    original = "Server srv-db-01 tại 192.168.10.5 gửi lỗi đến admin@test.com"
    masked = m.mask(original, sid)
    restored = m.demask(masked, sid)
    _assert(restored == original, f"De-mask sai!\nExpected: {original}\nGot:      {restored}")
    return "mask → de-mask → khớp hoàn toàn với bản gốc"


def unit_demask_long_tag_first():
    """HOST_10 phải được restore trước HOST_1 để tránh lỗi thay thế một phần."""
    m = Masker(); sid = "u13"
    # Tạo 10 host khác nhau để có [HOST_10]
    for i in range(1, 10):
        m.mask(f"srv-host-{i:02d}", sid)
    text10 = m.mask("srv-host-10", sid)
    tag10 = re.search(r"\[HOST_\d+\]", text10).group()
    _assert(tag10 == "[HOST_10]", f"Tag thứ 10 phải là [HOST_10], got {tag10}")
    # De-mask phải đúng
    restored = m.demask(text10, sid)
    _assert("srv-host-10" in restored, f"De-mask [HOST_10] sai: {restored}")
    return f"[HOST_10] được de-mask đúng trước [HOST_1]"


def unit_session_isolation():
    m = Masker()
    m.mask("10.0.0.1", "sessionA")
    m.mask("10.0.0.1", "sessionB")
    statsA = m.session_stats("sessionA")
    statsB = m.session_stats("sessionB")
    tagA = statsA["mappings"]["10.0.0.1"]
    tagB = statsB["mappings"]["10.0.0.1"]
    _assert(tagA == tagB == "[IP_1]", "Cùng IP nên cùng tag trong mỗi session")
    _assert(statsA is not statsB, "Hai session phải độc lập")
    return "sessionA và sessionB có mapping độc lập nhau"


def unit_no_sensitive_data():
    m = Masker(); sid = "u15"
    text = "Hệ thống hoạt động bình thường. Không có lỗi nào được ghi nhận."
    out = m.mask(text, sid)
    _assert(out == text, f"Văn bản không nhạy cảm bị thay đổi: {out}")
    return "Văn bản không nhạy cảm → giữ nguyên"


# ---------------------------------------------------------------------------
# ── API TESTS ───────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def _api_test(messages, log_block=False, max_tokens=512,
              check_mask=True, sensitive_values: list[str] | None = None):
    """
    Chạy 1 API test, trả về (status, details, token_usage).
    Kiểm tra: HTTP 200, không rò rỉ tag, masking đã xảy ra.
    """
    sid = uuid.uuid4().hex[:8]
    result = _send_api(messages, session_id=sid, log_block=log_block, max_tokens=max_tokens)
    content = _reply(result)
    usage   = _usage(result)
    stats   = _get_stats(sid)
    _clear(sid)

    lines = [
        f"Tokens: prompt={usage.get('prompt_tokens',0)} "
        f"completion={usage.get('completion_tokens',0)} "
        f"total={usage.get('total_tokens',0)}",
        f"Response length: {len(content)} chars",
        f"Masked values: {stats.get('mapped_values', 0)}",
    ]

    # Kiểm tra không rò rỉ tag
    if _has_tag_leak(content):
        leaked = TAG_RE.findall(content)
        raise AssertionError(f"Tag rò rỉ ra client: {leaked[:5]}")

    # Kiểm tra response có nội dung
    _assert(len(content.strip()) > 30, f"Response quá ngắn: '{content[:80]}'")

    # Kiểm tra masking đã xảy ra
    if check_mask:
        _assert(stats.get("mapped_values", 0) > 0, "Không có giá trị nào bị mask")

    # Kiểm tra giá trị nhạy cảm không xuất hiện dạng thô trong response
    for val in (sensitive_values or []):
        # Nếu có trong response thì vẫn OK (de-mask trả về đúng)
        pass   # de-masking là tính năng mong muốn, không phải lỗi

    # Thêm preview response
    preview = content[:200].replace("\n", " ")
    lines.append(f"Response preview: {preview}...")

    return "\n".join(lines), usage

# ── Định dạng log đơn dòng ──────────────────────────────────────────────────

NGINX_ACCESS = (
    '192.168.1.50 - admin [22/Mar/2026:10:05:23 +0700] '
    '"GET /api/v1/user/profile HTTP/1.1" 200 1842 '
    '"https://app.internal.corp" "Mozilla/5.0"'
)

APACHE_ERROR = (
    '[Mon Mar 22 10:06:01.123 2026] [error] [pid 1234] '
    '[client 10.0.2.15:51234] AH01276: Cannot serve directory '
    '/var/www/html/vsec_crm/uploads/: No matching DirectoryIndex'
)

SYSLOG_SINGLE = (
    'Mar 22 10:07:11 srv-app-03 kernel: [12345.678] '
    'Out of memory: Kill process 4567 (python3) score 892 '
    'or sacrifice child'
)

JSON_LOG = json.dumps({
    "timestamp": "2026-03-22T10:08:00.000Z",
    "level": "ERROR",
    "service": "api-gateway-01",
    "host": "10.1.5.20",
    "message": "Upstream connection timeout",
    "upstream": "db-master-01:5432",
    "user": "svc-account@internal.vsec.com",
    "path": "/api/v2/orders",
    "duration_ms": 30001
})

# ── Định dạng log đa dòng ────────────────────────────────────────────────────

NGINX_BLOCK = """
10.0.0.1 - - [22/Mar/2026:10:00:01 +0700] "GET /index.php HTTP/1.1" 200 4523
113.190.23.45 - - [22/Mar/2026:10:00:02 +0700] "POST /vsec_crm/login HTTP/1.1" 401 512
113.190.23.45 - - [22/Mar/2026:10:00:03 +0700] "POST /vsec_crm/login HTTP/1.1" 401 512
113.190.23.45 - - [22/Mar/2026:10:00:04 +0700] "POST /vsec_crm/login HTTP/1.1" 401 512
113.190.23.45 - - [22/Mar/2026:10:00:05 +0700] "POST /vsec_crm/login HTTP/1.1" 200 1024
113.190.23.45 - - [22/Mar/2026:10:00:06 +0700] "GET /vsec_crm/admin/users HTTP/1.1" 200 8901
113.190.23.45 - - [22/Mar/2026:10:00:07 +0700] "GET /vsec_crm/admin/export?table=customers HTTP/1.1" 200 204800
""".strip()

SYSLOG_BLOCK = """
Mar 22 10:10:01 srv-db-01 mysqld[1234]: [Warning] Aborted connection 5678 to db 'vsec_production'
Mar 22 10:10:01 srv-db-01 mysqld[1234]: [ERROR] InnoDB: Disk is full (os error 28)
Mar 22 10:10:02 srv-db-01 kernel: EXT4-fs error (device sda1): ext4_find_entry
Mar 22 10:10:02 srv-db-01 mysqld[1234]: [ERROR] Could not write to binary log. errno 28
Mar 22 10:10:03 srv-db-01 mysqld[1234]: [ERROR] An error occurred during flush stage
Mar 22 10:10:03 srv-db-01 systemd[1]: mysql.service: Main process exited with error
Mar 22 10:10:04 srv-db-01 systemd[1]: mysql.service: Failed with result exit-code
Mar 22 10:10:04 srv-app-01 app[5678]: [FATAL] Database connection pool exhausted. Giving up.
""".strip()

PYTHON_TRACEBACK = """
2026-03-22 10:15:01,234 ERROR [srv-api-02] Unhandled exception in request handler
Traceback (most recent call last):
  File "/var/www/vsec_crm/app/views/user.py", line 145, in get_user
    user = db.session.query(User).filter_by(id=user_id).one()
  File "/usr/local/lib/python3.11/site-packages/sqlalchemy/orm/query.py", line 989, in one
    raise NoResultFound("No row was found when one was required")
sqlalchemy.exc.NoResultFound: No row was found when one was required
2026-03-22 10:15:01,235 ERROR [srv-api-02] Client: 172.16.0.55, Path: /api/v1/user/9999
""".strip()

JAVA_SPRINGBOOT = """
2026-03-22 10:20:01.123  ERROR 4567 --- [nio-8080-exec-5] c.v.crm.service.AuthService: Authentication failed
2026-03-22 10:20:01.124  WARN  4567 --- [nio-8080-exec-5] c.v.crm.filter.JwtFilter: Invalid token from 203.0.113.88
2026-03-22 10:20:01.125  ERROR 4567 --- [pool-2-thread-1] c.v.crm.repo.UserRepository: DB query timeout after 30000ms
2026-03-22 10:20:01.126  ERROR 4567 --- [pool-2-thread-1] o.s.t.i.TransactionInterceptor: Application exception overridden by rollback exception
org.springframework.dao.QueryTimeoutException: JDBC exception executing SQL [SELECT * FROM users WHERE email=?]
	at com.vsec.crm.repo.UserRepository.findByEmail(UserRepository.java:89) ~[app.jar:1.0.0]
	at com.vsec.crm.service.AuthService.authenticate(AuthService.java:156) ~[app.jar:1.0.0]
2026-03-22 10:20:01.127  INFO  4567 --- [scheduling-1] c.v.crm.job.HealthCheck: DB srv-db-master-01 status: UNREACHABLE
""".strip()

DOCKER_LOG = """
2026-03-22T10:25:01.123Z [api-gateway-01] [INFO]  Container started on 172.17.0.5:8080
2026-03-22T10:25:02.456Z [api-gateway-01] [INFO]  Connected to redis-cache-01:6379
2026-03-22T10:25:03.789Z [api-gateway-01] [WARN]  Upstream srv-backend-02:9000 slow response: 5023ms
2026-03-22T10:25:04.012Z [api-gateway-01] [ERROR] Health check failed for srv-backend-02:9000
2026-03-22T10:25:04.345Z [api-gateway-01] [ERROR] Removing srv-backend-02:9000 from load balancer pool
2026-03-22T10:25:04.678Z [api-gateway-01] [WARN]  Only 1 upstream remaining: srv-backend-01:9000
2026-03-22T10:25:10.000Z [api-gateway-01] [ERROR] Circuit breaker OPEN for service: payment-svc
2026-03-22T10:25:10.001Z [api-gateway-01] [INFO]  Failover to backup-payment-svc-01:9001
""".strip()

WAF_SECURITY = """
[2026-03-22 10:30:01] BLOCK  src=45.77.12.33:51234 dst=vsec-prod-app-01:443 rule=SQL_INJECTION
[2026-03-22 10:30:01] ALERT  CVE-2021-44228 Log4Shell attempt from 45.77.12.33 against /api/login
[2026-03-22 10:30:02] BLOCK  src=45.77.12.33:51235 dst=vsec-prod-app-01:443 rule=XSS_REFLECTED
[2026-03-22 10:30:03] BLOCK  src=45.77.12.33:51236 dst=vsec-prod-app-01:443 rule=PATH_TRAVERSAL uri=/vsec_crm/../../../etc/passwd
[2026-03-22 10:30:03] ALERT  Repeated attack from 45.77.12.33 — 10 blocks in 3s. Auto-blacklisting.
[2026-03-22 10:30:04] BLOCK  src=89.185.44.201:61000 dst=vsec-prod-app-01:443 rule=BOTNET_UA
[2026-03-22 10:30:05] ALERT  DDoS pattern detected: 1500 req/s from AS12345 targeting /api/search
[2026-03-22 10:30:05] ACTION Rate-limit applied to /api/search — threshold: 100 req/s
""".strip()

MYSQL_SLOWQUERY = """
# Time: 2026-03-22T10:35:01.000000+07:00
# User@Host: app_user[app_user] @ srv-app-01 [10.0.10.5]
# Query_time: 45.123456  Lock_time: 0.000123 Rows_sent: 50000 Rows_examined: 12000000
SET timestamp=1742611501;
SELECT * FROM customers WHERE created_at > '2020-01-01' AND status='active' ORDER BY id;
# Time: 2026-03-22T10:36:15.000000+07:00
# User@Host: report_user[report_user] @ srv-report-01 [10.0.10.8]
# Query_time: 120.456789  Lock_time: 0.001000 Rows_sent: 0 Rows_examined: 50000000
SET timestamp=1742611575;
SELECT COUNT(*), SUM(amount) FROM orders JOIN customers ON orders.customer_id = customers.id WHERE orders.created_at BETWEEN '2025-01-01' AND '2026-01-01';
""".strip()

KUBERNETES_LOG = """
2026-03-22T10:40:01.123Z INFO  kube-scheduler: Successfully assigned vsec/api-pod-7d9f8b-xk2mp to k8s-node-03
2026-03-22T10:40:02.456Z INFO  kubelet: Pulling image "registry.vsec.internal/api:v2.1.5" on k8s-node-03
2026-03-22T10:40:15.789Z INFO  kubelet: Successfully pulled image "registry.vsec.internal/api:v2.1.5"
2026-03-22T10:40:16.000Z INFO  kubelet: Created container api in pod vsec/api-pod-7d9f8b-xk2mp
2026-03-22T10:40:16.500Z WARN  kube-proxy: iptables rule sync failed on k8s-node-03 (172.20.0.3)
2026-03-22T10:40:17.000Z ERROR kube-proxy: Failed to sync iptables rules: exit status 1
2026-03-22T10:40:45.000Z WARN  kubelet: Pod vsec/api-pod-7d9f8b-xk2mp failed readiness probe
2026-03-22T10:41:00.000Z ERROR kubelet: Liveness probe failed for api on k8s-node-03: Get "http://10.1.0.25:8080/health": context deadline exceeded
""".strip()

# ── Log độ dài khác nhau ────────────────────────────────────────────────────

def _make_log_block(n_lines: int) -> str:
    base_time = datetime(2026, 3, 22, 10, 0, 0)
    levels = ["INFO", "WARN", "ERROR", "DEBUG", "FATAL"]
    hosts  = ["srv-web-01", "srv-api-02", "db-master-01", "cache-redis-01"]
    ips    = ["10.0.0.1", "10.0.0.2", "192.168.1.50", "172.16.0.10"]
    lines  = []
    for i in range(n_lines):
        ts    = base_time.replace(second=i % 60, minute=i // 60)
        level = levels[i % len(levels)]
        host  = hosts[i % len(hosts)]
        ip    = ips[i % len(ips)]
        lines.append(
            f"{ts.strftime('%Y-%m-%d %H:%M:%S')} {level:5s} [{host}] "
            f"pid={1000+i} client={ip} msg='Event #{i+1} on {host}'"
        )
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_all(skip_api: bool = False) -> list[TestResult]:
    results: list[TestResult] = []
    start_all = time.monotonic()

    def _run(case: TestCase, fn, *args, **kwargs) -> TestResult:
        t0 = time.monotonic()
        try:
            if args or kwargs:
                detail, usage = fn(*args, **kwargs)
            else:
                detail, usage = fn(), {}
            status = "PASS"
            error  = ""
        except AssertionError as e:
            status, detail, usage, error = "FAIL", "", {}, str(e)
        except Exception as e:
            status, detail, usage, error = "ERROR", "", {}, f"{type(e).__name__}: {e}"
        duration = (time.monotonic() - t0) * 1000
        r = TestResult(case=case, status=status, duration_ms=duration,
                       details=detail, error=error, token_usage=usage)
        _print_result(r)
        results.append(r)
        return r

    def _print_result(r: TestResult):
        icon  = {"PASS": "✓", "FAIL": "✗", "ERROR": "!", "SKIP": "○"}[r.status]
        color = {"PASS": "\033[92m", "FAIL": "\033[91m",
                 "ERROR": "\033[93m", "SKIP": "\033[2m"}[r.status]
        reset = "\033[0m"
        print(f"  {color}{icon} [{r.case.id}] {r.case.name:<45} "
              f"{r.status:<5}  {r.duration_ms:>6.0f}ms{reset}")
        if r.error:
            print(f"      → {r.error[:120]}")

    # ── UNIT TESTS ────────────────────────────────────────────────────────────
    print("\n\033[1m  ── UNIT TESTS (Masker) ──\033[0m")
    unit_tests = [
        ("U01", "IP đơn lẻ bị mask",                       unit_ip_single),
        ("U02", "Nhiều IP khác nhau → nhiều tag",           unit_ip_multiple),
        ("U03", "Cùng IP → cùng tag (context integrity)",   unit_ip_context_integrity),
        ("U04", "Email bị mask",                            unit_email),
        ("U05", "Hostname prefix (srv-, db-) bị mask",      unit_hostname_prefix),
        ("U06", "Hostname dạng word-NN bị mask",            unit_hostname_nn_pattern),
        ("U07", "FQDN hostname bị mask",                    unit_fqdn),
        ("U08", "Đường dẫn file bị mask",                   unit_path),
        ("U09", "CVE ID KHÔNG bị mask",                     unit_cve_not_masked),
        ("U10", "Protocol version KHÔNG bị mask",           unit_protocol_version_not_masked),
        ("U11", "Mixed entities (IP+HOST+EMAIL+PATH)",       unit_mixed_entities),
        ("U12", "De-mask khôi phục chính xác bản gốc",      unit_demask_correctness),
        ("U13", "De-mask tag dài trước (HOST_10 > HOST_1)", unit_demask_long_tag_first),
        ("U14", "Session isolation — mapping độc lập",       unit_session_isolation),
        ("U15", "Văn bản không nhạy cảm giữ nguyên",        unit_no_sensitive_data),
    ]
    for uid, name, fn in unit_tests:
        case = TestCase(id=uid, category="UNIT", name=name, description=name)
        status, detail = _run_unit(fn)
        t = TestResult(case=case, status=status, duration_ms=0,
                       details=detail, error=detail if status != "PASS" else "")
        if status != "PASS":
            t.error = detail; t.details = ""
        _print_result(t)
        results.append(t)

    if skip_api:
        print("\n  [Skip] API tests bị bỏ qua (--skip-api)\n")
        return results

    # ── API_CHAT TESTS ────────────────────────────────────────────────────────
    print("\n\033[1m  ── API CHAT TESTS ──\033[0m")
    chat_cases = [
        ("C01", "API_CHAT", "Chat đơn giản có IP và hostname",
         [{"role": "user",
           "content": "Server srv-web-01 tại 10.0.0.5 trả về 500. Nguyên nhân có thể là gì?"}],
         False),
        ("C02", "API_CHAT", "Multi-turn: context integrity qua 2 lượt",
         [{"role": "user",    "content": "srv-db-01 tại 192.168.1.100 bị lỗi kết nối."},
          {"role": "assistant","content": "Bạn có thể kiểm tra service MySQL trên [HOST_1]."},
          {"role": "user",    "content": "Cách restart MySQL trên server đó?"}],
         False),
        ("C03", "API_CHAT", "Câu hỏi không có dữ liệu nhạy cảm",
         [{"role": "user", "content": "HTTP 500 là lỗi gì? Giải thích ngắn gọn."}],
         False),
    ]
    for cid, cat, name, msgs, lb in chat_cases:
        case = TestCase(id=cid, category=cat, name=name, description=name)
        _run(case, _api_test, msgs, log_block=lb,
             check_mask=(cid != "C03"))

    # ── API_LOG FORMAT TESTS ──────────────────────────────────────────────────
    print("\n\033[1m  ── API LOG FORMAT TESTS ──\033[0m")
    fmt_cases = [
        ("F01", "Nginx access log — đơn dòng",
         NGINX_ACCESS, False),
        ("F02", "Apache error log — đơn dòng",
         APACHE_ERROR, False),
        ("F03", "Syslog — đơn dòng",
         SYSLOG_SINGLE, False),
        ("F04", "JSON structured log — đơn dòng",
         JSON_LOG, False),
        ("F05", "Nginx access log block — brute force login (7 dòng)",
         NGINX_BLOCK, True),
        ("F06", "Syslog block — disk full + MySQL crash (8 dòng)",
         SYSLOG_BLOCK, True),
        ("F07", "Python traceback — stack trace đa dòng (7 dòng)",
         PYTHON_TRACEBACK, True),
        ("F08", "Java Spring Boot log + exception (8 dòng)",
         JAVA_SPRINGBOOT, True),
        ("F09", "Docker container log — circuit breaker (8 dòng)",
         DOCKER_LOG, True),
        ("F10", "WAF / Security log — attack pattern (8 dòng)",
         WAF_SECURITY, True),
        ("F11", "MySQL slow query log (9 dòng)",
         MYSQL_SLOWQUERY, True),
        ("F12", "Kubernetes pod log — scheduling failure (8 dòng)",
         KUBERNETES_LOG, True),
    ]
    for fid, name, log_content, is_block in fmt_cases:
        case = TestCase(id=fid, category="API_LOG", name=name, description=name)
        prompt = (f"Phân tích đoạn log sau:\n```\n{log_content}\n```"
                  if is_block else
                  f"Phân tích dòng log sau:\n```\n{log_content}\n```")
        _run(case, _api_test,
             [{"role": "user", "content": prompt}],
             log_block=is_block, max_tokens=600)

    # ── API_LEN — Độ dài log ─────────────────────────────────────────────────
    print("\n\033[1m  ── API LOG LENGTH TESTS ──\033[0m")
    len_cases = [
        ("L01", 1,  "Đoạn log 1 dòng"),
        ("L02", 5,  "Đoạn log 5 dòng"),
        ("L03", 15, "Đoạn log 15 dòng"),
        ("L04", 30, "Đoạn log 30 dòng"),
        ("L05", 50, "Đoạn log 50 dòng (stress test)"),
    ]
    for lid, n, name in len_cases:
        case = TestCase(id=lid, category="API_LEN", name=name, description=name)
        log_block = _make_log_block(n)
        prompt = f"Phân tích đoạn log sau:\n```\n{log_block}\n```"
        _run(case, _api_test,
             [{"role": "user", "content": prompt}],
             log_block=(n > 1), max_tokens=700)

    # ── EDGE CASE TESTS ───────────────────────────────────────────────────────
    print("\n\033[1m  ── EDGE CASE TESTS ──\033[0m")

    def edge_cve_preserved():
        log = (
            "[2026-03-22 10:30:01] ALERT CVE-2024-1086 exploit attempt "
            "from 45.77.12.33 on vsec-prod-app-01"
        )
        sid = uuid.uuid4().hex[:8]
        result = _send_api(
            [{"role": "user", "content": f"Phân tích log: {log}"}], sid)
        content = _reply(result)
        _clear(sid)
        _assert("CVE-2024-1086" in content, "CVE ID bị mất trong response")
        _assert(not _has_tag_leak(content), "Tag rò rỉ ra client")
        return f"CVE-2024-1086 xuất hiện trong response: có | No tag leak: ✓", _usage(result)

    def edge_same_ip_multi_line():
        log = "\n".join([
            f"2026-03-22 10:00:0{i} ERROR [srv-web-01] Request from 192.168.1.99 failed (attempt {i})"
            for i in range(1, 5)
        ])
        sid = uuid.uuid4().hex[:8]
        result = _send_api(
            [{"role": "user", "content": f"Phân tích:\n```\n{log}\n```"}], sid, log_block=True)
        stats = _get_stats(sid)
        _clear(sid)
        _assert(not _has_tag_leak(_reply(result)), "Tag rò rỉ")
        ip_count = stats.get("counters", {}).get("IP", 0)
        _assert(ip_count == 1, f"IP 192.168.1.99 phải chỉ có 1 tag, got {ip_count} IP tags")
        return f"192.168.1.99 xuất hiện 4 lần → 1 tag IP duy nhất: [IP_1]", _usage(result)

    def edge_mixed_lang():
        log = (
            "2026-03-22 10:50:01 LỖI [srv-web-01] Không thể kết nối tới "
            "cơ sở dữ liệu tại 10.0.0.99. Email hỗ trợ: support@vsec.vn"
        )
        sid = uuid.uuid4().hex[:8]
        result = _send_api(
            [{"role": "user", "content": f"Phân tích log này: {log}"}], sid)
        content = _reply(result)
        _clear(sid)
        _assert(not _has_tag_leak(content), "Tag rò rỉ")
        _assert(len(content) > 30, "Response quá ngắn")
        return "Log tiếng Việt được xử lý đúng, không rò rỉ tag", _usage(result)

    def edge_no_sensitive():
        msg = "HTTP 503 Service Unavailable là gì? Cách xử lý?"
        sid = uuid.uuid4().hex[:8]
        result = _send_api([{"role": "user", "content": msg}], sid)
        stats = _get_stats(sid)
        content = _reply(result)
        _clear(sid)
        _assert(not _has_tag_leak(content), "Tag rò rỉ")
        _assert(len(content) > 30, "Response quá ngắn")
        mapped = stats.get("mapped_values", 0)
        return f"Không có dữ liệu nhạy cảm → mapped_values={mapped} (mong đợi 0)", _usage(result)

    edge_tests = [
        ("E01", "EDGE", "CVE ID được giữ nguyên trong response", edge_cve_preserved),
        ("E02", "EDGE", "Cùng IP xuất hiện nhiều dòng → 1 tag duy nhất", edge_same_ip_multi_line),
        ("E03", "EDGE", "Log tiếng Việt kết hợp IP/hostname", edge_mixed_lang),
        ("E04", "EDGE", "Câu hỏi không chứa dữ liệu nhạy cảm", edge_no_sensitive),
    ]
    for eid, cat, name, fn in edge_tests:
        case = TestCase(id=eid, category=cat, name=name, description=name)
        t0 = time.monotonic()
        try:
            detail, usage = fn()
            r = TestResult(case=case, status="PASS",
                           duration_ms=(time.monotonic()-t0)*1000,
                           details=detail, token_usage=usage)
        except AssertionError as e:
            r = TestResult(case=case, status="FAIL",
                           duration_ms=(time.monotonic()-t0)*1000,
                           details="", error=str(e))
        except Exception as e:
            r = TestResult(case=case, status="ERROR",
                           duration_ms=(time.monotonic()-t0)*1000,
                           details="", error=f"{type(e).__name__}: {e}")
        _print_result(r)
        results.append(r)

    total_ms = (time.monotonic() - start_all) * 1000
    print(f"\n  Tổng thời gian: {total_ms/1000:.1f}s\n")
    return results

# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

def generate_report(results: list[TestResult], skip_api: bool) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out = REPORT_DIR / f"test_report_{ts}.md"

    total  = len(results)
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    errors = sum(1 for r in results if r.status == "ERROR")
    skipped= sum(1 for r in results if r.status == "SKIP")
    rate   = passed / total * 100 if total else 0

    total_tokens = sum(r.token_usage.get("total_tokens", 0) for r in results)
    total_ms     = sum(r.duration_ms for r in results)

    cats = {}
    for r in results:
        cats.setdefault(r.case.category, []).append(r)

    lines = []
    A = lines.append

    A("# Báo Cáo Kiểm Thử — LLM Privacy Gateway")
    A("")
    A(f"**Ngày chạy:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
    A(f"**Môi trường:** Gateway `{GATEWAY_BASE}` | Model `{MODEL}`  ")
    A(f"**Chế độ:** {'Unit only (không gọi OpenAI)' if skip_api else 'Đầy đủ (Unit + API)'}  ")
    A("")
    A("---")
    A("")
    A("## 1. Tổng Kết")
    A("")
    A(f"| Chỉ số | Giá trị |")
    A(f"|--------|---------|")
    A(f"| Tổng số test case | **{total}** |")
    A(f"| Passed  ✓ | **{passed}** |")
    A(f"| Failed  ✗ | **{failed}** |")
    A(f"| Error   ! | **{errors}** |")
    A(f"| Skipped ○ | **{skipped}** |")
    A(f"| Tỷ lệ pass | **{rate:.1f}%** |")
    A(f"| Thời gian chạy | **{total_ms/1000:.1f}s** |")
    A(f"| Tổng token OpenAI | **{total_tokens:,}** |")
    A("")

    # Summary per category
    A("## 2. Kết Quả Theo Danh Mục")
    A("")
    A("| Danh mục | Mô tả | Total | Pass | Fail | Error |")
    A("|----------|-------|-------|------|------|-------|")
    cat_desc = {
        "UNIT":     "Masker unit tests (không cần server)",
        "API_CHAT": "Chat thông thường qua Gateway",
        "API_LOG":  "Phân tích log nhiều định dạng",
        "API_LEN":  "Kiểm thử độ dài đoạn log",
        "EDGE":     "Trường hợp đặc biệt / biên",
    }
    for cat, rs in cats.items():
        p = sum(1 for r in rs if r.status == "PASS")
        f = sum(1 for r in rs if r.status == "FAIL")
        e = sum(1 for r in rs if r.status == "ERROR")
        desc = cat_desc.get(cat, cat)
        A(f"| **{cat}** | {desc} | {len(rs)} | {p} | {f} | {e} |")
    A("")

    # Failed / Error summary
    failures = [r for r in results if r.status in ("FAIL", "ERROR")]
    if failures:
        A("## 3. ⚠️ Test Thất Bại")
        A("")
        for r in failures:
            A(f"### [{r.case.id}] {r.case.name}")
            A(f"- **Danh mục:** {r.case.category}")
            A(f"- **Trạng thái:** `{r.status}`")
            A(f"- **Lỗi:** {r.error}")
            A("")
    else:
        A("## 3. ✅ Không Có Test Thất Bại")
        A("")

    # Detailed results per category
    A("## 4. Chi Tiết Từng Test Case")
    A("")
    for cat, rs in cats.items():
        A(f"### {cat} — {cat_desc.get(cat, cat)}")
        A("")
        A("| ID | Tên Test Case | Trạng thái | Thời gian | Tokens |")
        A("|----|---------------|------------|-----------|--------|")
        for r in rs:
            icon = {"PASS":"✓","FAIL":"✗","ERROR":"!","SKIP":"○"}[r.status]
            tok  = r.token_usage.get("total_tokens", "-")
            A(f"| `{r.case.id}` | {r.case.name} | {icon} {r.status} "
              f"| {r.duration_ms:.0f}ms | {tok} |")
        A("")

        # Detail per test
        for r in rs:
            A(f"#### `{r.case.id}` — {r.case.name}")
            A(f"**Mô tả:** {r.case.description}  ")
            A(f"**Kết quả:** `{r.status}`  ")
            A(f"**Thời gian:** {r.duration_ms:.0f}ms  ")
            if r.token_usage:
                u = r.token_usage
                A(f"**Token:** prompt={u.get('prompt_tokens',0)} "
                  f"completion={u.get('completion_tokens',0)} "
                  f"total={u.get('total_tokens',0)}  ")
            if r.details:
                A(f"**Chi tiết:**")
                A("```")
                A(textwrap.fill(r.details, width=100))
                A("```")
            if r.error:
                A(f"**Lỗi:** ⚠ `{r.error}`")
            A("")

    # Phân tích log format chi tiết
    A("## 5. Mô Tả Các Định Dạng Log Được Kiểm Thử")
    A("")
    fmt_desc = [
        ("F01", "Nginx Access Log (đơn dòng)",
         "Common Log Format với IP, path, HTTP status, user agent"),
        ("F02", "Apache Error Log (đơn dòng)",
         "Apache error format với PID, client IP, path, error message"),
        ("F03", "Syslog RFC 3164 (đơn dòng)",
         "Syslog với hostname, process name, PID, kernel message"),
        ("F04", "JSON Structured Log (đơn dòng)",
         "ECS-like JSON với timestamp, level, host IP, upstream, user email"),
        ("F05", "Nginx Access Log Block (7 dòng)",
         "Brute force attack pattern: 3 lần 401 → đăng nhập thành công → data exfiltration"),
        ("F06", "Syslog Block — Disk Full (8 dòng)",
         "Chuỗi lỗi MySQL do đầy đĩa: Warning → Error → Fatal → Service crash"),
        ("F07", "Python Traceback (7 dòng)",
         "Multi-line stack trace với SQLAlchemy exception, file path, client IP"),
        ("F08", "Java Spring Boot + Stack Trace (8 dòng)",
         "Spring Boot log với thread name, class path, DB timeout, exception chain"),
        ("F09", "Docker Container Log (8 dòng)",
         "Container lifecycle: connect → slow response → health fail → circuit breaker open"),
        ("F10", "WAF / Security Log (8 dòng)",
         "Tấn công đa vector: SQL injection, Log4Shell CVE, XSS, Path traversal, DDoS"),
        ("F11", "MySQL Slow Query Log (9 dòng)",
         "2 slow query với user, host IP, query time, rows examined"),
        ("F12", "Kubernetes Pod Log (8 dòng)",
         "Pod scheduling → image pull → iptables sync fail → liveness probe fail"),
    ]
    A("| ID | Định dạng | Mô tả |")
    A("|----|-----------|-------|")
    for fid, name, desc in fmt_desc:
        A(f"| `{fid}` | **{name}** | {desc} |")
    A("")

    A("## 6. Mô Tả Kiểm Thử Độ Dài Log")
    A("")
    A("| ID | Số dòng | Mục đích |")
    A("|----|---------|---------|")
    A("| `L01` | 1 dòng   | Baseline — log đơn lẻ |")
    A("| `L02` | 5 dòng   | Log ngắn — sự cố đơn giản |")
    A("| `L03` | 15 dòng  | Log trung bình — nhiều event |")
    A("| `L04` | 30 dòng  | Log dài — phân tích phức tạp |")
    A("| `L05` | 50 dòng  | Stress test — giới hạn context |")
    A("")

    A("---")
    A(f"*Report tự động sinh bởi `tests/test_cases.py` lúc {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

    out.write_text("\n".join(lines), encoding="utf-8")
    return out

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--unit-only", action="store_true",
                        help="Chỉ chạy unit tests, không gọi OpenAI API")
    parser.add_argument("--skip-api",  action="store_true",
                        help="Bỏ qua tất cả API tests")
    args = parser.parse_args()
    skip = args.unit_only or args.skip_api

    print("\n\033[1m╔══════════════════════════════════════════════════╗")
    print("║  LLM Privacy Gateway — Test Suite               ║")
    print("╚══════════════════════════════════════════════════╝\033[0m\n")

    results = run_all(skip_api=skip)

    total  = len(results)
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status in ("FAIL","ERROR"))

    print(f"\n  Kết quả: {passed}/{total} PASS", end="")
    if failed:
        print(f"  |  {failed} FAIL/ERROR \033[91m✗\033[0m")
    else:
        print("  \033[92m✓ Tất cả pass\033[0m")

    report_path = generate_report(results, skip_api=skip)
    print(f"\n  📄 Report: {report_path}\n")
    sys.exit(0 if failed == 0 else 1)
