# LLM Privacy Gateway — v1.4.0

Hệ thống trung gian (proxy) bảo vệ dữ liệu nhạy cảm khi giao tiếp với OpenAI API, tích hợp Auth & RBAC, Knowledge Base nội bộ, OCR tài liệu ảnh, và báo cáo thống kê sử dụng.

Gateway tự động **Mask** dữ liệu trước khi gửi lên LLM và **De-mask** kết quả trả về cho client — hoàn toàn trong suốt với người dùng cuối.

**Tính năng chính:**
- **Mask/De-mask tự động:** IP, Hostname, Email, File Path — Context Integrity xuyên suốt phiên hội thoại
- **Auth & RBAC:** JWT, bcrypt, quản lý người dùng, phân quyền theo role
- **Admin Dashboard:** tạo tài khoản, reset mật khẩu, khóa tài khoản, audit log
- **Knowledge Base (RAG):** hỏi đáp trên tài liệu PDF/DOCX/TXT/ảnh với RAG Isolation theo role
- **OCR tự động:** nhận dạng chữ trong file ảnh (PNG/JPG/TIFF/WEBP/BMP) và PDF scan qua OpenAI Vision
- **Usage Analytics:** thống kê tần suất, tokens, latency theo cá nhân và bộ phận
- **Audit Logging:** ghi nhận mọi hành động quản trị theo chuẩn `[Time] [Actor] action [Target]`
- **Logging 4 giai đoạn:** RECV → MASK → OAPI → SEND với full request trace

---

## Mục lục

1. [Kiến trúc tổng quan](#1-kiến-trúc-tổng-quan)
2. [Cấu trúc thư mục](#2-cấu-trúc-thư-mục)
3. [Cài đặt & Cấu hình](#3-cài-đặt--cấu-hình)
4. [Khởi động ứng dụng](#4-khởi-động-ứng-dụng)
5. [Tài khoản Admin mặc định](#5-tài-khoản-admin-mặc-định)
6. [API Reference](#6-api-reference)
7. [Auth & RBAC](#7-auth--rbac)
8. [Knowledge Base (RAG)](#8-knowledge-base-rag)
9. [Luồng Masking chi tiết](#9-luồng-masking-chi-tiết)
10. [Hệ thống Logging & Analytics](#10-hệ-thống-logging--analytics)
11. [Thiết kế bảo mật](#11-thiết-kế-bảo-mật)
12. [Mở rộng hệ thống](#12-mở-rộng-hệ-thống)

---

## 1. Kiến trúc tổng quan

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              LLM Privacy Gateway                             │
│                                                                              │
│  ┌──────────────────┐   HTTP + JWT   ┌──────────────────────────────────┐   │
│  │                  │ ─────────────► │                                  │   │
│  │  Streamlit UI    │  /v1/chat/     │      FastAPI Gateway             │   │
│  │  :8501           │  /v1/rag/chat  │      :8000                       │   │
│  │                  │ ◄───────────── │                                  │   │
│  └──────────────────┘                │  ┌──────────┐  ┌─────────────┐  │   │
│                                      │  │  Masker  │  │  RAG Engine │  │   │
│                                      │  │ (Regex)  │  │ (LangChain) │  │   │
│                                      │  └──────────┘  │ +OCR Vision │  │   │
│                                      │                └──────┬──────┘  │   │
│                                      │                        │         │   │
│                                      │  ┌──────────┐ ┌───────▼──────┐  │   │
│                                      │  │  SQLite  │ │   ChromaDB   │  │   │
│                                      │  │ users.db │ │ (Vector Store│  │   │
│                                      │  └──────────┘ └─────────────┘  │   │
│                                      │                                  │   │
│                                      │  logs/audit/    logs/usage/      │   │
│                                      │  logs/requests/ logs/rag/        │   │
└──────────────────────────────────────┴────────────────┬─────────────────┘   │
                                                        │ HTTPS (masked)
                                                        ▼
                                             ┌──────────────────────┐
                                             │     OpenAI API        │
                                             │  (không thấy data    │
                                             │   thật của bạn)      │
                                             └──────────────────────┘
```

### Luồng xử lý Chat thường

```
Client gửi + JWT  { messages: [...] }
      │
      ▼
 [Auth]   Xác thực JWT → lấy role từ DB (luôn đồng bộ)
      │
      ▼
 [1] RECV     Ghi log request gốc + role + session_id
      │
      ▼
 [2] MASK     Inject Role System Prompt → Mask dữ liệu nhạy cảm
              "10.0.0.5"    →  "[IP_1]"
              "srv-web-01"  →  "[HOST_1]"
              "admin@x.com" →  "[EMAIL_1]"
      │
      ▼
 [3] OAPI     Gửi payload đã ẩn danh lên OpenAI, nhận response
      │
      ▼
 [4] SEND     De-mask response → trả về client → ghi usage log
```

### Luồng xử lý RAG Chat

```
Client + JWT  { query: "phân tích sự cố..." }
      │
      ▼
 [Auth]   JWT → role (dùng để lọc tài liệu theo RAG Isolation)
      │
      ▼
 [R-1] RAG_RECV      Nhận query gốc, ghi log
      │
      ▼
 [R-2] RAG_RETRIEVE  mask(query) → semantic search ChromaDB
                     → lọc chunk theo allowed_roles (RAG Isolation)
      │
      ▼
 [R-3] RAG_MASK_CTX  mask(context chunks) → log trước/sau mask
      │
      ▼
 [R-4] RAG_SEND      Role Prompt + Context → LLM → demask(answer)
                     → ghi usage log
```

---

## 2. Cấu trúc thư mục

```
datamasking/
│
├── app/
│   ├── __init__.py
│   ├── config.py           # 5 vai trò & system prompts
│   ├── masker.py           # Engine Mask/De-mask — regex, session mapping
│   ├── state.py            # Singleton masker (tránh circular import)
│   ├── db.py               # SQLite CRUD — users.db
│   ├── auth.py             # bcrypt hash/verify, JWT create/decode
│   ├── dependencies.py     # FastAPI deps: get_current_user, require_admin
│   ├── auth_router.py      # POST /auth/login, GET /auth/me, change-password
│   ├── admin_router.py     # CRUD users, reset/lock/unlock, audit log API
│   ├── stats_router.py     # GET /admin/stats/* — thống kê sử dụng
│   ├── server.py           # FastAPI app — endpoint chính, proxy OpenAI
│   ├── request_logger.py   # Logging 4 giai đoạn Chat vào JSONL
│   ├── rag.py              # RAG engine + router (upload/search/chat) + OCR pipeline
│   ├── rag_logger.py       # Logging 4 giai đoạn RAG vào JSONL
│   ├── audit_logger.py     # Audit log hành động quản trị vào JSONL
│   └── usage_logger.py     # Usage log mỗi request vào JSONL
│
├── ui/
│   └── app.py              # Streamlit Web UI
│
├── tests/
│   ├── test_full.py        # 58 test cases (8 nhóm), sinh báo cáo Markdown
│   ├── client_test.py      # CLI client tương tác
│   └── test_cases.py       # Test cases v1.2 (legacy)
│
├── logs/
│   ├── requests/           # YYYY-MM-DD.jsonl — Chat 4-stage log
│   ├── audit/              # YYYY-MM-DD.jsonl — Audit log hành động
│   └── usage/              # YYYY-MM-DD.jsonl — Usage analytics log
│
├── chroma_db/              # ChromaDB vector store (tự tạo khi upload)
│   └── registry.json       # Metadata registry tài liệu
│
├── users.db                # SQLite database người dùng
├── .env                    # Biến môi trường (không commit)
├── .env.example            # Mẫu cấu hình
├── requirements.txt
└── README.md
```

### Vai trò từng file chính

| File | Vai trò |
|------|---------|
| `app/config.py` | 5 vai trò (SOC, Marketing, PM, HR, Normal) và system prompt |
| `app/masker.py` | Regex patterns, bảng mapping per-session, mask/demask API |
| `app/db.py` | SQLite CRUD: init_db, create_user, get_user, update_user, list_users |
| `app/auth.py` | bcrypt password hash/verify; JWT create/decode (PyJWT) |
| `app/dependencies.py` | `get_current_user` (JWT → DB sync), `require_admin` (ADMIN_EMAILS) |
| `app/auth_router.py` | `/auth/login`, `/auth/me`, `/auth/change-password` |
| `app/admin_router.py` | CRUD users, reset/lock/unlock, đọc audit log |
| `app/stats_router.py` | 4 endpoint thống kê: summary, users, departments, daily |
| `app/server.py` | Gateway chính: 4-stage pipeline, proxy OpenAI, ghi usage |
| `app/rag.py` | Upload, list, delete tài liệu; OCR ảnh/PDF scan; RAG chat với RBAC isolation |
| `app/audit_logger.py` | Ghi JSONL cho mọi hành động quản trị |
| `app/usage_logger.py` | Ghi JSONL mỗi request: tokens, latency, masked_entities |
| `ui/app.py` | Web UI: Login, Chat, KB, Admin Dashboard (Users + Stats + Audit) |

---

## 3. Cài đặt & Cấu hình

### Yêu cầu

- Python 3.11+
- OpenAI API Key
- **poppler** (cần cho OCR PDF scan):
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y poppler-utils
  # macOS
  brew install poppler
  ```

### Tạo môi trường

```bash
git clone <repo>
cd datamasking

python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
```

### Tạo file `.env`

```bash
cp .env.example .env
```

Mở `.env` và điền đầy đủ:

```env
OPENAI_API_KEY=sk-...your-key-here...
OPENAI_BASE_URL=https://api.openai.com/v1

# Auth & RBAC
JWT_SECRET=change-me-to-a-long-random-secret
JWT_EXPIRE_HOURS=8
ADMIN_EMAILS=admin@vsec.com.vn

# OCR (dùng cho file ảnh và PDF scan)
OCR_MODEL=gpt-4o-mini
```

> **Lưu ý bảo mật:** Đặt `JWT_SECRET` là một chuỗi ngẫu nhiên dài (≥ 32 ký tự).
> Có thể dùng: `python3 -c "import secrets; print(secrets.token_hex(32))"`

---

## 4. Khởi động ứng dụng

```bash
# Terminal 1 — Gateway API
export $(grep -v '^#' .env | xargs)
uvicorn app.server:app --host 0.0.0.0 --port 8000

# Terminal 2 — Web UI
streamlit run ui/app.py --server.port 8501
```

Hoặc chạy nền:

```bash
export $(grep -v '^#' .env | xargs)
nohup uvicorn app.server:app --host 0.0.0.0 --port 8000 > logs/gateway.log 2>&1 &
nohup streamlit run ui/app.py --server.port 8501 --server.address 0.0.0.0 \
      --server.headless true > logs/ui.log 2>&1 &
```

Kiểm tra:

```bash
curl http://localhost:8000/health
# {"status": "ok", "active_sessions": 0}
```

---

## 5. Tài khoản Admin mặc định

Khi khởi động lần đầu, tạo tài khoản admin qua script bootstrap:

```bash
export $(grep -v '^#' .env | xargs)
python3 - <<'EOF'
from app.db import init_db, create_user
from app.auth import hash_password
init_db()
create_user(
    email="admin@vsec.com.vn",
    hashed_password=hash_password("Admin@2026"),
    full_name="System Admin",
    role="SOC",
    created_by="system",
)
print("Admin created.")
EOF
```

**Đăng nhập Web UI:** http://localhost:8501
- Email: `admin@vsec.com.vn`
- Mật khẩu: `Admin@2026`

> **Khuyến nghị:** Đổi mật khẩu ngay sau lần đăng nhập đầu tiên qua tab **Đổi mật khẩu**.

### Admin Dashboard

Sau khi đăng nhập admin, tab **⚙️ Admin** hiển thị 4 sub-tab:

| Sub-tab | Chức năng |
|---------|-----------|
| 👥 Quản lý Users | Tạo, sửa role, khóa/mở khóa, reset mật khẩu tài khoản |
| 📊 Thống kê sử dụng | Báo cáo theo cá nhân, bộ phận, xu hướng theo ngày |
| 📋 Audit Log | Xem lịch sử hành động quản trị theo ngày |
| 🔑 Đổi mật khẩu | Admin tự đổi mật khẩu của mình |

---

## 6. API Reference

> **Tất cả endpoints (trừ `/health` và `/auth/login`) đều yêu cầu JWT Bearer token.**

```bash
# Lấy token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vsec.com.vn","password":"Admin@2026"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Dùng token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/auth/me
```

---

### Auth

#### `POST /auth/login`
```json
// Request
{"email": "user@vsec.com.vn", "password": "P@ssword123"}

// Response
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "user": {"id": 1, "email": "...", "role": "SOC", "full_name": "..."}
}
```

#### `GET /auth/me`
Trả về thông tin người dùng hiện tại (đồng bộ từ DB).

#### `POST /auth/change-password`
```json
{"current_password": "old", "new_password": "New@2026"}
```

---

### Chat

#### `POST /v1/chat/completions`

Role tự động lấy từ JWT — không cần truyền trong body.

```json
{
  "model": "gpt-4o-mini",
  "session_id": "my-session-01",
  "messages": [
    {"role": "user", "content": "Server srv-web-01 tại 10.0.0.5 bị lỗi 500"}
  ],
  "temperature": 0.7,
  "max_tokens": 2048
}
```

| Trường | Bắt buộc | Mô tả |
|--------|----------|-------|
| `model` | Có | Model OpenAI |
| `messages` | Có | Mảng lịch sử hội thoại |
| `session_id` | Không | ID phiên — giữ Context Integrity xuyên lượt |
| `log_block` | Không | `true` để bật phân tích log block 5 bước |

---

### RAG

#### `POST /v1/rag/chat`
```json
{
  "query": "Tóm tắt sự cố Q1-2026",
  "session_id": "rag-01",
  "model": "gpt-4o-mini",
  "top_k": 4
}
```

**Response** thêm trường `_rag_meta`:
```json
{
  "choices": [...],
  "_rag_meta": {
    "request_id": "9C0E4D7C",
    "chunks_used": 3,
    "role": "SOC"
  }
}
```

#### `POST /upload` *(Admin only)*
```bash
curl -X POST http://localhost:8000/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@report.pdf" \
  -F "description=Báo cáo Q1" \
  -F "allowed_roles=SOC,HR"    # hoặc "all"
```

Hỗ trợ: `pdf`, `docx`, `doc`, `txt`, `png`, `jpg`, `jpeg`, `tiff`, `tif`, `webp`, `bmp`

Response:
```json
{
  "doc_id": "abc123",
  "filename": "report.pdf",
  "chunks": 7,
  "ocr": false,
  "ocr_pages": 0
}
```
> Với file ảnh hoặc PDF scan, `ocr: true` và `ocr_pages` là số trang đã OCR.

#### `GET /documents`
Danh sách tài liệu theo quyền của user hiện tại (admin thấy tất cả).

#### `DELETE /documents/{doc_id}` *(Admin only)*

---

### Admin *(Yêu cầu email trong ADMIN_EMAILS)*

#### Users
| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/admin/users` | Danh sách tài khoản |
| `POST` | `/admin/users` | Tạo tài khoản mới |
| `PUT` | `/admin/users/{id}` | Cập nhật role/full_name |
| `POST` | `/admin/users/{id}/reset-password` | Đặt lại mật khẩu |
| `POST` | `/admin/users/{id}/lock` | Khóa tài khoản |
| `POST` | `/admin/users/{id}/unlock` | Mở khóa tài khoản |
| `DELETE` | `/admin/users/{id}` | Xóa tài khoản |

#### Audit Log
| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/admin/audit-logs` | Danh sách file audit log |
| `GET` | `/admin/audit-logs/{date}` | Đọc log ngày cụ thể (`?action=AUTH_LOGIN&actor=email`) |

#### Thống kê sử dụng
| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/admin/stats/summary?days=30` | Tổng quan: requests, tokens, users, success rate |
| `GET` | `/admin/stats/users?days=30` | Thống kê từng cá nhân |
| `GET` | `/admin/stats/departments?days=30` | Thống kê theo bộ phận (role) |
| `GET` | `/admin/stats/daily?days=30` | Xu hướng theo ngày (Chat + RAG) |

---

### Vận hành
| Method | Endpoint | Mô tả |
|--------|----------|-------|
| `GET` | `/health` | Health check |
| `GET` | `/v1/session/{id}/stats` | Bảng masking của session |
| `DELETE` | `/v1/session/{id}` | Xóa session khỏi bộ nhớ |
| `GET` | `/v1/logs` | Danh sách file log |
| `GET` | `/v1/logs/{date}` | Log theo ngày (`?stage=MASK&session=...`) |
| `GET` | `/v1/logs/{date}/{request_id}` | Full 4-stage trace của một request |

---

## 7. Auth & RBAC

### Kiến trúc xác thực

```
Client gửi request
      │
      ▼
Authorization: Bearer <JWT>
      │
      ▼
get_current_user()
  ├── decode_token()       → lấy user_id từ JWT payload
  ├── get_user_by_id(DB)   → kiểm tra is_active, đồng bộ role mới nhất
  └── trả về user dict     → role luôn phản ánh DB hiện tại
      │
      ▼ (nếu endpoint cần admin)
require_admin()
  └── kiểm tra email ∈ ADMIN_EMAILS (env var)
```

### Vai trò người dùng

| Vai trò | System Prompt tự động | Mô tả |
|---------|----------------------|-------|
| `SOC` | Phân tích sự cố bảo mật, xác định root cause | An ninh mạng |
| `Marketing` | Tư duy sáng tạo, định hướng khách hàng | Marketing |
| `PM` | Cấu trúc rõ ràng, quản lý rủi ro | Quản lý dự án |
| `HR` | Tuân thủ chính sách, bảo mật nhân viên | Nhân sự |
| `Normal` | Tìm hiểu quy trình, kiến thức chung | Mặc định |

Role được inject thành System Prompt **tự động từ JWT** — người dùng không thể tự khai báo role trong request body.

### Quản lý người dùng (Admin)

```bash
# Tạo user mới
curl -X POST http://localhost:8000/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"soc1@vsec.com.vn","password":"Pass@2026","full_name":"Nguyen Van A","role":"SOC"}'

# Đổi role
curl -X PUT http://localhost:8000/admin/users/2 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "HR"}'

# Khóa tài khoản
curl -X POST http://localhost:8000/admin/users/2/lock \
  -H "Authorization: Bearer $TOKEN"
```

### Thêm admin

Thêm email vào `ADMIN_EMAILS` trong `.env` (cách nhau dấu phẩy), restart gateway:

```env
ADMIN_EMAILS=admin@vsec.com.vn,admin2@vsec.com.vn
```

---

## 8. Knowledge Base (RAG)

### RAG Isolation theo Role

Mỗi tài liệu upload có trường `allowed_roles` xác định ai được truy cập:

```
allowed_roles = "all"        → mọi người xem được
allowed_roles = "SOC"        → chỉ SOC
allowed_roles = "SOC,HR"     → SOC và HR
```

Tại query time, gateway lấy `top_k × 5` chunk rồi lọc theo role của JWT — đảm bảo người dùng chỉ nhận câu trả lời từ tài liệu mình được phép xem.

### Masking trong RAG

Dữ liệu nhạy cảm được mask ở **hai nơi**:
1. **Query** — trước khi tìm kiếm vector (ChromaDB nhận query đã mask)
2. **Context chunks** — trước khi gửi LLM

Tài liệu lưu trong ChromaDB ở dạng **nguyên bản** — masking chỉ xảy ra tại request-time trong session.

### Định dạng hỗ trợ

| Định dạng | Phương thức xử lý | Chunk size |
|-----------|-------------------|-----------|
| `.pdf` (text) | PyPDFLoader | 800 chars / 100 overlap |
| `.pdf` (scan) | Auto-detect → OCR via OpenAI Vision | 800 chars / 100 overlap |
| `.docx` / `.doc` | Docx2txtLoader | 800 chars / 100 overlap |
| `.txt` | TextLoader (UTF-8) | 800 chars / 100 overlap |
| `.png` / `.jpg` / `.jpeg` | OCR via OpenAI Vision | 800 chars / 100 overlap |
| `.tiff` / `.tif` / `.webp` / `.bmp` | OCR via OpenAI Vision | 800 chars / 100 overlap |

### OCR Pipeline

```
File upload
      │
      ├── Ảnh (.png/.jpg/…)
      │       │
      │       ▼
      │   _ocr_image_to_docs()
      │   └── base64 encode → gpt-4o-mini Vision API → text → Document
      │
      └── PDF
              │
              ▼
          PyPDFLoader → extract text
              │
              ├── avg chars/page ≥ 80 → PDF có text → dùng bình thường
              │
              └── avg chars/page < 80 → PDF scan → _ocr_pdf_to_docs()
                      │
                      ▼
                  pdf2image (poppler) → JPEG bytes per page
                      │
                      ▼
                  _ocr_page() × N trang (gpt-4o-mini Vision)
                      │
                      ▼
                  Ghép text → Document list
```

Response của `/upload` khi dùng OCR:
```json
{
  "doc_id": "abc123",
  "filename": "scan_report.pdf",
  "chunks": 5,
  "ocr": true,
  "ocr_pages": 3
}
```

---

## 9. Luồng Masking chi tiết

### Các loại dữ liệu được phát hiện

| Loại | Tag | Ví dụ | Ngưỡng kích hoạt |
|------|-----|-------|-----------------|
| IPv4 | `[IP_N]` | `10.0.0.5`, `192.168.1.100` | Bất kỳ IPv4 hợp lệ |
| Email | `[EMAIL_N]` | `admin@internal.corp` | Bất kỳ email hợp lệ |
| Hostname | `[HOST_N]` | `srv-web-01`, `db-master` | Server/service name có hyphen |
| File Path | `[PATH_N]` | `/var/log/nginx/error.log` | Đường dẫn ≥ 4 segment |

**Thứ tự ưu tiên:** IP → EMAIL → HOST → PATH

### Không bị mask

- CVE IDs: `CVE-2024-1086`
- Protocol versions: `HTTP-1.1`, `TLS-1.3`, `SSL-3.0`
- Đường dẫn ngắn ≤ 3 segment: `/var/log/app.log`

### Context Integrity

Cùng giá trị trong cùng session luôn map về cùng tag:

```
Turn 1: "server srv-web-01 tại 10.0.0.5"  →  "[HOST_1] tại [IP_1]"
Turn 2: "Port nào mở trên 10.0.0.5?"       →  "Port nào mở trên [IP_1]?"
```

### De-masking an toàn

Tags sắp xếp theo **độ dài giảm dần** trước khi replace, tránh `[HOST_1]0]` thay vì `[HOST_10]`.

---

## 10. Hệ thống Logging & Analytics

### Cấu trúc thư mục log

```
logs/
├── requests/           # Chat 4-stage log (RECV/MASK/OAPI/SEND)
│   └── YYYY-MM-DD.jsonl
├── audit/              # Audit log hành động quản trị
│   └── YYYY-MM-DD.jsonl
└── usage/              # Usage analytics — mỗi request 1 record
    └── YYYY-MM-DD.jsonl
```

### Usage log — mỗi request ghi 1 record

```json
{
  "timestamp": "2026-03-28T10:15:00+00:00",
  "user_id": 1,
  "email": "soc1@vsec.com.vn",
  "role": "SOC",
  "session_id": "abc123",
  "request_id": "3C735A99",
  "type": "CHAT",
  "model": "gpt-4o-mini",
  "prompt_tokens": 312,
  "completion_tokens": 156,
  "total_tokens": 468,
  "latency_ms": 2340,
  "masked_entities": 3,
  "chunks_used": 0,
  "ok": true
}
```

### Audit log — các sự kiện được ghi

| Action | Khi nào |
|--------|---------|
| `AUTH_LOGIN` | Đăng nhập thành công |
| `AUTH_LOGIN_FAIL` | Đăng nhập thất bại |
| `AUTH_CHANGE_PASSWORD` | Đổi mật khẩu |
| `CREATE_USER` | Admin tạo tài khoản |
| `UPDATE_USER` | Admin đổi role/thông tin |
| `RESET_PASSWORD` | Admin reset mật khẩu |
| `LOCK_USER` / `UNLOCK_USER` | Admin khóa/mở khóa |
| `DELETE_USER` | Admin xóa tài khoản |
| `UPLOAD_DOC` | Admin upload tài liệu |
| `DELETE_DOC` | Admin xóa tài liệu |
| `ACCESS_DOC` | User truy vấn RAG (ghi doc_ids accessed) |

### API thống kê sử dụng

```bash
# Tổng quan 30 ngày
curl "http://localhost:8000/admin/stats/summary?days=30" \
  -H "Authorization: Bearer $TOKEN"

# Thống kê từng người dùng
curl "http://localhost:8000/admin/stats/users?days=7" \
  -H "Authorization: Bearer $TOKEN"

# Thống kê theo bộ phận
curl "http://localhost:8000/admin/stats/departments?days=30" \
  -H "Authorization: Bearer $TOKEN"

# Xu hướng theo ngày
curl "http://localhost:8000/admin/stats/daily?days=14" \
  -H "Authorization: Bearer $TOKEN"
```

### Xem log request trực tiếp

```bash
# Realtime
tail -f logs/requests/$(date +%Y-%m-%d).jsonl | python3 -m json.tool

# Lọc theo stage
curl "http://localhost:8000/v1/logs/$(date +%Y-%m-%d)?stage=MASK" \
  -H "Authorization: Bearer $TOKEN"

# Full trace 1 request
curl "http://localhost:8000/v1/logs/2026-03-28/3C735A99" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 11. Thiết kế bảo mật

| Vấn đề | Giải pháp |
|--------|-----------|
| API Key lộ | `.env` không commit; truyền qua env_file khi chạy |
| Password lộ | bcrypt hash (rounds=12); không bao giờ trả `hashed_password` về API |
| Role giả mạo | Role luôn lấy từ DB khi decode JWT — không tin JWT payload |
| Token cũ sau lock | `get_current_user` kiểm tra `is_active` từ DB trên mỗi request |
| Admin privilege | Kiểm tra qua `ADMIN_EMAILS` env var, không phải field trong DB |
| Data rò rỉ sang LLM | Masking trước khi gửi OpenAI — cả query lẫn context RAG |
| Tag rò rỉ về client | De-mask toàn bộ trước khi trả response |
| Context Integrity | Bảng mapping per-session; cùng giá trị → cùng tag |
| RAG data isolation | `allowed_roles` trên mỗi chunk; lọc tại request-time |
| Token bộ nhớ | `DELETE /v1/session/{id}` giải phóng session sau hội thoại |
| Audit trail | Mọi hành động quản trị ghi vào `logs/audit/` JSONL |

---

## 12. Mở rộng hệ thống

### Thêm loại dữ liệu cần mask

Mở `app/masker.py`, thêm vào `PATTERNS`:

```python
(
    "CARD",
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),   # Credit card number
),
(
    "PHONE",
    re.compile(r"\b(?:\+84|0)[3-9]\d{8}\b"),  # Số điện thoại VN
),
```

### Thêm vai trò mới

Mở `app/config.py`, thêm vào dict `ROLES`:

```python
ROLES["Legal"] = (
    "Bạn là chuyên gia tư vấn pháp lý nội bộ, "
    "chuyên hỗ trợ các vấn đề hợp đồng và tuân thủ pháp luật."
)
```

### Chạy test toàn diện

```bash
export $(grep -v '^#' .env | xargs)

# Không gọi OpenAI (nhanh)
python3 tests/test_full.py --skip-llm

# Đầy đủ (tốn token)
python3 tests/test_full.py

# Chỉ 1 nhóm
python3 tests/test_full.py --group AUTH
python3 tests/test_full.py --group ADMIN
python3 tests/test_full.py --group MASKER
python3 tests/test_full.py --group STATS
```

Bộ test gồm **58 test cases**, **8 nhóm**:

| Nhóm | Mã | Số test | Nội dung |
|------|----|---------|----------|
| AUTH | A | 6 | Login, JWT, malformed token |
| ADMIN | B | 10 | CRUD users, lock/unlock, reset pwd |
| PROTECT | C | 8 | Endpoint auth/authz, stats access |
| MASKER | D | 12 | IP/Email/Host/Path mask, session isolation |
| CHAT | E | 6 | Chat proxy, system prompt injection |
| RAG | F | 8 | Upload/list/delete, RAG chat, role filter |
| AUDIT | G | 4 | Audit log write/read |
| STATS | H | 4 | Summary/users/departments/daily stats |

Báo cáo Markdown tự động tạo tại `tests/reports/test_full_YYYY-MM-DD_HH-MM-SS.md`.

### Dùng Redis cho multi-instance

Thay `self._sessions: Dict` trong `Masker` bằng Redis client để hỗ trợ horizontal scaling.

### Thêm Presidio Analyzer

```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_lg
```

Tích hợp vào `masker.py` để phát hiện thêm: tên người, CMND, số điện thoại, địa chỉ.

### Hỗ trợ Streaming

Xử lý `text/event-stream` từ OpenAI và de-mask từng SSE chunk trước khi forward về client.
