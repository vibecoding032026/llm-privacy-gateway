# LLM Privacy Gateway — v1.2

Hệ thống trung gian (proxy) bảo vệ dữ liệu nhạy cảm khi giao tiếp với OpenAI API.
Gateway tự động **Mask** dữ liệu trước khi gửi lên LLM và **De-mask** kết quả trả về cho client — hoàn toàn trong suốt với người dùng cuối.

**Tính năng chính:**
- Mask/De-mask tự động: IP, Hostname, Email, File Path
- Knowledge Base nội bộ (RAG) với ChromaDB — hỏi đáp trên tài liệu PDF/DOCX/TXT
- Hệ thống vai trò người dùng (User Roles) với System Prompt tự động
- Web UI Streamlit trực quan
- Logging 4 giai đoạn đầy đủ (RECV → MASK → OAPI → SEND)
- Retry với exponential backoff, adaptive timeout

---

## Mục lục

1. [Kiến trúc tổng quan](#1-kiến-trúc-tổng-quan)
2. [Cấu trúc thư mục](#2-cấu-trúc-thư-mục)
3. [Cài đặt & Cấu hình](#3-cài-đặt--cấu-hình)
4. [Chạy bằng Docker (khuyến nghị)](#4-chạy-bằng-docker-khuyến-nghị)
5. [Chạy thủ công (không dùng Docker)](#5-chạy-thủ-công-không-dùng-docker)
6. [API Reference](#6-api-reference)
7. [Vai trò người dùng (User Roles)](#7-vai-trò-người-dùng-user-roles)
8. [Knowledge Base (RAG)](#8-knowledge-base-rag)
9. [Luồng Masking chi tiết](#9-luồng-masking-chi-tiết)
10. [Hệ thống Logging](#10-hệ-thống-logging)
11. [Thiết kế bảo mật](#11-thiết-kế-bảo-mật)
12. [Mở rộng hệ thống](#12-mở-rộng-hệ-thống)

---

## 1. Kiến trúc tổng quan

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           Docker Network                                  │
│                                                                           │
│  ┌──────────────────┐   HTTP/JSON    ┌──────────────────────────────────┐ │
│  │                  │ ─────────────► │                                  │ │
│  │  Streamlit UI    │  /v1/chat/     │      LLM Privacy Gateway         │ │
│  │  :8501           │  /v1/rag/chat  │      (FastAPI  :8000)            │ │
│  │                  │ ◄───────────── │                                  │ │
│  └──────────────────┘                │  ┌──────────┐  ┌─────────────┐  │ │
│                                      │  │  Masker  │  │  RAG Engine │  │ │
│  ┌──────────────────┐   HTTP/JSON    │  │ (Regex)  │  │ (LangChain) │  │ │
│  │                  │ ─────────────► │  └──────────┘  └──────┬──────┘  │ │
│  │  CLI Client      │  /v1/chat/     │                        │         │ │
│  │  (client_test)   │  completions   │               ┌────────▼───────┐ │ │
│  │                  │ ◄───────────── │               │   ChromaDB     │ │ │
│  └──────────────────┘                │               │  (Vector Store)│ │ │
│                                      │               └────────────────┘ │ │
└──────────────────────────────────────┴──────────────────────┬────────────┘
                                                              │ HTTPS (masked payload)
                                                              ▼
                                                   ┌──────────────────────┐
                                                   │     OpenAI API        │
                                                   │  (không thấy data    │
                                                   │   thật của bạn)      │
                                                   └──────────────────────┘
```

### Luồng xử lý Chat thường

```
Client gửi request  { role: "SOC", messages: [...] }
      │
      ▼
 [1] RECV     Nhận request gốc, ghi log kèm role
      │
      ▼
 [2] MASK     Inject Role System Prompt
              → Mask dữ liệu nhạy cảm trong toàn bộ messages
              "10.0.0.5"   →  "[IP_1]"
              "srv-web-01" →  "[HOST_1]"
              "admin@x.com"→  "[EMAIL_1]"
      │
      ▼
 [3] OAPI     Gửi payload đã ẩn danh lên OpenAI, nhận response
      │
      ▼
 [4] SEND     De-mask response → trả về client với dữ liệu gốc
```

### Luồng xử lý RAG Chat

```
Client gửi query  { role: "SOC", query: "phân tích sự cố..." }
      │
      ▼
 [R-1] RAG_RECV      Nhận query gốc, ghi log
      │
      ▼
 [R-2] RAG_RETRIEVE  mask(query) → tìm kiếm semantic trong ChromaDB
                     → trả về các chunk liên quan
      │
      ▼
 [R-3] RAG_MASK_CTX  mask(context) → log [Doc_ID]→[Extracted]→[Masked]
      │
      ▼
 [R-4] RAG_SEND      Role Prompt + TAG Instruction + Masked Context
                     → LLM → demask(answer) → trả về client
```

---

## 2. Cấu trúc thư mục

```
datamasking/
│
├── app/
│   ├── __init__.py
│   ├── config.py          # Định nghĩa 5 vai trò & system prompts
│   ├── masker.py          # Engine Mask/De-mask — regex patterns, session mapping
│   ├── state.py           # Shared masker singleton (tránh circular import)
│   ├── server.py          # FastAPI Gateway — endpoint chính, proxy, logging
│   ├── request_logger.py  # Logging 4 giai đoạn vào JSONL
│   ├── rag.py             # RAG engine + FastAPI router (upload/search/chat)
│   └── rag_logger.py      # Logging 4 giai đoạn RAG vào JSONL
│
├── ui/
│   └── app.py             # Streamlit Web UI (Tab Chat + Tab Knowledge Base)
│
├── tests/
│   ├── client_test.py     # CLI client tương tác + auto-test
│   └── test_cases.py      # 39 test cases (unit + API), sinh báo cáo Markdown
│
├── logs/
│   └── requests/          # YYYY-MM-DD.jsonl — log từng request theo ngày
│
├── chroma_db/             # ChromaDB vector store (tự tạo khi upload tài liệu)
│   └── registry.json      # Metadata registry các tài liệu đã upload
│
├── Dockerfile             # Image Gateway (multi-stage, non-root)
├── Dockerfile.client      # Image CLI Client (tối giản)
├── Dockerfile.ui          # Image Streamlit UI
├── docker-compose.yml     # Orchestrate: gateway + ui + client
├── .dockerignore
├── .env.example
├── requirements.txt
└── README.md
```

### Vai trò từng file chính

| File | Vai trò |
|------|---------|
| `app/config.py` | Định nghĩa 5 vai trò (SOC, Marketing, PM, HR, Normal) và system prompt tương ứng |
| `app/masker.py` | Lõi xử lý: regex patterns, bảng mapping per-session, mask/demask API |
| `app/state.py` | Singleton `masker` dùng chung cho `server.py` và `rag.py` |
| `app/server.py` | FastAPI app: nhận request, inject role prompt, điều phối masking, proxy sang OpenAI |
| `app/request_logger.py` | Ghi log 4 giai đoạn (RECV/MASK/OAPI/SEND) vào file JSONL theo ngày |
| `app/rag.py` | Upload tài liệu, tìm kiếm vector, RAG chat với masking tích hợp |
| `app/rag_logger.py` | Ghi log 4 giai đoạn RAG (RAG_RECV/RETRIEVE/MASK_CTX/SEND) |
| `ui/app.py` | Web UI: chọn vai trò, chat, upload/quản lý Knowledge Base |
| `Dockerfile.ui` | Build Streamlit UI container |
| `docker-compose.yml` | 3 service: gateway (8000), ui (8501), client |

---

## 3. Cài đặt & Cấu hình

### Yêu cầu

- Docker >= 24.x và Docker Compose >= 2.x
- Hoặc: Python 3.11+ (nếu chạy thủ công)
- OpenAI API Key

### Tạo file `.env`

```bash
cp .env.example .env
```

Mở `.env` và điền:

```env
OPENAI_API_KEY=sk-...your-key-here...
OPENAI_BASE_URL=https://api.openai.com/v1
```

> `.env` được liệt kê trong `.dockerignore` — không bao giờ bị đưa vào Docker image.

---

## 4. Chạy bằng Docker (khuyến nghị)

### 4.1 Chạy toàn bộ hệ thống (gateway + web UI)

```bash
docker compose up --build gateway ui
```

**Kết quả:**
- Gateway API: `http://localhost:8000`
- Web UI (Streamlit): `http://localhost:8501`

Container `ui` tự động **chờ** gateway healthy trước khi khởi động.

---

### 4.2 Chỉ chạy Gateway

```bash
docker compose up --build gateway
```

Dùng khi chỉ cần API, không cần Web UI.

---

### 4.3 Chạy CLI client test tự động

```bash
docker compose run --rm client
```

Chạy kịch bản test 3 lượt hội thoại, kiểm tra không rò rỉ tag, in kết quả.

---

### 4.4 Rebuild sau khi thay đổi code

```bash
# Rebuild tất cả service
docker compose build

# Rebuild riêng từng service
docker compose build gateway
docker compose build ui
```

---

### 4.5 Xem log realtime

```bash
# Log của gateway (thấy RECV/MASK/OAPI/SEND/role)
docker compose logs -f gateway

# Log của UI
docker compose logs -f ui

# Tất cả
docker compose logs -f
```

---

### 4.6 Dừng và dọn dẹp

```bash
# Dừng tất cả container (giữ nguyên dữ liệu ChromaDB)
docker compose down

# Dừng và xóa image đã build
docker compose down --rmi local

# Xóa cả volume ChromaDB (mất toàn bộ Knowledge Base)
docker compose down -v
```

---

### 4.7 Test thủ công bằng curl

```bash
# Health check
curl http://localhost:8000/health

# Chat với vai trò SOC
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "session_id": "my-session-01",
    "role": "SOC",
    "messages": [
      {"role": "user", "content": "Server srv-web-01 tại 10.0.0.5 bị tấn công DDoS"}
    ]
  }'

# Upload tài liệu vào Knowledge Base
curl -X POST http://localhost:8000/upload \
  -F "file=@report.pdf" \
  -F "description=Báo cáo sự cố Q1-2026"

# RAG chat
curl -X POST http://localhost:8000/v1/rag/chat \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Tóm tắt các sự cố trong Q1?",
    "session_id": "rag-session-01",
    "role": "SOC"
  }'

# Xem bảng mapping của session
curl http://localhost:8000/v1/session/my-session-01/stats

# Xóa session
curl -X DELETE http://localhost:8000/v1/session/my-session-01
```

---

## 5. Chạy thủ công (không dùng Docker)

```bash
# Tạo virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# Cài dependencies
pip install -r requirements.txt

# Khởi động gateway
export $(cat .env | xargs)
uvicorn app.server:app --reload --port 8000

# Khởi động Web UI (terminal khác)
streamlit run ui/app.py

# Chạy CLI client (terminal khác)
python tests/client_test.py

# Chạy test tự động
python tests/test_cases.py --skip-api   # unit tests
python tests/test_cases.py              # tất cả (cần gateway đang chạy)
```

---

## 6. API Reference

### `POST /v1/chat/completions`

Tương thích cấu trúc OpenAI Chat Completions API. Thêm các trường: `session_id`, `role`, `log_block`.

**Request body:**

```json
{
  "model": "gpt-4o-mini",
  "session_id": "my-conversation-001",
  "role": "SOC",
  "messages": [
    {"role": "user", "content": "Server srv-web-01 tại 10.0.0.5 bị lỗi 500"}
  ],
  "temperature": 0.7,
  "max_tokens": 2048
}
```

| Trường | Bắt buộc | Mô tả |
|--------|----------|-------|
| `model` | Có | Model OpenAI muốn dùng |
| `messages` | Có | Mảng lịch sử hội thoại |
| `session_id` | Không | ID phiên — dùng chung nhiều lượt để giữ ngữ cảnh và Context Integrity |
| `role` | Không | Vai trò người dùng: `SOC`, `Marketing`, `PM`, `HR`, `Normal` (mặc định: `Normal`) |
| `log_block` | Không | `true` để bật chế độ phân tích log block 5 bước |

**Response:** Giống hệt OpenAI response, nội dung đã được de-mask.

---

### `POST /v1/rag/chat`

RAG chat với Knowledge Base nội bộ. Dữ liệu nhạy cảm trong query và context đều được mask trước khi gửi LLM.

**Request body:**

```json
{
  "query": "Tóm tắt các sự cố trong báo cáo Q1?",
  "session_id": "rag-session-01",
  "role": "SOC",
  "model": "gpt-4o-mini",
  "top_k": 4,
  "messages": [],
  "temperature": 0.7,
  "max_tokens": 2048
}
```

| Trường | Bắt buộc | Mô tả |
|--------|----------|-------|
| `query` | Có | Câu hỏi của người dùng |
| `session_id` | Không | ID phiên (tạo tự động nếu bỏ qua) |
| `role` | Không | Vai trò người dùng (mặc định: `Normal`) |
| `top_k` | Không | Số chunk lấy từ Knowledge Base (mặc định: 4) |
| `messages` | Không | Lịch sử chat các lượt trước |

**Response:** OpenAI-compatible + metadata RAG:

```json
{
  "choices": [{"message": {"content": "Theo báo cáo..."}}],
  "_rag_meta": {
    "request_id": "9C0E4D7C",
    "session_id": "rag-session-01",
    "chunks_used": 3,
    "top_k": 4
  }
}
```

---

### `POST /upload`

Upload tài liệu vào Knowledge Base. Hỗ trợ PDF, DOCX, TXT.

```bash
curl -X POST http://localhost:8000/upload \
  -F "file=@report.pdf" \
  -F "description=Báo cáo sự cố Q1-2026"
```

**Response:**
```json
{
  "doc_id": "0e88e880cb6b",
  "filename": "report.pdf",
  "chunk_count": 42,
  "uploaded_at": "2026-03-22T07:22:18+00:00"
}
```

---

### `GET /documents`

Danh sách tài liệu trong Knowledge Base.

```json
[
  {
    "doc_id": "0e88e880cb6b",
    "filename": "report.pdf",
    "description": "Báo cáo sự cố Q1-2026",
    "chunk_count": 42,
    "char_count": 35840,
    "uploaded_at": "2026-03-22T07:22:18+00:00"
  }
]
```

---

### `DELETE /documents/{doc_id}`

Xóa tài liệu khỏi Knowledge Base và ChromaDB.

```json
{"deleted": "0e88e880cb6b", "filename": "report.pdf"}
```

---

### `GET /health`

```json
{"status": "ok", "active_sessions": 3}
```

---

### `GET /v1/session/{session_id}/stats`

Xem bảng mapping của một session (debug).

```json
{
  "mapped_values": 3,
  "counters": {"IP": 1, "HOST": 1, "EMAIL": 1},
  "mappings": {
    "10.0.0.5": "[IP_1]",
    "srv-web-01": "[HOST_1]",
    "admin@corp.com": "[EMAIL_1]"
  }
}
```

---

### `DELETE /v1/session/{session_id}`

Giải phóng bộ nhớ session sau khi kết thúc hội thoại.

---

### `GET /v1/logs`, `GET /v1/logs/{date}`, `GET /v1/logs/{date}/{request_id}`

Xem log theo ngày hoặc theo request_id cụ thể.

```bash
# Danh sách file log
curl http://localhost:8000/v1/logs

# Log ngày hôm nay, lọc theo stage MASK
curl "http://localhost:8000/v1/logs/2026-03-22?stage=MASK"

# Toàn bộ 4 giai đoạn của một request
curl http://localhost:8000/v1/logs/2026-03-22/3C735A99
```

---

## 7. Vai trò người dùng (User Roles)

Hệ thống hỗ trợ 5 vai trò, mỗi vai trò có System Prompt riêng được tự động inject vào mỗi request trước khi masking.

### Danh sách vai trò

| Vai trò | Mô tả | System Prompt |
|---------|-------|---------------|
| `SOC` | An ninh mạng | Phân tích sự cố bảo mật, xác định root cause, đề xuất biện pháp khắc phục |
| `Marketing` | Marketing | Tư duy sáng tạo, định hướng khách hàng, chiến lược tiếp thị |
| `PM` | Quản lý dự án | Cấu trúc rõ ràng, kế hoạch hành động, quản lý rủi ro dự án B2B |
| `HR` | Nhân sự | Tuân thủ chính sách, bảo mật thông tin nhân viên, phát triển tổ chức |
| `Normal` | Nhân viên thông thường | Tìm hiểu quy trình nội bộ, kiến thức chung *(mặc định)* |

### Luồng inject System Prompt

```
Request đến: { role: "SOC", messages: [{role: "user", content: "..."}] }
      │
      ▼
[1] Inject Role Prompt vào messages:
    messages = [
      {role: "system", content: "Bạn là nhân sự SOC..."},  ← thêm mới
      {role: "user",   content: "..."}
    ]
      │
      ▼
[2] Mask toàn bộ messages (bao gồm cả system prompt nếu có dữ liệu nhạy cảm)
      │
      ▼
[3] Inject TAG_SYSTEM_INSTRUCTION vào system message
      │
      ▼
[4] Gửi lên OpenAI (field "role" của request bị loại bỏ, không forward)
```

### Cách truyền vai trò

**Qua API:**
```json
{"role": "SOC", "messages": [...]}
```

**Qua Web UI:** Bấm vào một trong 5 button vai trò trên đầu trang Chat.

**Không truyền:** Server dùng vai trò mặc định `Normal`.

### Thêm vai trò mới

Mở `app/config.py` và thêm vào dict `ROLES`:

```python
ROLES["Legal"] = (
    "Bạn là chuyên gia tư vấn pháp lý nội bộ, "
    "chuyên hỗ trợ các vấn đề hợp đồng và tuân thủ pháp luật."
)
```

---

## 8. Knowledge Base (RAG)

### Kiến trúc RAG

```
┌────────────────────────────────────────────────────────────┐
│                     RAG Pipeline                            │
│                                                             │
│  Tài liệu (PDF/DOCX/TXT)                                   │
│        │                                                    │
│        ▼                                                    │
│  LangChain Loader → Text Splitter (chunk 800 chars)        │
│        │                                                    │
│        ▼                                                    │
│  OpenAI Embeddings → ChromaDB (PersistentClient)           │
│                                                             │
│  Query: "phân tích sự cố?"                                  │
│        │                                                    │
│        ▼                                                    │
│  mask(query) → similarity_search_with_score(top_k=4)       │
│        │                                                    │
│        ▼                                                    │
│  mask(context chunks) → LLM → demask(answer)               │
└────────────────────────────────────────────────────────────┘
```

### Định dạng tài liệu hỗ trợ

| Định dạng | Loader | Ghi chú |
|-----------|--------|---------|
| `.pdf` | PyPDFLoader | Multi-page, bảng, hình (text layer) |
| `.docx` / `.doc` | Docx2txtLoader | Microsoft Word |
| `.txt` | TextLoader (UTF-8) | Plain text, log files |

### Masking trong RAG

Dữ liệu nhạy cảm được mask ở **hai nơi**:
1. **Query** — trước khi tìm kiếm vector
2. **Context** — các chunk retrieved từ ChromaDB trước khi gửi LLM

Tài liệu lưu trong ChromaDB ở dạng **nguyên bản** (chưa mask), masking chỉ xảy ra tại thời điểm xử lý request trong session đó.

### Logging RAG (4 giai đoạn)

| Stage | Nội dung ghi log |
|-------|-----------------|
| `RAG_RECV` | Query gốc (dữ liệu thật), model, top_k |
| `RAG_RETRIEVE` | Query đã mask, danh sách chunk retrieved + score |
| `RAG_MASK_CTX` | Từng chunk: `[doc_id] → [extracted] → [masked]`, flag `changed` |
| `RAG_SEND` | Answer trước/sau de-mask, token usage |

---

## 9. Luồng Masking chi tiết

### Các loại dữ liệu được phát hiện

| Loại | Tag | Ví dụ phát hiện |
|------|-----|-----------------|
| IPv4 Address | `[IP_N]` | `10.0.0.5`, `192.168.1.100` |
| Email | `[EMAIL_N]` | `admin@internal.corp` |
| Hostname / Server | `[HOST_N]` | `srv-web-01`, `db-master`, `api-gw-prod` |
| File Path | `[PATH_N]` | `/var/log/nginx/error.log` |

**Thứ tự ưu tiên:** IP → EMAIL → HOST → PATH (cụ thể trước, tổng quát sau)

### Tính nhất quán ngữ cảnh (Context Integrity)

```
Turn 1: "server srv-web-01 tại 10.0.0.5"
         → mask → "server [HOST_1] tại [IP_1]"

Turn 2: "Port nào mở trên 10.0.0.5?"
         → mask → "Port nào mở trên [IP_1]?"
                                         ↑ Cùng tag, không tạo [IP_2]
```

Bảng mapping lưu theo `session_id` trong bộ nhớ. Mỗi giá trị xuất hiện lần đầu tạo tag mới; lần tiếp theo dùng tag cũ.

### De-masking an toàn

Tags sắp xếp theo **độ dài giảm dần** trước khi replace:

```
✓ Đúng: [HOST_10] → srv-db-10   (restore trước)
         [HOST_1]  → srv-web-01  (restore sau)

✗ Sai (nếu không sort): [HOST_1]0] → srv-web-010]
```

### Các pattern đặc biệt không bị mask

- **CVE IDs:** `CVE-2024-1086` — không mask (negative lookahead)
- **Protocol versions:** `HTTP-1.1`, `TLS-1.3`, `SSL-3.0` — không mask
- **File names đơn giản:** `app.log`, `nginx.conf` — không mask (yêu cầu ít nhất 1 hyphen trong hostname)

---

## 10. Hệ thống Logging

### Cấu trúc log

```
logs/
└── requests/
    ├── 2026-03-22.jsonl    ← mỗi dòng là 1 JSON record
    └── 2026-03-23.jsonl
```

### Ví dụ log console (RECV với role)

```
2026-03-22T14:39:00Z  INFO  [3C735A99] ── RECV ──  session=my-session-01  role=SOC  model=gpt-4o-mini  turns=1
2026-03-22T14:39:00Z  INFO  [3C735A99] ── MASK ──  2/2 message(s) chứa dữ liệu nhạy cảm  |  Bảng mapping: 3 giá trị
2026-03-22T14:39:02Z  INFO  [3C735A99] ── OAPI ──  HTTP 200  |  tokens: prompt=312 completion=156 total=468
2026-03-22T14:39:02Z  INFO  [3C735A99] ── SEND ──  1 choice(s) đã de-mask → trả về client
```

### Xem log qua API

```bash
# Danh sách file log
curl http://localhost:8000/v1/logs

# Log một ngày, lọc theo stage
curl "http://localhost:8000/v1/logs/2026-03-22?stage=RECV"
curl "http://localhost:8000/v1/logs/2026-03-22?session=my-session-01"

# Toàn bộ 4 giai đoạn của một request
curl http://localhost:8000/v1/logs/2026-03-22/3C735A99
```

### Xem log trực tiếp (realtime)

```bash
tail -f logs/requests/$(date +%Y-%m-%d).jsonl | python3 -m json.tool
grep '"role":"SOC"' logs/requests/2026-03-22.jsonl | python3 -m json.tool
grep '"stage":"RAG_MASK_CTX"' logs/requests/2026-03-22.jsonl | python3 -m json.tool
```

---

## 11. Thiết kế bảo mật

| Vấn đề | Giải pháp |
|--------|-----------|
| API Key lộ trong image | `.env` trong `.dockerignore`; truyền qua `env_file` khi runtime |
| Container chạy root | `USER 1001` (non-root) trong tất cả Dockerfile |
| Client thấy tag thô | De-mask toàn bộ trước khi trả response |
| Cùng giá trị, khác tag | Bảng mapping per-session đảm bảo Context Integrity |
| Tag dài tốn token | Tags ngắn `[IP_1]` thay vì `SENSITIVE_IP_ADDRESS_01` |
| Bộ nhớ tích lũy | `DELETE /v1/session/{id}` để giải phóng khi xong |
| Role prompt chứa data nhạy cảm | Masking áp dụng SAU khi inject role prompt |
| Field `role` forward sang OpenAI | Strip `role` khỏi payload trước khi gửi |
| ChromaDB lưu dữ liệu thật | Tài liệu nguyên bản trong DB; masking chỉ xảy ra tại request-time |

---

## 12. Mở rộng hệ thống

### Thêm loại dữ liệu cần mask

Mở `app/masker.py` → thêm vào `PATTERNS`:

```python
(
    "CARD",
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),
),
```

### Thêm vai trò mới

Mở `app/config.py` → thêm vào `ROLES`:

```python
ROLES["Legal"] = (
    "Bạn là chuyên gia tư vấn pháp lý nội bộ, "
    "chuyên hỗ trợ các vấn đề hợp đồng và tuân thủ pháp luật."
)
```

### Dùng Redis thay In-memory

Thay `self._sessions: Dict` trong `Masker` bằng Redis client để hỗ trợ nhiều instance gateway (horizontal scaling).

### Thêm Presidio Analyzer

```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_lg
```

Tích hợp vào `masker.py` để phát hiện thêm: tên người, số CMND, số điện thoại, ...

### Hỗ trợ Streaming

Xử lý `text/event-stream` response từ OpenAI và de-mask từng chunk SSE trước khi forward về client.
