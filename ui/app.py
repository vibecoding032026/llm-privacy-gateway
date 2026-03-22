"""
app.py — Streamlit Web UI cho LLM Privacy Gateway + RAG Knowledge Base.

Tab 1: Chat — gửi câu hỏi đến /v1/rag/chat (nếu có KB) hoặc /v1/chat/completions
Tab 2: Knowledge Base — upload, xem danh sách, xóa tài liệu

Biến môi trường:
  GATEWAY_URL   — base URL của gateway  (mặc định: http://localhost:8000)
  MODEL         — mô hình LLM           (mặc định: gpt-4o-mini)
"""

import os
import uuid

import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Cấu hình
# ---------------------------------------------------------------------------

GATEWAY_BASE = os.getenv("GATEWAY_URL", "http://localhost:8000").rstrip("/")
MODEL        = os.getenv("MODEL", "gpt-4o-mini")

CHAT_URL    = f"{GATEWAY_BASE}/v1/chat/completions"
RAG_URL     = f"{GATEWAY_BASE}/v1/rag/chat"
UPLOAD_URL  = f"{GATEWAY_BASE}/upload"
DOCS_URL    = f"{GATEWAY_BASE}/documents"

TAG_PREFIXES = ["[IP_", "[HOST_", "[EMAIL_", "[PATH_"]

# Danh sách vai trò và icon tương ứng
ROLES = {
    "SOC":       "🛡️ SOC",
    "Marketing": "📣 Marketing",
    "PM":        "📋 PM",
    "HR":        "👥 HR",
    "Normal":    "👤 Normal",
}
ROLE_DESCRIPTIONS = {
    "SOC":       "Phân tích an ninh mạng & sự cố bảo mật",
    "Marketing": "Sáng tạo kịch bản & chiến lược marketing",
    "PM":        "Quản lý dự án B2B & lập kế hoạch",
    "HR":        "Quản lý nhân sự & chính sách tổ chức",
    "Normal":    "Tìm hiểu quy trình nội bộ & kiến thức chung",
}

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

def _init_state() -> None:
    if "session_id" not in st.session_state:
        st.session_state.session_id = str(uuid.uuid4())[:8]
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "use_rag" not in st.session_state:
        st.session_state.use_rag = True
    if "selected_role" not in st.session_state:
        st.session_state.selected_role = "Normal"


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _send_chat(query: str, use_rag: bool) -> dict:
    """Gửi câu hỏi đến gateway và trả về JSON response."""
    session_id  = st.session_state.session_id
    role        = st.session_state.selected_role
    history     = st.session_state.messages[:-1]  # bỏ message vừa thêm

    if use_rag:
        payload = {
            "query":       query,
            "session_id":  session_id,
            "role":        role,
            "model":       MODEL,
            "top_k":       4,
            "messages":    history,
            "temperature": 0.7,
            "max_tokens":  2048,
        }
        resp = requests.post(RAG_URL, json=payload, timeout=120)
    else:
        messages = history + [{"role": "user", "content": query}]
        payload = {
            "model":       MODEL,
            "messages":    messages,
            "session_id":  session_id,
            "role":        role,
            "temperature": 0.7,
            "max_tokens":  2048,
        }
        resp = requests.post(CHAT_URL, json=payload, timeout=90)

    resp.raise_for_status()
    return resp.json()


def _get_documents() -> list:
    try:
        r = requests.get(DOCS_URL, timeout=10)
        return r.json() if r.ok else []
    except Exception:
        return []


def _upload_document(file_bytes: bytes, filename: str, description: str) -> dict:
    files = {"file": (filename, file_bytes, "application/octet-stream")}
    data  = {"description": description}
    resp  = requests.post(UPLOAD_URL, files=files, data=data, timeout=120)
    resp.raise_for_status()
    return resp.json()


def _delete_document(doc_id: str) -> bool:
    try:
        r = requests.delete(f"{DOCS_URL}/{doc_id}", timeout=10)
        return r.ok
    except Exception:
        return False


def _get_stats() -> dict | None:
    try:
        r = requests.get(
            f"{GATEWAY_BASE}/v1/session/{st.session_state.session_id}/stats",
            timeout=5,
        )
        return r.json() if r.ok else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tab 1 — Chat
# ---------------------------------------------------------------------------

def render_chat_tab() -> None:
    st.subheader("Trò chuyện với AI")

    # ── Bộ chọn vai trò ───────────────────────────────────────────────────────
    st.markdown("**Chọn vai trò:**")
    role_cols = st.columns(len(ROLES))
    for col, (role_key, role_label) in zip(role_cols, ROLES.items()):
        with col:
            is_selected = st.session_state.selected_role == role_key
            btn_type = "primary" if is_selected else "secondary"
            if st.button(
                role_label,
                key=f"role_btn_{role_key}",
                use_container_width=True,
                type=btn_type,
            ):
                if st.session_state.selected_role != role_key:
                    st.session_state.selected_role = role_key
                    st.rerun()

    # Hiển thị mô tả vai trò đang chọn
    current_role = st.session_state.selected_role
    st.info(
        f"**{ROLES[current_role]}** — {ROLE_DESCRIPTIONS[current_role]}",
        icon="ℹ️",
    )

    st.divider()

    # ── Thanh điều khiển ──────────────────────────────────────────────────────
    col1, col2, col3 = st.columns([3, 2, 2])
    with col1:
        st.caption(f"Session: `{st.session_state.session_id}`  |  Model: `{MODEL}`")
    with col2:
        use_rag = st.toggle(
            "Dùng Knowledge Base",
            value=st.session_state.use_rag,
            key="rag_toggle",
        )
        st.session_state.use_rag = use_rag
    with col3:
        if st.button("Cuộc trò chuyện mới", use_container_width=True):
            # Xóa session trên server
            try:
                requests.delete(
                    f"{GATEWAY_BASE}/v1/session/{st.session_state.session_id}",
                    timeout=5,
                )
            except Exception:
                pass
            st.session_state.session_id = str(uuid.uuid4())[:8]
            st.session_state.messages = []
            st.rerun()

    # Hiển thị lịch sử hội thoại
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Ô nhập câu hỏi
    if prompt := st.chat_input("Nhập câu hỏi của bạn..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Đang xử lý..."):
                try:
                    result = _send_chat(prompt, use_rag=st.session_state.use_rag)
                    answer = result["choices"][0]["message"]["content"]

                    # Cảnh báo tag rò rỉ
                    if any(p in answer for p in TAG_PREFIXES):
                        import re
                        leaked = re.findall(r'\[[A-Z]+_\d+\]', answer)
                        st.warning(f"⚠ Tag bị rò rỉ trong response: {leaked}")

                    # RAG metadata
                    if "_rag_meta" in result:
                        meta = result["_rag_meta"]
                        st.caption(
                            f"RAG: {meta['chunks_used']} chunk(s) từ Knowledge Base  "
                            f"|  role: **{st.session_state.selected_role}**  "
                            f"|  request_id: `{meta['request_id']}`"
                        )

                    st.markdown(answer)
                    st.session_state.messages.append({"role": "assistant", "content": answer})

                except requests.exceptions.ConnectionError:
                    st.error(f"Không kết nối được Gateway tại {GATEWAY_BASE}")
                except requests.exceptions.HTTPError as e:
                    status = e.response.status_code if e.response is not None else "?"
                    try:
                        detail = e.response.json().get("detail", str(e))
                    except Exception:
                        detail = str(e)
                    st.error(f"Lỗi {status}: {detail}")
                except Exception as e:
                    st.error(f"Lỗi: {e}")

    # Bảng masking
    with st.expander("Xem bảng Masking của session hiện tại"):
        stats = _get_stats()
        if stats and stats.get("mapped_values", 0) > 0:
            st.caption(f"Tổng {stats['mapped_values']} giá trị được mask  |  {stats.get('counters', {})}")
            mapping = stats.get("mappings", {})
            if mapping:
                rows = [{"Giá trị gốc": orig, "Tag gửi LLM": tag} for orig, tag in mapping.items()]
                st.dataframe(rows, use_container_width=True)
        else:
            st.caption("Chưa có dữ liệu nào được mask trong session này.")


# ---------------------------------------------------------------------------
# Tab 2 — Knowledge Base
# ---------------------------------------------------------------------------

def render_kb_tab() -> None:
    st.subheader("Quản lý Knowledge Base")

    # Upload
    st.markdown("#### Upload tài liệu mới")
    with st.form("upload_form", clear_on_submit=True):
        uploaded = st.file_uploader(
            "Chọn file (PDF, DOCX, TXT)",
            type=["pdf", "docx", "doc", "txt"],
        )
        description = st.text_input("Mô tả tài liệu (tuỳ chọn)")
        submitted = st.form_submit_button("Upload", use_container_width=True)

        if submitted and uploaded:
            with st.spinner(f"Đang xử lý {uploaded.name}..."):
                try:
                    result = _upload_document(
                        uploaded.read(),
                        uploaded.name,
                        description,
                    )
                    st.success(
                        f"Upload thành công! "
                        f"doc_id: `{result['doc_id']}`  |  "
                        f"{result['chunk_count']} chunk(s)"
                    )
                    st.rerun()
                except requests.exceptions.ConnectionError:
                    st.error(f"Không kết nối được Gateway tại {GATEWAY_BASE}")
                except requests.exceptions.HTTPError as e:
                    try:
                        detail = e.response.json().get("detail", str(e))
                    except Exception:
                        detail = str(e)
                    st.error(f"Upload thất bại: {detail}")
                except Exception as e:
                    st.error(f"Lỗi: {e}")
        elif submitted and not uploaded:
            st.warning("Vui lòng chọn một file trước khi upload.")

    st.divider()

    # Danh sách tài liệu
    st.markdown("#### Tài liệu trong Knowledge Base")
    docs = _get_documents()

    if not docs:
        st.info("Knowledge Base đang trống. Upload tài liệu đầu tiên ở trên.")
        return

    for doc in docs:
        with st.container(border=True):
            col1, col2 = st.columns([5, 1])
            with col1:
                st.markdown(f"**{doc['filename']}**")
                if doc.get("description"):
                    st.caption(doc["description"])
                st.caption(
                    f"doc_id: `{doc['doc_id']}`  |  "
                    f"{doc['chunk_count']} chunks  |  "
                    f"{doc.get('char_count', 0):,} ký tự  |  "
                    f"Upload: {doc.get('uploaded_at', '')}"
                )
            with col2:
                if st.button("Xóa", key=f"del_{doc['doc_id']}", use_container_width=True):
                    with st.spinner("Đang xóa..."):
                        if _delete_document(doc["doc_id"]):
                            st.success(f"Đã xóa {doc['filename']}")
                            st.rerun()
                        else:
                            st.error("Xóa thất bại.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(
        page_title="LLM Privacy Gateway",
        page_icon="🔒",
        layout="wide",
    )
    st.title("🔒 LLM Privacy Gateway")
    st.caption("Dữ liệu nhạy cảm (IP, hostname, email, path) được tự động mask trước khi gửi lên AI.")

    _init_state()

    tab_chat, tab_kb = st.tabs(["💬 Chat", "📚 Knowledge Base"])

    with tab_chat:
        render_chat_tab()

    with tab_kb:
        render_kb_tab()


if __name__ == "__main__":
    main()
