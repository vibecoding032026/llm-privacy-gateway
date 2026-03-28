"""
app.py — Streamlit Web UI cho LLM Privacy Gateway + Auth & RBAC.

Cấu trúc
---------
  [Chưa đăng nhập]  →  Trang Login
  [Đã đăng nhập]    →  Tab Chat | Tab Knowledge Base | Tab Admin (admin only)

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

CHAT_URL        = f"{GATEWAY_BASE}/v1/chat/completions"
RAG_URL         = f"{GATEWAY_BASE}/v1/rag/chat"
UPLOAD_URL      = f"{GATEWAY_BASE}/upload"
DOCS_URL        = f"{GATEWAY_BASE}/documents"
LOGIN_URL       = f"{GATEWAY_BASE}/auth/login"
ME_URL          = f"{GATEWAY_BASE}/auth/me"
CHANGE_PWD_URL  = f"{GATEWAY_BASE}/auth/change-password"
REGISTER_URL    = f"{GATEWAY_BASE}/auth/register"
ADMIN_USERS_URL  = f"{GATEWAY_BASE}/admin/users"
ADMIN_AUDIT_URL  = f"{GATEWAY_BASE}/admin/audit-logs"
ADMIN_STATS_URL  = f"{GATEWAY_BASE}/admin/stats"
ADMIN_APIKEYS_URL = f"{GATEWAY_BASE}/admin/api-keys"
ADMIN_PENDING_URL = f"{GATEWAY_BASE}/admin/pending-registrations"


TAG_PREFIXES = ["[IP_", "[HOST_", "[EMAIL_", "[PATH_"]

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
ALL_ROLE_OPTIONS = ["all"] + list(ROLES.keys())


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def _init_state() -> None:
    defaults = {
        "token":         None,
        "user":          None,
        "session_id":    str(uuid.uuid4())[:8],
        "messages":      [],
        "use_rag":       True,
        "show_register": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def _is_logged_in() -> bool:
    return bool(st.session_state.get("token"))


def _is_admin() -> bool:
    return bool(st.session_state.get("user", {}).get("is_admin", False))


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {st.session_state.token}"}


def _user_role() -> str:
    return st.session_state.get("user", {}).get("role", "Normal")


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _api_get(url: str, **kwargs) -> requests.Response:
    return requests.get(url, headers=_auth_headers(), timeout=10, **kwargs)


def _api_post(url: str, **kwargs) -> requests.Response:
    return requests.post(url, headers=_auth_headers(), timeout=120, **kwargs)


def _api_put(url: str, **kwargs) -> requests.Response:
    return requests.put(url, headers=_auth_headers(), timeout=10, **kwargs)


def _api_delete(url: str, **kwargs) -> requests.Response:
    return requests.delete(url, headers=_auth_headers(), timeout=10, **kwargs)


def _safe_detail(resp: requests.Response) -> str:
    """Trích xuất thông báo lỗi đọc được từ response (kể cả Pydantic 422 list)."""
    try:
        body   = resp.json()
        detail = body.get("detail", resp.text)
        if isinstance(detail, list):
            msgs = []
            for err in detail:
                if isinstance(err, dict):
                    msg   = err.get("msg", str(err))
                    msg   = msg.removeprefix("Value error, ")
                    loc   = err.get("loc", [])
                    field = next((x for x in reversed(loc) if isinstance(x, str) and x != "body"), "")
                    msgs.append(f"**{field}**: {msg}" if field else msg)
                else:
                    msgs.append(str(err))
            return "  \n".join(msgs) if msgs else str(detail)
        return str(detail)
    except Exception:
        return resp.text


# ---------------------------------------------------------------------------
# Trang Đăng ký
# ---------------------------------------------------------------------------

def render_register_form() -> None:
    col_l, col_m, col_r = st.columns([1, 2, 1])
    with col_m:
        st.markdown("## 🔒 LLM Privacy Gateway")
        st.markdown("##### Tạo tài khoản mới")
        st.divider()

        with st.form("register_form"):
            reg_email    = st.text_input("Email công ty", placeholder="ten@vsec.com.vn")
            reg_name     = st.text_input("Họ và tên")
            reg_password = st.text_input("Mật khẩu (≥8 ký tự)", type="password")
            reg_confirm  = st.text_input("Xác nhận mật khẩu", type="password")
            reg_btn      = st.form_submit_button("Đăng ký", use_container_width=True, type="primary")

        if reg_btn:
            if not all([reg_email, reg_name, reg_password, reg_confirm]):
                st.error("Vui lòng điền đầy đủ thông tin.")
            elif reg_password != reg_confirm:
                st.error("Mật khẩu xác nhận không khớp.")
            else:
                try:
                    resp = requests.post(
                        REGISTER_URL,
                        json={"email": reg_email, "full_name": reg_name, "password": reg_password},
                        timeout=15,
                    )
                    if resp.status_code == 202:
                        st.success(resp.json().get("message", "Đăng ký thành công! Kiểm tra email để kích hoạt tài khoản."))
                    else:
                        st.error(_safe_detail(resp))
                except requests.exceptions.ConnectionError:
                    st.error(f"Không kết nối được Gateway tại {GATEWAY_BASE}")
                except Exception as e:
                    st.error(f"Lỗi: {e}")

        st.divider()
        st.markdown("Đã có tài khoản?")
        if st.button("Quay lại đăng nhập", use_container_width=True):
            st.session_state.show_register = False
            st.rerun()


# ---------------------------------------------------------------------------
# Trang Login
# ---------------------------------------------------------------------------

def render_login_page() -> None:
    col_l, col_m, col_r = st.columns([1, 2, 1])
    with col_m:
        st.markdown("## 🔒 LLM Privacy Gateway")
        st.markdown("##### Đăng nhập để tiếp tục")
        st.divider()

        with st.form("login_form"):
            email    = st.text_input("Email", placeholder="ten@vsec.com.vn")
            password = st.text_input("Mật khẩu", type="password")
            submitted = st.form_submit_button("Đăng nhập", use_container_width=True, type="primary")

        if submitted:
            if not email or not password:
                st.error("Vui lòng nhập email và mật khẩu.")
                return
            try:
                resp = requests.post(LOGIN_URL, json={"email": email, "password": password}, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    st.session_state.token = data["access_token"]
                    user_info = data["user"]
                    # Gọi /auth/me để lấy thông tin đầy đủ và kiểm tra admin
                    me_resp = requests.get(ME_URL, headers={"Authorization": f"Bearer {data['access_token']}"}, timeout=5)
                    if me_resp.ok:
                        user_info = me_resp.json()
                    # Xác định admin bằng cách thử gọi /admin/users
                    admin_check = requests.get(ADMIN_USERS_URL,
                                               headers={"Authorization": f"Bearer {data['access_token']}"},
                                               timeout=5)
                    user_info["is_admin"] = admin_check.status_code == 200
                    st.session_state.user = user_info
                    st.rerun()
                else:
                    st.error(_safe_detail(resp))
            except requests.exceptions.ConnectionError:
                st.error(f"Không kết nối được Gateway tại {GATEWAY_BASE}")
            except Exception as e:
                st.error(f"Lỗi: {e}")

        st.divider()
        st.markdown("Chưa có tài khoản?")
        if st.button("Đăng ký tài khoản mới", use_container_width=True):
            st.session_state.show_register = True
            st.rerun()


# ---------------------------------------------------------------------------
# Tab Chat
# ---------------------------------------------------------------------------

def render_chat_tab() -> None:
    st.subheader("Trò chuyện với AI")
    role = _user_role()

    # Bộ chọn vai trò (chỉ hiển thị, không thể thay đổi — role cố định theo tài khoản)
    st.info(
        f"Vai trò của bạn: **{ROLES.get(role, role)}** — {ROLE_DESCRIPTIONS.get(role, '')}",
        icon="ℹ️",
    )

    col1, col2, col3 = st.columns([3, 2, 2])
    with col1:
        st.caption(f"Session: `{st.session_state.session_id}`  |  Model: `{MODEL}`")
    with col2:
        use_rag = st.toggle("Dùng Knowledge Base", value=st.session_state.use_rag, key="rag_toggle")
        st.session_state.use_rag = use_rag
    with col3:
        if st.button("Cuộc trò chuyện mới", use_container_width=True):
            try:
                _api_delete(f"{GATEWAY_BASE}/v1/session/{st.session_state.session_id}")
            except Exception:
                pass
            st.session_state.session_id = str(uuid.uuid4())[:8]
            st.session_state.messages = []
            st.rerun()

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("Nhập câu hỏi của bạn..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Đang xử lý..."):
                try:
                    if st.session_state.use_rag:
                        payload = {
                            "query":       prompt,
                            "session_id":  st.session_state.session_id,
                            "model":       MODEL,
                            "top_k":       4,
                            "messages":    st.session_state.messages[:-1],
                            "temperature": 0.7,
                            "max_tokens":  2048,
                        }
                        resp = _api_post(RAG_URL, json=payload)
                    else:
                        payload = {
                            "model":       MODEL,
                            "messages":    st.session_state.messages,
                            "session_id":  st.session_state.session_id,
                            "temperature": 0.7,
                            "max_tokens":  2048,
                        }
                        resp = _api_post(CHAT_URL, json=payload)

                    resp.raise_for_status()
                    result = resp.json()
                    answer = result["choices"][0]["message"]["content"]

                    if any(p in answer for p in TAG_PREFIXES):
                        import re
                        leaked = re.findall(r'\[[A-Z]+_\d+\]', answer)
                        st.warning(f"⚠ Tag bị rò rỉ: {leaked}")

                    if "_rag_meta" in result:
                        meta = result["_rag_meta"]
                        st.caption(
                            f"RAG: {meta['chunks_used']} chunk(s)  "
                            f"|  role: **{meta.get('role', role)}**  "
                            f"|  req: `{meta['request_id']}`"
                        )

                    st.markdown(answer)
                    st.session_state.messages.append({"role": "assistant", "content": answer})

                except requests.exceptions.HTTPError as e:
                    st.error(f"Lỗi {e.response.status_code}: {_safe_detail(e.response)}")
                except requests.exceptions.ConnectionError:
                    st.error(f"Không kết nối được Gateway tại {GATEWAY_BASE}")
                except Exception as e:
                    st.error(f"Lỗi: {e}")

    with st.expander("Xem bảng Masking của session hiện tại"):
        try:
            r = _api_get(f"{GATEWAY_BASE}/v1/session/{st.session_state.session_id}/stats")
            stats = r.json() if r.ok else {}
        except Exception:
            stats = {}
        if stats and stats.get("mapped_values", 0) > 0:
            st.caption(f"Tổng {stats['mapped_values']} giá trị được mask  |  {stats.get('counters', {})}")
            rows = [{"Giá trị gốc": orig, "Tag gửi LLM": tag}
                    for orig, tag in stats.get("mappings", {}).items()]
            if rows:
                st.dataframe(rows, use_container_width=True)
        else:
            st.caption("Chưa có dữ liệu nào được mask trong session này.")


# ---------------------------------------------------------------------------
# Tab Knowledge Base
# ---------------------------------------------------------------------------

def render_kb_tab() -> None:
    st.subheader("Knowledge Base")

    if _is_admin():
        # Admin: upload form với lựa chọn allowed_roles
        st.markdown("#### Upload tài liệu mới")
        with st.form("upload_form", clear_on_submit=True):
            uploaded    = st.file_uploader(
                "Chọn file (PDF, DOCX, TXT, hoặc ảnh PNG/JPG/TIFF/WEBP)",
                type=["pdf", "docx", "doc", "txt", "png", "jpg", "jpeg", "tiff", "tif", "webp", "bmp"],
            )
            description = st.text_input("Mô tả tài liệu")
            allowed     = st.multiselect(
                "Phân quyền truy cập",
                options=list(ROLES.keys()) + ["all"],
                default=["all"],
                help="Chọn 'all' để mọi người xem được, hoặc chọn các role cụ thể.",
            )
            submitted = st.form_submit_button("Upload", use_container_width=True)

            if submitted and uploaded:
                allowed_str = "all" if "all" in allowed else ",".join(allowed)
                with st.spinner(f"Đang xử lý {uploaded.name}..."):
                    try:
                        files = {"file": (uploaded.name, uploaded.read(), "application/octet-stream")}
                        data  = {"description": description, "allowed_roles": allowed_str}
                        resp  = requests.post(UPLOAD_URL, files=files, data=data,
                                              headers=_auth_headers(), timeout=120)
                        resp.raise_for_status()
                        r = resp.json()
                        ocr_note = f"  |  🔍 OCR {r['ocr_pages']} trang" if r.get("ocr") else ""
                        st.success(
                            f"Upload thành công! doc_id: `{r['doc_id']}`  |  "
                            f"{r['chunk_count']} chunk(s)  |  roles: **{r['allowed_roles']}**{ocr_note}"
                        )
                        st.rerun()
                    except requests.exceptions.HTTPError as e:
                        st.error(f"Upload thất bại: {_safe_detail(e.response)}")
                    except Exception as e:
                        st.error(f"Lỗi: {e}")
            elif submitted:
                st.warning("Vui lòng chọn file.")
        st.divider()

    # Danh sách tài liệu
    st.markdown("#### Tài liệu trong Knowledge Base")
    try:
        resp = _api_get(DOCS_URL)
        docs = resp.json() if resp.ok else []
    except Exception:
        docs = []

    if not docs:
        st.info("Không có tài liệu nào phù hợp với quyền truy cập của bạn.")
        return

    for doc in docs:
        with st.container(border=True):
            col1, col2 = st.columns([5, 1])
            with col1:
                st.markdown(f"**{doc['filename']}**")
                if doc.get("description"):
                    st.caption(doc["description"])
                roles_badge = f"🔑 `{doc.get('allowed_roles', 'all')}`"
                ocr_badge   = "  |  🔍 OCR" if doc.get("ocr") else ""
                st.caption(
                    f"doc_id: `{doc['doc_id']}`  |  {doc['chunk_count']} chunks  |  "
                    f"{doc.get('char_count', 0):,} ký tự  |  "
                    f"Upload: {doc.get('uploaded_at', '')}  |  {roles_badge}{ocr_badge}"
                )
            with col2:
                if _is_admin():
                    if st.button("Xóa", key=f"del_{doc['doc_id']}", use_container_width=True):
                        try:
                            r = _api_delete(f"{DOCS_URL}/{doc['doc_id']}")
                            if r.ok:
                                st.success("Đã xóa.")
                                st.rerun()
                            else:
                                st.error(_safe_detail(r))
                        except Exception as e:
                            st.error(f"Lỗi: {e}")


# ---------------------------------------------------------------------------
# Tab Admin Dashboard
# ---------------------------------------------------------------------------

def render_admin_tab() -> None:
    st.subheader("Admin Dashboard")
    admin_tab1, admin_tab2, admin_tab3, admin_tab4, admin_tab5 = st.tabs([
        "👥 Quản lý Users", "📊 Thống kê sử dụng", "🗝️ API Keys", "📋 Audit Log", "🔑 Đổi mật khẩu",
    ])

    # ── Quản lý Users ─────────────────────────────────────────────────────────
    with admin_tab1:
        # ── Form tạo user mới (trong expander để tránh lồng columns) ──────────
        with st.expander("➕ Tạo user mới", expanded=False):
            with st.form("create_user_form", clear_on_submit=True):
                c1, c2 = st.columns(2)
                with c1:
                    new_email = st.text_input("Email (@vsec.com.vn)")
                    new_name  = st.text_input("Họ và tên")
                with c2:
                    new_role     = st.selectbox("Vai trò", list(ROLES.keys()))
                    new_password = st.text_input("Mật khẩu khởi tạo", type="password")
                create_btn = st.form_submit_button("Tạo tài khoản", use_container_width=True, type="primary")

            if create_btn:
                if not all([new_email, new_name, new_password]):
                    st.error("Vui lòng điền đầy đủ thông tin.")
                else:
                    try:
                        resp = _api_post(ADMIN_USERS_URL, json={
                            "email": new_email, "password": new_password,
                            "full_name": new_name, "role": new_role,
                        })
                        if resp.status_code == 201:
                            st.success(f"Đã tạo tài khoản **{new_email}** ({new_role})")
                            st.rerun()
                        else:
                            st.error(_safe_detail(resp))
                    except Exception as e:
                        st.error(f"Lỗi: {e}")

        # ── Yêu cầu đăng ký chờ duyệt ──────────────────────────────────────
        with st.expander("🕐 Yêu cầu đăng ký chờ duyệt", expanded=False):
            try:
                resp_pending = _api_get(ADMIN_PENDING_URL)
                pending_list = resp_pending.json() if resp_pending.ok else []
            except Exception:
                pending_list = []

            if not pending_list:
                st.info("Không có yêu cầu đăng ký nào đang chờ.")
            else:
                st.caption(f"{len(pending_list)} yêu cầu đang chờ kích hoạt")
                for p in pending_list:
                    with st.container(border=True):
                        col_pinfo, col_pact, col_pdel = st.columns([5, 1, 1])
                        with col_pinfo:
                            st.markdown(f"**{p['full_name']}**  `{p['email']}`")
                            st.caption(
                                f"Đăng ký: {p.get('created_at', '')[:19]}  |  "
                                f"Hết hạn: {p.get('expires_at', '')[:19]}"
                            )
                        with col_pact:
                            if st.button("Kích hoạt", key=f"act_pending_{p['id']}", use_container_width=True, type="primary"):
                                try:
                                    r = _api_post(f"{ADMIN_PENDING_URL}/{p['id']}/activate")
                                    if r.ok:
                                        st.success(r.json().get("message", "Đã kích hoạt."))
                                        st.rerun()
                                    else:
                                        st.error(_safe_detail(r))
                                except Exception as e:
                                    st.error(f"Lỗi: {e}")
                        with col_pdel:
                            if st.button("Xóa", key=f"del_pending_{p['id']}", use_container_width=True):
                                try:
                                    r = _api_delete(f"{ADMIN_PENDING_URL}/{p['id']}")
                                    if r.ok:
                                        st.rerun()
                                    else:
                                        st.error(_safe_detail(r))
                                except Exception as e:
                                    st.error(f"Lỗi: {e}")

        # ── Danh sách tài khoản ──────────────────────────────────────────────
        st.markdown("#### Danh sách tài khoản")
        try:
            resp  = _api_get(ADMIN_USERS_URL)
            users = resp.json() if resp.ok else []
        except Exception:
            users = []

        for u in users:
            status_icon = "✅" if u["is_active"] else "🔒"
            uid = u["id"]
            with st.container(border=True):
                # Hàng 1: thông tin user — 1 cấp columns duy nhất
                col_info, col_role, col_lock, col_reset = st.columns([4, 2, 1, 1])

                with col_info:
                    st.markdown(f"{status_icon} **{u['full_name']}**  `{u['email']}`")
                    st.caption(f"Role: **{u['role']}**  |  Tạo bởi: {u['created_by']}  |  {u['created_at'][:10]}")

                with col_role:
                    new_r = st.selectbox(
                        "Role", list(ROLES.keys()),
                        index=list(ROLES.keys()).index(u["role"]) if u["role"] in ROLES else 0,
                        key=f"role_{uid}", label_visibility="collapsed",
                    )
                    if new_r != u["role"]:
                        if st.button("Lưu role", key=f"save_role_{uid}", use_container_width=True):
                            r = _api_put(f"{ADMIN_USERS_URL}/{uid}", json={"role": new_r})
                            if r.ok:
                                st.rerun()
                            else:
                                st.error(_safe_detail(r))

                with col_lock:
                    if u["is_active"]:
                        if st.button("🔒", key=f"lock_{uid}", use_container_width=True, help="Khóa tài khoản"):
                            r = _api_post(f"{ADMIN_USERS_URL}/{uid}/lock")
                            if r.ok:
                                st.rerun()
                            else:
                                st.error(_safe_detail(r))
                    else:
                        if st.button("🔓", key=f"unlock_{uid}", use_container_width=True, help="Mở khóa"):
                            r = _api_post(f"{ADMIN_USERS_URL}/{uid}/unlock")
                            if r.ok:
                                st.rerun()
                            else:
                                st.error(_safe_detail(r))

                with col_reset:
                    with st.popover("🔑", help="Reset mật khẩu"):
                        new_pwd = st.text_input("Mật khẩu mới (≥8)", type="password", key=f"rpwd_{uid}")
                        if st.button("Xác nhận reset", key=f"do_reset_{uid}", use_container_width=True):
                            if len(new_pwd) < 8:
                                st.error("Tối thiểu 8 ký tự.")
                            else:
                                r = _api_post(f"{ADMIN_USERS_URL}/{uid}/reset-password",
                                              json={"new_password": new_pwd})
                                if r.ok:
                                    st.success("Đã reset mật khẩu thành công.")
                                else:
                                    st.error(_safe_detail(r))

    # ── Thống kê sử dụng ─────────────────────────────────────────────────────
    with admin_tab2:
        st.markdown("#### Báo cáo thống kê sử dụng")

        days_opt = st.selectbox(
            "Khoảng thời gian", [7, 14, 30, 90],
            index=2, format_func=lambda d: f"{d} ngày gần nhất",
            key="stats_days",
        )

        # ── Summary cards ────────────────────────────────────────────────────
        try:
            r_sum = _api_get(f"{ADMIN_STATS_URL}/summary", params={"days": days_opt})
            summ  = r_sum.json() if r_sum.ok else {}
        except Exception:
            summ = {}

        if summ:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Tổng lượt gửi",    f"{summ.get('total_requests', 0):,}")
            c2.metric("Người dùng",        f"{summ.get('unique_users', 0):,}")
            c3.metric("Tổng tokens",       f"{summ.get('total_tokens', 0):,}")
            c4.metric("Tỷ lệ thành công",  f"{summ.get('success_rate', 0)}%")

            c5, c6, c7, c8 = st.columns(4)
            c5.metric("Chat thường",       f"{summ.get('chat_requests', 0):,}")
            c6.metric("RAG Chat",          f"{summ.get('rag_requests', 0):,}")
            c7.metric("Entities bị mask",  f"{summ.get('total_masked', 0):,}")
            c8.metric("Latency TB (ms)",   f"{summ.get('avg_latency_ms', 0):,}")
        else:
            st.info("Chưa có dữ liệu sử dụng. Hãy thực hiện một số chat để xem thống kê.")

        st.divider()

        # ── Xu hướng theo ngày ───────────────────────────────────────────────
        st.markdown("##### Xu hướng sử dụng theo ngày")
        try:
            r_daily = _api_get(f"{ADMIN_STATS_URL}/daily", params={"days": days_opt})
            daily   = r_daily.json() if r_daily.ok else []
        except Exception:
            daily = []

        if daily:
            import pandas as pd
            df_daily = pd.DataFrame(daily).set_index("date")[["chat", "rag", "requests"]]
            df_daily.columns = ["Chat", "RAG Chat", "Tổng"]
            st.line_chart(df_daily[["Chat", "RAG Chat"]], use_container_width=True)

            st.caption("Số tokens theo ngày")
            df_tokens = pd.DataFrame(daily).set_index("date")[["total_tokens"]]
            df_tokens.columns = ["Tokens"]
            st.bar_chart(df_tokens, use_container_width=True)
        else:
            st.caption("Không có dữ liệu.")

        st.divider()

        # ── Thống kê theo bộ phận ────────────────────────────────────────────
        st.markdown("##### Thống kê theo bộ phận (Role)")
        try:
            r_dept = _api_get(f"{ADMIN_STATS_URL}/departments", params={"days": days_opt})
            depts  = r_dept.json() if r_dept.ok else []
        except Exception:
            depts = []

        if depts:
            import pandas as pd
            df_dept = pd.DataFrame(depts)
            df_dept_display = df_dept.rename(columns={
                "role": "Bộ phận", "requests": "Lượt gửi",
                "chat": "Chat", "rag": "RAG Chat",
                "total_tokens": "Tokens", "unique_users": "Người dùng",
                "masked_entities": "Entities mask", "errors": "Lỗi",
            })
            st.dataframe(df_dept_display.drop(columns=["Lỗi"], errors="ignore"),
                         use_container_width=True, hide_index=True)

            st.caption("Số lượt gửi theo bộ phận")
            chart_data = pd.DataFrame(depts).set_index("role")[["requests"]]
            chart_data.columns = ["Lượt gửi"]
            st.bar_chart(chart_data, use_container_width=True)
        else:
            st.caption("Không có dữ liệu.")

        st.divider()

        # ── Thống kê theo cá nhân ────────────────────────────────────────────
        st.markdown("##### Thống kê theo cá nhân")
        try:
            r_users = _api_get(f"{ADMIN_STATS_URL}/users", params={"days": days_opt})
            ustats  = r_users.json() if r_users.ok else []
        except Exception:
            ustats = []

        if ustats:
            import pandas as pd
            df_u = pd.DataFrame(ustats).rename(columns={
                "email": "Email", "role": "Vai trò",
                "requests": "Lượt gửi", "chat": "Chat", "rag": "RAG",
                "total_tokens": "Tokens", "avg_latency_ms": "Latency TB (ms)",
                "success_rate": "Thành công (%)", "errors": "Lỗi",
                "masked_entities": "Entities mask", "last_active": "Hoạt động cuối",
            })
            st.dataframe(df_u, use_container_width=True, hide_index=True)
        else:
            st.caption("Không có dữ liệu.")

    # ── API Keys ──────────────────────────────────────────────────────────────
    with admin_tab3:
        st.markdown("#### Quản lý API Keys")

        # Tạo key mới cho user bất kỳ
        with st.expander("➕ Tạo API Key mới", expanded=False):
            with st.form("create_apikey_form", clear_on_submit=True):
                # Lấy danh sách user
                try:
                    all_users = _api_get(ADMIN_USERS_URL).json()
                    user_options = {f"{u['email']} ({u['role']})": u["id"] for u in all_users}
                except Exception:
                    user_options = {}
                selected_user_label = st.selectbox("Tài khoản", list(user_options.keys()))
                key_name     = st.text_input("Tên key (tuỳ chọn)", placeholder="Ví dụ: CI/CD pipeline")
                expires_at   = st.text_input("Hết hạn (ISO 8601, để trống = không hết hạn)",
                                              placeholder="2026-12-31T23:59:59+00:00")
                create_k_btn = st.form_submit_button("Tạo API Key", use_container_width=True, type="primary")

            if create_k_btn and user_options:
                payload = {
                    "user_id": user_options[selected_user_label],
                    "name": key_name,
                    "expires_at": expires_at.strip() or None,
                }
                try:
                    resp = _api_post(ADMIN_APIKEYS_URL, json=payload)
                    if resp.status_code == 201:
                        data = resp.json()
                        st.success("API Key đã được tạo! Lưu lại ngay — sẽ không hiển thị lại.")
                        st.code(data["key"], language="text")
                        st.caption(f"Prefix: `{data['key_prefix']}` · User: {selected_user_label}")
                        st.rerun()
                    else:
                        st.error(_safe_detail(resp))
                except Exception as e:
                    st.error(f"Lỗi: {e}")

        # Danh sách toàn bộ API keys
        st.markdown("#### Danh sách API Keys")
        try:
            resp = _api_get(ADMIN_APIKEYS_URL)
            all_keys = resp.json() if resp.ok else []
        except Exception:
            all_keys = []

        if not all_keys:
            st.info("Chưa có API key nào.")
        else:
            st.caption(f"{len(all_keys)} keys")
            for k in all_keys:
                status_icon = "✅" if k["is_active"] else "🔒"
                with st.container(border=True):
                    col_info, col_action = st.columns([5, 1])
                    with col_info:
                        name_display = f"**{k['name']}**  " if k.get("name") else ""
                        st.markdown(f"{status_icon} {name_display}`{k['key_prefix']}…`  —  {k['email']}")
                        last_used = k.get("last_used_at", "Chưa dùng") or "Chưa dùng"
                        expires   = k.get("expires_at", "Không hết hạn") or "Không hết hạn"
                        st.caption(f"Tạo: {k['created_at'][:10]}  |  Dùng cuối: {last_used[:19] if last_used != 'Chưa dùng' else last_used}  |  Hết hạn: {expires[:10] if expires != 'Không hết hạn' else expires}")
                    with col_action:
                        if st.button("🗑️ Xóa", key=f"del_key_{k['id']}", use_container_width=True):
                            try:
                                r = _api_delete(f"{ADMIN_APIKEYS_URL}/{k['id']}")
                                if r.ok:
                                    st.rerun()
                                else:
                                    st.error(_safe_detail(r))
                            except Exception as e:
                                st.error(str(e))

    # ── Audit Log ─────────────────────────────────────────────────────────────
    with admin_tab4:
        st.markdown("#### Audit Log")
        try:
            resp  = _api_get(ADMIN_AUDIT_URL)
            files = resp.json().get("files", []) if resp.ok else []
        except Exception:
            files = []

        if not files:
            st.info("Chưa có audit log.")
        else:
            dates = [f["date"] for f in files]
            chosen_date = st.selectbox("Chọn ngày", dates, key="audit_date")
            action_filter = st.selectbox("Lọc theo action",
                ["(tất cả)", "AUTH_LOGIN", "AUTH_LOGIN_FAIL", "CREATE_USER", "UPDATE_USER",
                 "RESET_PASSWORD", "LOCK_USER", "UNLOCK_USER", "DELETE_USER",
                 "UPLOAD_DOC", "DELETE_DOC", "ACCESS_DOC",
                 "CREATE_API_KEY", "REVOKE_API_KEY", "DELETE_API_KEY", "API_KEY_AUTH"],
                key="audit_action")

            params = {}
            if action_filter != "(tất cả)":
                params["action"] = action_filter

            try:
                resp = _api_get(f"{ADMIN_AUDIT_URL}/{chosen_date}", params=params)
                entries = resp.json() if resp.ok else []
            except Exception:
                entries = []

            if not entries:
                st.info("Không có bản ghi nào.")
            else:
                st.caption(f"{len(entries)} bản ghi")
                for e in reversed(entries):
                    st.markdown(
                        f"`{e['timestamp']}`  **{e['action']}**  "
                        f"actor: `{e['actor']}`"
                        + (f"  →  `{e['target']}`" if e.get("target") else "")
                        + (f"  _{e['detail']}_" if e.get("detail") else "")
                    )

    # ── Đổi mật khẩu (admin tự đổi) ──────────────────────────────────────────
    with admin_tab5:
        st.markdown("#### Đổi mật khẩu của bạn")
        with st.form("chg_pwd_form"):
            cur_pwd = st.text_input("Mật khẩu hiện tại", type="password")
            new_pwd = st.text_input("Mật khẩu mới (≥8 ký tự)", type="password")
            new_pwd2 = st.text_input("Xác nhận mật khẩu mới", type="password")
            chg_btn = st.form_submit_button("Đổi mật khẩu", use_container_width=True)

        if chg_btn:
            if new_pwd != new_pwd2:
                st.error("Mật khẩu xác nhận không khớp.")
            elif len(new_pwd) < 8:
                st.error("Mật khẩu mới phải có ít nhất 8 ký tự.")
            else:
                try:
                    resp = _api_post(CHANGE_PWD_URL,
                                     json={"current_password": cur_pwd, "new_password": new_pwd})
                    if resp.ok:
                        st.success("Đổi mật khẩu thành công!")
                    else:
                        st.error(_safe_detail(resp))
                except Exception as e:
                    st.error(f"Lỗi: {e}")


# ---------------------------------------------------------------------------
# Tab đổi mật khẩu (user thường)
# ---------------------------------------------------------------------------

def render_change_password_tab() -> None:
    st.subheader("Đổi mật khẩu")
    with st.form("user_chg_pwd"):
        cur  = st.text_input("Mật khẩu hiện tại", type="password")
        new1 = st.text_input("Mật khẩu mới (≥8 ký tự)", type="password")
        new2 = st.text_input("Xác nhận", type="password")
        btn  = st.form_submit_button("Đổi mật khẩu", use_container_width=True)

    if btn:
        if new1 != new2:
            st.error("Mật khẩu xác nhận không khớp.")
        elif len(new1) < 8:
            st.error("Mật khẩu mới phải có ít nhất 8 ký tự.")
        else:
            try:
                resp = _api_post(CHANGE_PWD_URL,
                                 json={"current_password": cur, "new_password": new1})
                if resp.ok:
                    st.success("Đổi mật khẩu thành công!")
                else:
                    st.error(_safe_detail(resp))
            except Exception as e:
                st.error(f"Lỗi: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(
        page_title="LLM Privacy Gateway",
        page_icon="🔒",
        layout="wide",
    )
    _init_state()

    if not _is_logged_in():
        if st.session_state.get("show_register"):
            render_register_form()
        else:
            render_login_page()
        return

    # Header
    user = st.session_state.user or {}
    col_title, col_user = st.columns([5, 2])
    with col_title:
        st.title("🔒 LLM Privacy Gateway")
        st.caption("Dữ liệu nhạy cảm được tự động mask trước khi gửi lên AI.")
    with col_user:
        st.markdown(f"**{user.get('full_name', '')}**  `{user.get('email', '')}`")
        st.caption(f"Role: **{user.get('role', '')}**" + ("  |  👑 Admin" if _is_admin() else ""))
        if st.button("Đăng xuất", use_container_width=True):
            for k in ["token", "user", "messages", "session_id"]:
                st.session_state[k] = None if k != "messages" else []
            st.session_state.session_id = str(uuid.uuid4())[:8]
            st.rerun()

    st.divider()

    # Tabs — admin có thêm tab Admin Dashboard
    if _is_admin():
        tab_chat, tab_kb, tab_admin = st.tabs(["💬 Chat", "📚 Knowledge Base", "⚙️ Admin"])
        with tab_chat:
            render_chat_tab()
        with tab_kb:
            render_kb_tab()
        with tab_admin:
            render_admin_tab()
    else:
        tab_chat, tab_kb, tab_pwd = st.tabs(
            ["💬 Chat", "📚 Knowledge Base", "🔑 Đổi mật khẩu"]
        )
        with tab_chat:
            render_chat_tab()
        with tab_kb:
            render_kb_tab()
        with tab_pwd:
            render_change_password_tab()


if __name__ == "__main__":
    main()
