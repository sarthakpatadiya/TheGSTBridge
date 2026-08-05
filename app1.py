import io
import os
import re
import secrets
import sqlite3
from datetime import datetime

import pandas as pd
import streamlit as st
from cryptography.fernet import Fernet, InvalidToken

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="The GST Bridge",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

NAVY = "#08306b"
NAVY_LIGHT = "#0f4c92"
GOLD = "#d4af37"
GOLD_LIGHT = "#f1d980"

# ============================================================
# STORAGE LOCATIONS
# ============================================================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "gst_bridge_data.db")
KEY_PATH = os.path.join(APP_DIR, "secret.key")

# First-run bootstrap developer account.
# Log in with this once, then go to Profile (or Developer Options -> Add User)
# and set your own password. Do this immediately after your first deployment.
DEFAULT_DEVELOPER_USERNAME = "sarthak"
DEFAULT_DEVELOPER_PASSWORD = "ChangeMe@2026"


# ============================================================
# ENCRYPTION (passwords are stored encrypted, not hashed, so the
# developer can view existing users' passwords in Developer Options)
# ============================================================
def _get_fernet():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
    return Fernet(key)


_FERNET = _get_fernet()


def encrypt_password(password):
    return _FERNET.encrypt(password.encode("utf-8")).decode("utf-8")


def decrypt_password(enc_password):
    try:
        return _FERNET.decrypt(enc_password.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        return "<unreadable>"


# ============================================================
# DATABASE (users, sessions, feedback)
# ============================================================
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_enc TEXT NOT NULL,
            is_developer INTEGER NOT NULL DEFAULT 0,
            active_token TEXT
        )"""
    )
    cur.execute(
        """CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"""
    )
    conn.commit()
    conn.close()
    if count_developers() == 0:
        create_or_update_user(DEFAULT_DEVELOPER_USERNAME, DEFAULT_DEVELOPER_PASSWORD, is_developer=True)


def username_exists(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (username.strip(),))
    row = cur.fetchone()
    conn.close()
    return row is not None


def create_or_update_user(username, password, is_developer=False):
    username = username.strip()
    enc = encrypt_password(password)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO users (username, password_enc, is_developer, active_token)
           VALUES (?, ?, ?, NULL)
           ON CONFLICT(username) DO UPDATE SET
                password_enc = excluded.password_enc,
                is_developer = excluded.is_developer,
                active_token = NULL""",
        (username, enc, 1 if is_developer else 0),
    )
    conn.commit()
    conn.close()


def update_password_only(username, new_password):
    enc = encrypt_password(new_password)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_enc = ?, active_token = NULL WHERE username = ?", (enc, username))
    conn.commit()
    conn.close()


def rename_user(old_username, new_username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET username = ?, active_token = NULL WHERE username = ?",
        (new_username.strip(), old_username),
    )
    conn.commit()
    conn.close()


def update_developer_flag(username, is_dev):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_developer = ? WHERE username = ?", (1 if is_dev else 0, username))
    conn.commit()
    conn.close()


def delete_user(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def list_users_with_passwords():
    conn = get_conn()
    df = pd.read_sql_query("SELECT username, password_enc, is_developer FROM users ORDER BY username", conn)
    conn.close()
    if df.empty:
        return pd.DataFrame(columns=["User ID", "Password", "Developer Access"])
    df["Password"] = df["password_enc"].apply(decrypt_password)
    df["Developer Access"] = df["is_developer"].map({1: "Yes", 0: "No"})
    df = df.rename(columns={"username": "User ID"})
    return df[["User ID", "Password", "Developer Access"]]


def count_developers():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE is_developer = 1")
    n = cur.fetchone()[0]
    conn.close()
    return n


def verify_user(username, password):
    if not username or not password:
        return False, False
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password_enc, is_developer FROM users WHERE username = ?", (username.strip(),))
    row = cur.fetchone()
    conn.close()
    if row is None:
        return False, False
    enc, is_developer = row
    stored_password = decrypt_password(enc)
    if stored_password != "<unreadable>" and secrets.compare_digest(password, stored_password):
        return True, bool(is_developer)
    return False, False


def set_active_token(username, token):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET active_token = ? WHERE username = ?", (token, username))
    conn.commit()
    conn.close()


def get_active_token(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT active_token FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def add_feedback(username, message):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO feedback (username, message, created_at) VALUES (?, ?, ?)",
        (username, message, datetime.now().strftime("%d-%m-%Y %H:%M")),
    )
    conn.commit()
    conn.close()


def list_feedback():
    conn = get_conn()
    df = pd.read_sql_query("SELECT username, message, created_at FROM feedback ORDER BY id DESC", conn)
    conn.close()
    return df


init_db()

# ============================================================
# SESSION STATE DEFAULTS
# ============================================================
_defaults = {
    "logged_in": False,
    "username": None,
    "is_developer": False,
    "session_token": None,
    "uploader_key": 0,
    "reconciliation_done": False,
    "result_df": None,
    "books_count": 0,
    "gstr2b_count": 0,
    "excluded_zero_count": 0,
    "nav": "Reconciler",
    "feedback_box_key": 0,
    "show_add_user_form": False,
}
for _k, _v in _defaults.items():
    st.session_state.setdefault(_k, _v)

# ============================================================
# ENFORCE SINGLE ACTIVE SESSION PER USER
# ============================================================
if st.session_state.logged_in:
    current_db_token = get_active_token(st.session_state.username)
    if current_db_token != st.session_state.session_token:
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.is_developer = False
        st.session_state.session_token = None
        st.session_state.nav = "Reconciler"
        st.warning("You've been logged out because this account was signed in from another location.")

# ============================================================
# CSS THEME
# ============================================================
st.markdown(
    f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;800;900&family=Inter:wght@400;500;600;700&display=swap');

        .stApp {{
            background: linear-gradient(180deg, #f7f8fb 0%, #eef1f7 100%);
            font-family: 'Inter', sans-serif;
        }}

        #MainMenu {{visibility: hidden;}}
        header[data-testid="stHeader"] {{background: transparent;}}
        footer {{visibility: hidden;}}

        .block-container {{
            padding-top: 1rem;
            padding-bottom: 6rem;
            max-width: 1200px;
        }}

        /* Best-effort restyle of Streamlit's built-in sidebar toggle so it
           reads as a simple icon in the top-left corner. The sidebar itself
           already starts closed (initial_sidebar_state="collapsed") and only
           opens when this icon is clicked -- that behaviour is native to
           Streamlit. The exact icon markup can shift between Streamlit
           versions, so treat this block as cosmetic only. */
        [data-testid="collapsedControl"] {{
            background: {NAVY};
            border-radius: 8px;
            border: 1px solid {GOLD};
        }}
        [data-testid="collapsedControl"] svg {{
            fill: {GOLD} !important;
        }}

        .hero-banner {{
            background: linear-gradient(135deg, {NAVY} 0%, {NAVY_LIGHT} 100%);
            border-radius: 18px;
            padding: 2.4rem 2.2rem 2rem 2.2rem;
            margin-bottom: 1.8rem;
            box-shadow: 0 10px 30px rgba(8, 48, 107, 0.35);
            border: 1px solid {GOLD};
            position: relative;
            overflow: hidden;
        }}
        .hero-banner::before {{
            content: "";
            position: absolute;
            top: -60px;
            right: -60px;
            width: 220px;
            height: 220px;
            background: radial-gradient(circle, rgba(212,175,55,0.25) 0%, rgba(212,175,55,0) 70%);
        }}
        .hero-title {{
            font-family: 'Playfair Display', serif;
            font-weight: 900;
            font-size: 3.1rem;
            letter-spacing: 1px;
            margin: 0;
            background: linear-gradient(90deg, {GOLD_LIGHT} 0%, {GOLD} 55%, #b8860b 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 4px 18px rgba(0,0,0,0.35);
            line-height: 1.15;
        }}
        .hero-subtitle {{
            color: #dfe7f5;
            font-size: 0.95rem;
            font-weight: 500;
            margin-top: 0.4rem;
            letter-spacing: 0.4px;
        }}
        .hero-tagline {{
            color: {GOLD_LIGHT};
            font-size: 1.02rem;
            margin-top: 1rem;
            font-style: italic;
            font-weight: 400;
        }}

        .section-card {{
            background: #ffffff;
            border-radius: 14px;
            padding: 1.4rem 1.6rem;
            margin-bottom: 1.3rem;
            border-left: 5px solid {GOLD};
            box-shadow: 0 4px 16px rgba(8, 48, 107, 0.08);
        }}
        .section-title {{
            color: {NAVY};
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 0.6rem;
        }}

        .metric-card {{
            background: linear-gradient(135deg, {NAVY} 0%, {NAVY_LIGHT} 100%);
            border-radius: 14px;
            padding: 1.1rem 1rem;
            text-align: center;
            border: 1px solid {GOLD};
            box-shadow: 0 6px 18px rgba(8,48,107,0.18);
        }}
        .metric-value {{
            color: {GOLD};
            font-size: 2rem;
            font-weight: 800;
        }}
        .metric-label {{
            color: #dfe7f5;
            font-size: 0.85rem;
            margin-top: 0.2rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .stButton > button, .stDownloadButton > button {{
            background: linear-gradient(135deg, {GOLD} 0%, #c79c2e 100%);
            color: {NAVY};
            font-weight: 700;
            border: none;
            border-radius: 10px;
            padding: 0.6rem 1.4rem;
            box-shadow: 0 4px 12px rgba(212,175,55,0.35);
            transition: all 0.2s ease-in-out;
        }}
        .stButton > button:hover, .stDownloadButton > button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(212,175,55,0.5);
            color: {NAVY};
        }}

        section[data-testid="stSidebar"] {{
            background: linear-gradient(180deg, {NAVY} 0%, #061f45 100%);
        }}
        section[data-testid="stSidebar"] * {{
            color: #eef1f7 !important;
        }}
        section[data-testid="stSidebar"] .stSelectbox label,
        section[data-testid="stSidebar"] .stSlider label,
        section[data-testid="stSidebar"] .stRadio label,
        section[data-testid="stSidebar"] .stTextInput label {{
            color: {GOLD_LIGHT} !important;
            font-weight: 600;
        }}

        .stTabs [data-baseweb="tab-list"] {{
            gap: 6px;
        }}
        .stTabs [data-baseweb="tab"] {{
            background-color: #eef1f7;
            border-radius: 14px 14px 6px 6px;
            padding: 0.5rem 1.2rem;
            color: {NAVY};
            font-weight: 600;
        }}
        .stTabs [aria-selected="true"] {{
            background-color: {NAVY} !important;
            color: {GOLD} !important;
        }}

        thead tr th {{
            background-color: {NAVY} !important;
            color: {GOLD} !important;
        }}

        .badge-missing {{
            background: #fde8e8;
            color: #b3261e;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 0.78rem;
            font-weight: 700;
        }}
        .badge-ok {{
            background: #e6f4ea;
            color: #1e7b34;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 0.78rem;
            font-weight: 700;
        }}

        /* ---------- FORMS (applies to every st.form in the app) ---------- */
        [data-testid="stForm"] {{
            background-color: #ffffff !important;
            border: 1px solid {GOLD} !important;
            border-radius: 14px !important;
            padding: 1.8rem 1.8rem 1.2rem 1.8rem !important;
            box-shadow: 0 10px 28px rgba(8, 48, 107, 0.20) !important;
        }}
        .form-title {{
            color: {NAVY};
            font-size: 1.35rem;
            font-weight: 800;
            text-align: center;
            margin-bottom: 0.3rem;
        }}
        .form-subtitle {{
            color: #666;
            font-size: 0.9rem;
            text-align: center;
            margin-bottom: 1rem;
        }}

        /* ---------- Scoped: blue Log In button only ---------- */
        .login-btn-scope [data-testid="stFormSubmitButton"] button,
        .login-btn-scope .stButton > button {{
            background: linear-gradient(135deg, #1a73e8 0%, #0d47a1 100%) !important;
            color: #ffffff !important;
            box-shadow: 0 4px 12px rgba(13,71,161,0.35) !important;
        }}
        .login-btn-scope [data-testid="stFormSubmitButton"] button:hover,
        .login-btn-scope .stButton > button:hover {{
            background: linear-gradient(135deg, #2b83f6 0%, #114db8 100%) !important;
            color: #ffffff !important;
        }}

        /* ---------- Scoped: Criteria filter styled like an Excel-style dropdown ---------- */
        .criteria-filter-scope div[data-baseweb="select"] > div {{
            background-color: #ffffff !important;
            border: 1px solid {NAVY} !important;
            border-radius: 6px !important;
        }}

        /* ---------- Sidebar nav buttons (no radio dots; current page shown as muted) ---------- */
        section[data-testid="stSidebar"] .nav-btn-scope .stButton > button:disabled {{
            opacity: 0.55 !important;
            color: {NAVY} !important;
            background: {GOLD_LIGHT} !important;
        }}

        .footer-bar {{
            position: fixed;
            left: 0;
            bottom: 0;
            width: 100%;
            background: linear-gradient(90deg, {NAVY} 0%, {NAVY_LIGHT} 100%);
            color: {GOLD};
            text-align: center;
            padding: 0.55rem 0;
            font-weight: 600;
            letter-spacing: 0.4px;
            border-top: 2px solid {GOLD};
            z-index: 999;
            font-size: 0.85rem;
        }}
    </style>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# HERO HEADER (shown on every page, logged in or not)
# ============================================================
st.markdown(
    f"""
    <div class="hero-banner">
        <div class="hero-title">The GST Bridge</div>
        <div class="hero-subtitle">created by Sarthak Patadiya</div>
        <div class="hero-tagline">Books vs GSTR-2B &mdash; find every missing invoice, and know exactly why it's missing.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# HELPERS (reconciliation logic - unchanged core behaviour)
# ============================================================

def normalize_invoice_no(x):
    if pd.isna(x):
        return ""
    s = str(x).strip().upper()
    s = re.sub(r"[^A-Z0-9]", "", s)
    s = s.lstrip("0") if s.isdigit() else s
    return s


def to_number(x):
    try:
        if pd.isna(x):
            return None
        if isinstance(x, str):
            x = x.replace(",", "").strip()
            if x == "":
                return None
        return round(float(x), 2)
    except (ValueError, TypeError):
        return None


def to_date(x):
    if pd.isna(x):
        return None
    if isinstance(x, (pd.Timestamp, datetime)):
        return pd.Timestamp(x)
    try:
        return pd.to_datetime(x, dayfirst=True, errors="coerce")
    except Exception:
        return None


def close(a, b, tol):
    if a is None or b is None:
        return False
    return abs(a - b) <= tol


def val_or_zero(x):
    return 0 if x is None else x


def compute_match_flags(b, cand, tolerance, tax_criteria):
    """Returns an ordered list of (field_name, is_matching) tuples used for the
    match decision. Taxable Value is always checked; the tax fields checked
    depend on tax_criteria -- either CGST + SGST, or IGST, never both."""
    flags = [("Taxable Value", close(b["Taxable Value"], cand["Taxable Value"], tolerance))]
    if tax_criteria == "IGST":
        flags.append(("IGST", close(b["IGST"], cand["IGST"], tolerance)))
    else:
        flags.append(("CGST", close(b["CGST"], cand["CGST"], tolerance)))
        flags.append(("SGST", close(b["SGST"], cand["SGST"], tolerance)))
    return flags


def categorize_reason(reason):
    if reason.startswith("Not found in 2B"):
        return "Completely Missing"
    if "possible invoice number typo" in reason:
        return "Possible Invoice Number Typo"
    if reason.startswith("Invoice No. matches 2B"):
        return "Amount Mismatch"
    return "Other"


# ============================================================
# LOGIN-ONLY VIEW (rendered when nobody is logged in)
# ============================================================
def render_login_page():
    st.markdown('<div class="login-btn-scope" style="max-width:440px; margin:0 auto;">', unsafe_allow_html=True)
    with st.form("login_form"):
        st.markdown('<div class="form-title">Log In</div>', unsafe_allow_html=True)
        st.markdown('<div class="form-subtitle">Please log in to use The GST Bridge.</div>', unsafe_allow_html=True)
        login_username = st.text_input("User ID")
        login_password = st.text_input("Password", type="password")
        login_submit = st.form_submit_button("Log In", use_container_width=True)

    if login_submit:
        ok, is_dev = verify_user(login_username, login_password)
        if ok:
            token = secrets.token_hex(16)
            set_active_token(login_username.strip(), token)
            st.session_state.logged_in = True
            st.session_state.username = login_username.strip()
            st.session_state.is_developer = is_dev
            st.session_state.session_token = token
            st.session_state.nav = "Reconciler"
            st.rerun()
        else:
            st.error("Invalid User ID or Password.")

    with st.expander("Forgot password?"):
        st.write("Please contact the developer for your password information.")

    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# SIDEBAR (only rendered once logged in)
# ============================================================
def render_sidebar():
    with st.sidebar:
        st.markdown("### Account")
        st.success(f"Logged in as: {st.session_state.username}")
        if st.button("Log Out", use_container_width=True):
            set_active_token(st.session_state.username, None)
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.is_developer = False
            st.session_state.session_token = None
            st.session_state.nav = "Reconciler"
            st.rerun()

        st.markdown("---")

        st.markdown("### Navigate")
        nav_options = ["Reconciler", "Feedback", "Profile"]
        if st.session_state.is_developer:
            nav_options.append("Developer Options")

        st.markdown('<div class="nav-btn-scope">', unsafe_allow_html=True)
        for option in nav_options:
            is_current = st.session_state.nav == option
            if st.button(option, key=f"nav_btn_{option}", use_container_width=True, disabled=is_current):
                st.session_state.nav = option
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("---")

        tolerance = 1.0
        tax_criteria = "CGST + SGST"
        if st.session_state.nav == "Reconciler":
            st.markdown("### Settings")
            tolerance = st.slider(
                "Amount matching tolerance (Rs.)",
                min_value=0.0, max_value=100.0, value=1.0, step=0.5,
                help="Two amounts are treated as matching if the difference is within this value. "
                     "Useful for paisa-level rounding differences.",
            )
            tax_criteria = st.radio(
                "Tax matching criteria",
                ["CGST + SGST", "IGST"],
                index=0,
                help="Choose whether invoices should be matched using CGST + SGST (intra-state) "
                     "or using IGST (inter-state). Only one of the two is compared, not both.",
            )

        st.markdown("---")
        st.caption("Built for CA / articleship reconciliation workflows.")

        return tolerance, tax_criteria


# ============================================================
# PAGE: FEEDBACK
# ============================================================
def render_feedback_page():
    st.markdown(
        """
        <div class="section-card">
            <div class="section-title">Feedback</div>
            <p style="color:#555; margin-top:-8px;">Found a bug, or have a suggestion? Let us know below.</p>
        """,
        unsafe_allow_html=True,
    )
    fb_key = f"feedback_text_{st.session_state.feedback_box_key}"
    feedback_text = st.text_area("Your feedback", key=fb_key, height=120)
    if st.button("Submit Feedback"):
        if feedback_text and feedback_text.strip():
            add_feedback(st.session_state.username, feedback_text.strip())
            st.session_state.feedback_box_key += 1
            st.success("Thank you for your feedback.")
            st.rerun()
        else:
            st.warning("Please write something before submitting.")
    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# PAGE: PROFILE
# ============================================================
def render_profile_page():
    st.markdown(
        """
        <div class="section-card">
            <div class="section-title">Profile</div>
        """,
        unsafe_allow_html=True,
    )
    st.write(f"Current User ID: **{st.session_state.username}**")
    st.caption("Leave a field blank to keep it unchanged. Your current password is always required to confirm any change.")

    with st.form("profile_form"):
        current_pw = st.text_input("Current Password", type="password")
        new_username = st.text_input("New User ID (optional)")
        new_password = st.text_input("New Password (optional)", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")
        submitted = st.form_submit_button("Update Credentials")

    if submitted:
        ok, _ = verify_user(st.session_state.username, current_pw)
        if not ok:
            st.error("Current password is incorrect.")
        else:
            errors = []
            do_rename = False
            do_password = False
            target_username = st.session_state.username

            if new_username.strip() and new_username.strip() != st.session_state.username:
                if username_exists(new_username.strip()):
                    errors.append("That User ID is already taken.")
                else:
                    do_rename = True
                    target_username = new_username.strip()

            if new_password or confirm_password:
                if new_password != confirm_password:
                    errors.append("New password and confirmation do not match.")
                else:
                    do_password = True

            if errors:
                for e in errors:
                    st.error(e)
            elif not do_rename and not do_password:
                st.info("No changes were made.")
            else:
                if do_rename:
                    rename_user(st.session_state.username, target_username)
                if do_password:
                    update_password_only(target_username, new_password)
                st.success("Credentials updated. Please log in again with your new details.")
                st.session_state.logged_in = False
                st.session_state.username = None
                st.session_state.is_developer = False
                st.session_state.session_token = None
                st.session_state.nav = "Reconciler"
                st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# PAGE: DEVELOPER OPTIONS
# ============================================================
def render_developer_options():
    st.markdown(
        """
        <div class="section-card">
            <div class="section-title">Developer Options</div>
        """,
        unsafe_allow_html=True,
    )

    tab1, tab2 = st.tabs(["Manage Users", "Feedback Inbox"])

    with tab1:
        st.markdown("**Existing Users**")
        users_df = list_users_with_passwords()
        st.dataframe(users_df, use_container_width=True, height=220)
        st.caption("Passwords are stored encrypted and are decrypted here only for your reference as the developer.")

        if st.button("Add User"):
            st.session_state.show_add_user_form = True

        if st.session_state.show_add_user_form:
            with st.form("add_user_form", clear_on_submit=True):
                add_username = st.text_input("User ID")
                add_password = st.text_input("Password", type="password")
                add_is_dev = st.checkbox("Grant Developer Access")
                add_submit = st.form_submit_button("Create User")
            if add_submit:
                if add_username.strip() and add_password:
                    already_existed = username_exists(add_username.strip())
                    create_or_update_user(add_username, add_password, is_developer=add_is_dev)
                    if already_existed:
                        st.success(f"User '{add_username.strip()}' updated successfully.")
                    else:
                        st.success(f"User '{add_username.strip()}' added successfully.")
                    st.session_state.show_add_user_form = False
                    st.rerun()
                else:
                    st.warning("Please provide both a User ID and a Password.")

        st.markdown("---")
        st.markdown("**Change Access Level**")
        if len(users_df) > 0:
            access_username = st.selectbox("Select user", users_df["User ID"].tolist(), key="access_user_select")
            current_is_dev = users_df.loc[users_df["User ID"] == access_username, "Developer Access"].iloc[0] == "Yes"
            new_is_dev = st.checkbox("Developer Access", value=current_is_dev, key="access_user_checkbox")
            if st.button("Update Access Level"):
                if current_is_dev and not new_is_dev and count_developers() <= 1:
                    st.error("Cannot revoke access from the last remaining Developer account.")
                else:
                    update_developer_flag(access_username, new_is_dev)
                    st.success(f"Access level updated for '{access_username}'.")
                    st.rerun()

        st.markdown("---")
        st.markdown("**Delete User**")
        if len(users_df) > 0:
            del_username = st.selectbox("Select user to delete", users_df["User ID"].tolist(), key="del_user_select")
            if st.button("Delete Selected User"):
                if del_username == st.session_state.username:
                    st.error("You cannot delete the account you are currently logged in with.")
                else:
                    is_target_dev = users_df.loc[users_df["User ID"] == del_username, "Developer Access"].iloc[0] == "Yes"
                    if is_target_dev and count_developers() <= 1:
                        st.error("Cannot delete the last remaining Developer account.")
                    else:
                        delete_user(del_username)
                        st.success(f"User '{del_username}' deleted.")
                        st.rerun()

    with tab2:
        st.markdown("**Feedback submitted by users**")
        fb_df = list_feedback()
        if fb_df.empty:
            st.info("No feedback submitted yet.")
        else:
            st.dataframe(fb_df, use_container_width=True, height=400)

    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# PAGE: RECONCILER
# ============================================================
def render_reconciler(tolerance, tax_criteria):
    st.markdown(
        """
        <div class="section-card">
            <div class="section-title">Step 1 - Upload Workbook</div>
        """,
        unsafe_allow_html=True,
    )
    uploaded_file = st.file_uploader(
        "Upload one Excel workbook containing both sheets (Books data + GSTR-2B data)",
        type=["xlsx", "xls"],
        key=f"uploaded_file_{st.session_state.uploader_key}",
    )
    st.markdown("</div>", unsafe_allow_html=True)

    if uploaded_file is None:
        if st.session_state.reconciliation_done:
            _render_results_section()
        else:
            st.info("Upload your workbook to get started. It should have one sheet for Books entries and one for GSTR-2B entries.")
        return

    try:
        xls = pd.ExcelFile(uploaded_file)
    except Exception as e:
        st.error(f"Could not read this file: {e}")
        return

    sheet_names = xls.sheet_names

    st.markdown(
        """
        <div class="section-card">
            <div class="section-title">Step 2 - Identify Sheets</div>
        """,
        unsafe_allow_html=True,
    )
    c1, c2 = st.columns(2)
    with c1:
        books_sheet = st.selectbox("Which sheet is your BOOKS data?", sheet_names, index=0, key="books_sheet")
    with c2:
        default_2b_idx = 1 if len(sheet_names) > 1 else 0
        gstr2b_sheet = st.selectbox("Which sheet is your GSTR-2B data?", sheet_names, index=default_2b_idx, key="gstr2b_sheet")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class="section-card">
            <div class="section-title">Step 3 - Confirm Header Row</div>
            <p style="color:#555; margin-top:-8px;">Many Books/2B exports have a title or blank rows above the actual column headers. Preview each sheet below and tell the tool which row number holds the real column headers.</p>
        """,
        unsafe_allow_html=True,
    )

    preview_rows = 8
    hc1, hc2 = st.columns(2)

    with hc1:
        st.markdown(f"**Books sheet - `{books_sheet}` (raw preview, no header assumed)**")
        raw_preview_books = xls.parse(books_sheet, header=None, nrows=preview_rows)
        raw_preview_books.index = [f"Row {i+1}" for i in raw_preview_books.index]
        st.dataframe(raw_preview_books, use_container_width=True, height=230)
        books_header_row = st.number_input(
            "Header row number (Books)", min_value=1, max_value=preview_rows, value=1, step=1, key="books_header_row"
        )

    with hc2:
        st.markdown(f"**GSTR-2B sheet - `{gstr2b_sheet}` (raw preview, no header assumed)**")
        raw_preview_2b = xls.parse(gstr2b_sheet, header=None, nrows=preview_rows)
        raw_preview_2b.index = [f"Row {i+1}" for i in raw_preview_2b.index]
        st.dataframe(raw_preview_2b, use_container_width=True, height=230)
        gstr2b_header_row = st.number_input(
            "Header row number (2B)", min_value=1, max_value=preview_rows, value=1, step=1, key="gstr2b_header_row"
        )

    st.markdown("</div>", unsafe_allow_html=True)

    df_books_raw = xls.parse(books_sheet, header=books_header_row - 1)
    df_2b_raw = xls.parse(gstr2b_sheet, header=gstr2b_header_row - 1)
    df_books_raw = df_books_raw.dropna(how="all")
    df_2b_raw = df_2b_raw.dropna(how="all")

    st.markdown(
        """
        <div class="section-card">
            <div class="section-title">Step 4 - Map Columns</div>
            <p style="color:#555; margin-top:-8px;">Tell the tool which column in each sheet holds each field.</p>
        """,
        unsafe_allow_html=True,
    )

    fields = ["Invoice No", "Invoice Date", "Taxable Value", "CGST", "SGST", "IGST"]

    def guess(colnames, keywords):
        for kw in keywords:
            for c in colnames:
                if kw.lower() in str(c).lower():
                    return c
        return colnames[0] if len(colnames) else None

    guess_map = {
        "Invoice No": ["invoice no", "inv no", "invoice number", "bill no", "document no"],
        "Invoice Date": ["invoice date", "inv date", "date", "bill date"],
        "Taxable Value": ["taxable value", "taxable amt", "taxable amount", "assessable"],
        "CGST": ["cgst"],
        "SGST": ["sgst"],
        "IGST": ["igst"],
    }

    colA, colB = st.columns(2)
    books_map = {}
    gstr2b_map = {}

    with colA:
        st.markdown(f"**Books sheet - `{books_sheet}`**")
        for f in fields:
            opts = list(df_books_raw.columns)
            default = guess(opts, guess_map[f])
            idx = opts.index(default) if default in opts else 0
            books_map[f] = st.selectbox(f"{f} (Books)", opts, index=idx, key=f"books_{f}")

    with colB:
        st.markdown(f"**GSTR-2B sheet - `{gstr2b_sheet}`**")
        for f in fields:
            opts = list(df_2b_raw.columns)
            default = guess(opts, guess_map[f])
            idx = opts.index(default) if default in opts else 0
            gstr2b_map[f] = st.selectbox(f"{f} (2B)", opts, index=idx, key=f"2b_{f}")

    st.markdown("</div>", unsafe_allow_html=True)

    run = st.button("Run Reconciliation", use_container_width=True)

    if run:
        _run_reconciliation(df_books_raw, df_2b_raw, books_map, gstr2b_map, tolerance, tax_criteria)

    if st.session_state.reconciliation_done:
        _render_results_section()


def _build_clean(df_raw, colmap):
    out = pd.DataFrame()
    out["Invoice No Raw"] = df_raw[colmap["Invoice No"]]
    out["Invoice No Norm"] = out["Invoice No Raw"].apply(normalize_invoice_no)
    out["Invoice Date"] = df_raw[colmap["Invoice Date"]].apply(to_date)
    out["Year"] = out["Invoice Date"].apply(lambda d: d.year if pd.notna(d) else None)
    out["Taxable Value"] = df_raw[colmap["Taxable Value"]].apply(to_number)
    out["CGST"] = df_raw[colmap["CGST"]].apply(to_number)
    out["SGST"] = df_raw[colmap["SGST"]].apply(to_number)
    out["IGST"] = df_raw[colmap["IGST"]].apply(to_number)
    out = out[out["Invoice No Raw"].notna()]
    return out


def _run_reconciliation(df_books_raw, df_2b_raw, books_map, gstr2b_map, tolerance, tax_criteria):
    books = _build_clean(df_books_raw, books_map)
    gstr2b = _build_clean(df_2b_raw, gstr2b_map)

    # Exclude Books invoices where CGST, SGST and IGST are all zero (or blank).
    keep_mask = books.apply(
        lambda r: not (val_or_zero(r["CGST"]) == 0 and val_or_zero(r["SGST"]) == 0 and val_or_zero(r["IGST"]) == 0),
        axis=1,
    )
    excluded_zero_count = int((~keep_mask).sum())
    books = books[keep_mask].reset_index(drop=True)

    # Build mutable 2B records so a matched row can be "consumed" and not reused.
    gstr2b_records = gstr2b.reset_index(drop=True).to_dict("records")
    for rec in gstr2b_records:
        rec["_used"] = False

    norm_to_indices = {}
    for i, rec in enumerate(gstr2b_records):
        norm_to_indices.setdefault(rec["Invoice No Norm"], []).append(i)

    criteria_desc = "Taxable Value/IGST" if tax_criteria == "IGST" else "Taxable Value/CGST/SGST"

    missing_rows = []

    for _, b in books.iterrows():
        inv_norm = b["Invoice No Norm"]
        candidate_idxs = [i for i in norm_to_indices.get(inv_norm, []) if not gstr2b_records[i]["_used"]]

        matched_clean = False
        reason = None

        if inv_norm and candidate_idxs:
            best_idx = None
            best_score = -1
            best_flags = None
            for i in candidate_idxs:
                cand = gstr2b_records[i]
                flags = compute_match_flags(b, cand, tolerance, tax_criteria)
                score = sum(1 for _, ok in flags if ok)
                if score > best_score:
                    best_score = score
                    best_idx = i
                    best_flags = flags

            gstr2b_records[best_idx]["_used"] = True

            if all(ok for _, ok in best_flags):
                matched_clean = True
            else:
                mismatch_details = [name for name, ok in best_flags if not ok]
                reason = "Invoice No. matches 2B, but mismatch in: " + ", ".join(mismatch_details)
        else:
            amt_match_idx = None
            for i, cand in enumerate(gstr2b_records):
                if cand["_used"]:
                    continue
                flags = compute_match_flags(b, cand, tolerance, tax_criteria)
                if all(ok for _, ok in flags):
                    amt_match_idx = i
                    break

            if amt_match_idx is not None:
                gstr2b_records[amt_match_idx]["_used"] = True
                matched_invoice_no = gstr2b_records[amt_match_idx]["Invoice No Raw"]
                reason = (
                    f"Invoice No. not found in 2B, but {criteria_desc.replace('/', ' + ')} match "
                    f"2B invoice '{matched_invoice_no}' - possible invoice number typo/mismatch"
                )
            else:
                reason = f"Not found in 2B - no match on Invoice No. or on {criteria_desc} combination"

        if not matched_clean:
            missing_rows.append(
                {
                    "Invoice No": b["Invoice No Raw"],
                    "Invoice Date": b["Invoice Date"].strftime("%d-%m-%Y") if pd.notna(b["Invoice Date"]) else "",
                    "Year": b["Year"],
                    "Taxable Amount": b["Taxable Value"],
                    "CGST Amount": b["CGST"],
                    "SGST Amount": b["SGST"],
                    "IGST Amount": b["IGST"],
                    "Criteria for Missing": reason,
                }
            )

    result_df = pd.DataFrame(missing_rows)
    if not result_df.empty:
        result_df.insert(
            result_df.columns.get_loc("Criteria for Missing"),
            "Criteria Type",
            result_df["Criteria for Missing"].apply(categorize_reason),
        )

    st.session_state.result_df = result_df
    st.session_state.books_count = len(books)
    st.session_state.gstr2b_count = len(gstr2b)
    st.session_state.excluded_zero_count = excluded_zero_count
    st.session_state.reconciliation_done = True


def _render_results_section():
    st.markdown(
        """
        <div class="section-card">
            <div class="section-title">Step 5 - Results</div>
        """,
        unsafe_allow_html=True,
    )

    result_df = st.session_state.result_df

    if st.session_state.excluded_zero_count:
        st.caption(
            f"{st.session_state.excluded_zero_count} Books invoice(s) excluded because CGST, SGST and IGST were all zero."
        )

    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown(
            f"""<div class="metric-card"><div class="metric-value">{st.session_state.books_count}</div>
            <div class="metric-label">Invoices in Books</div></div>""",
            unsafe_allow_html=True,
        )
    with m2:
        st.markdown(
            f"""<div class="metric-card"><div class="metric-value">{st.session_state.gstr2b_count}</div>
            <div class="metric-label">Invoices in 2B</div></div>""",
            unsafe_allow_html=True,
        )
    with m3:
        st.markdown(
            f"""<div class="metric-card"><div class="metric-value">{len(result_df)}</div>
            <div class="metric-label">Missing / Mismatched</div></div>""",
            unsafe_allow_html=True,
        )

    st.write("")

    if result_df.empty:
        st.success("Every invoice in your Books matches an invoice in GSTR-2B within the chosen tolerance. Nothing to reconcile.")
    else:
        st.markdown(f"<span class='badge-missing'>{len(result_df)} invoice(s) need attention</span>", unsafe_allow_html=True)
        st.write("")

        st.markdown("**Filter Results**")
        categories_available = sorted(result_df["Criteria Type"].dropna().unique())

        st.markdown('<div class="criteria-filter-scope">', unsafe_allow_html=True)
        sel_categories = st.multiselect("Filter by Criteria for Missing", categories_available, default=categories_available)
        st.markdown("</div>", unsafe_allow_html=True)

        if sel_categories:
            filtered_df = result_df[result_df["Criteria Type"].isin(sel_categories)]
        else:
            filtered_df = result_df.iloc[0:0]

        st.markdown(f"<span class='badge-missing'>{len(filtered_df)} shown after filters</span>", unsafe_allow_html=True)
        st.write("")
        st.dataframe(filtered_df, use_container_width=True, height=420)

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            sheet_name = "Missing in 2B"
            title_row = 0
            subtitle_row = 1
            header_row = 3
            filtered_df.to_excel(writer, index=False, sheet_name=sheet_name, startrow=header_row)

            workbook = writer.book
            worksheet = writer.sheets[sheet_name]

            n_cols = len(filtered_df.columns)
            n_rows = len(filtered_df)

            title_fmt = workbook.add_format(
                {"bold": True, "font_color": GOLD, "bg_color": NAVY, "font_size": 16, "align": "center", "valign": "vcenter"}
            )
            subtitle_fmt = workbook.add_format(
                {"italic": True, "font_color": "#FFFFFF", "bg_color": NAVY_LIGHT, "font_size": 11, "align": "center", "valign": "vcenter"}
            )
            header_fmt = workbook.add_format(
                {"bold": True, "font_color": GOLD, "bg_color": NAVY, "border": 1, "align": "center", "valign": "vcenter", "text_wrap": True}
            )
            cell_fmt = workbook.add_format({"border": 1, "valign": "vcenter"})
            money_fmt = workbook.add_format({"border": 1, "num_format": "#,##0.00", "valign": "vcenter"})
            footer_fmt = workbook.add_format(
                {"italic": True, "font_color": GOLD, "bg_color": NAVY, "font_size": 10, "align": "center", "valign": "vcenter"}
            )

            last_col = max(n_cols - 1, 0)
            worksheet.merge_range(title_row, 0, title_row, last_col, "Reconciled Invoice Wise GST Data", title_fmt)
            worksheet.merge_range(subtitle_row, 0, subtitle_row, last_col, "Mismatched or missing invoices are as following.", subtitle_fmt)

            for col_num, col_name in enumerate(filtered_df.columns):
                worksheet.write(header_row, col_num, col_name, header_fmt)

            money_cols = {"Taxable Amount", "CGST Amount", "SGST Amount", "IGST Amount"}
            for row_num in range(n_rows):
                for col_num, col_name in enumerate(filtered_df.columns):
                    val = filtered_df.iloc[row_num, col_num]
                    fmt = money_fmt if col_name in money_cols else cell_fmt
                    worksheet.write(header_row + 1 + row_num, col_num, val, fmt)

            footer_row = header_row + n_rows + 2
            worksheet.merge_range(
                footer_row, 0, footer_row, last_col, "Reconciled using The GST Bridge by Sarthak Patadiya", footer_fmt
            )

            if n_rows > 0:
                worksheet.autofilter(header_row, 0, header_row + n_rows, last_col)

            widths = [18, 14, 8, 15, 13, 13, 13, 22, 55]
            for i, w in enumerate(widths[: n_cols]):
                worksheet.set_column(i, i, w)

            worksheet.freeze_panes(header_row + 1, 0)

        output.seek(0)
        st.download_button(
            label="Download Result as Excel",
            data=output,
            file_name=f"GST_Reconciliation_Missing_in_2B_{datetime.now().strftime('%d%m%Y_%H%M')}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )

    st.write("")
    if st.button("Reconcile Another File", use_container_width=True):
        st.session_state.uploader_key += 1
        st.session_state.reconciliation_done = False
        st.session_state.result_df = None
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# ROUTING
# ============================================================
if not st.session_state.logged_in:
    render_login_page()
else:
    tolerance, tax_criteria = render_sidebar()

    if st.session_state.nav == "Reconciler":
        render_reconciler(tolerance, tax_criteria)
    elif st.session_state.nav == "Feedback":
        render_feedback_page()
    elif st.session_state.nav == "Profile":
        render_profile_page()
    elif st.session_state.nav == "Developer Options" and st.session_state.is_developer:
        render_developer_options()
    else:
        st.session_state.nav = "Reconciler"
        render_reconciler(tolerance, tax_criteria)

# ============================================================
# FOOTER
# ============================================================
st.markdown('<div class="footer-bar">Created By Sarthak Patadiya</div>', unsafe_allow_html=True)