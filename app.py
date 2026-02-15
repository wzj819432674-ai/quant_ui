import streamlit as st
import yfinance as yf
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import numpy as np
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import smtplib
import sqlite3
from email.message import EmailMessage
from urllib.error import URLError
from urllib.request import Request, urlopen

st.set_page_config(page_title="Quant Trading UI", layout="wide")

AUTH_DB_PATH = Path(os.getenv("APP_AUTH_DB_PATH", str(Path(__file__).with_name("auth_users.db"))))
PBKDF2_ROUNDS = 210_000


def get_config_value(key: str, default: str = "") -> str:
    try:
        if key in st.secrets:
            return str(st.secrets[key]).strip()
    except Exception:
        pass
    return os.getenv(key, default).strip()


def using_postgres() -> bool:
    return bool(get_config_value("APP_DATABASE_URL"))


def open_sqlite_db() -> sqlite3.Connection:
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def open_postgres_db():
    database_url = get_config_value("APP_DATABASE_URL")
    if not database_url:
        raise RuntimeError("APP_DATABASE_URL is not set.")

    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise SystemExit(
            "Missing dependency: psycopg. Install with: py -m pip install 'psycopg[binary]>=3.2,<4'"
        ) from exc

    return psycopg.connect(database_url, row_factory=dict_row)


def init_auth_db() -> None:
    if using_postgres():
        with open_postgres_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id BIGSERIAL PRIMARY KEY,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                        is_approved BOOLEAN NOT NULL DEFAULT FALSE,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
            conn.commit()
    else:
        with open_sqlite_db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    is_approved INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.commit()


def normalize_username(username: str) -> str:
    return username.strip().lower()


def hash_password(password: str, salt_bytes: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, PBKDF2_ROUNDS)
    return dk.hex()


def send_notification_webhook(payload: dict) -> tuple[bool, str]:
    webhook_url = get_config_value("APP_NOTIFY_WEBHOOK_URL")
    if not webhook_url:
        return False, "webhook not configured"

    data = json.dumps(payload).encode("utf-8")
    req = Request(webhook_url, data=data, headers={"Content-Type": "application/json"})

    try:
        with urlopen(req, timeout=10) as resp:
            status = getattr(resp, "status", 200)
            if 200 <= status < 300:
                return True, "webhook sent"
            return False, f"webhook HTTP {status}"
    except URLError as exc:
        return False, f"webhook failed: {exc.reason}"
    except Exception as exc:
        return False, f"webhook failed: {exc}"


def send_notification_email(subject: str, body: str) -> tuple[bool, str]:
    smtp_host = get_config_value("APP_SMTP_HOST")
    smtp_port_raw = get_config_value("APP_SMTP_PORT", "587")
    smtp_user = get_config_value("APP_SMTP_USER")
    smtp_password = get_config_value("APP_SMTP_PASSWORD")
    notify_to = get_config_value("APP_NOTIFY_EMAIL_TO")
    notify_from = get_config_value("APP_NOTIFY_EMAIL_FROM", smtp_user)
    smtp_use_ssl = get_config_value("APP_SMTP_SSL", "false").lower() in ("1", "true", "yes")
    smtp_use_starttls = get_config_value("APP_SMTP_STARTTLS", "true").lower() in ("1", "true", "yes")

    if not smtp_host or not notify_to or not notify_from:
        return False, "email not configured"

    try:
        smtp_port = int(smtp_port_raw)
    except ValueError:
        return False, "invalid APP_SMTP_PORT"

    msg = EmailMessage()
    msg["From"] = notify_from
    msg["To"] = notify_to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if smtp_use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                if smtp_user:
                    server.login(smtp_user, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                if smtp_use_starttls:
                    server.starttls()
                    server.ehlo()
                if smtp_user:
                    server.login(smtp_user, smtp_password)
                server.send_message(msg)
        return True, "email sent"
    except Exception as exc:
        return False, f"email failed: {exc}"


def notify_admin_new_signup(username: str) -> tuple[bool, str]:
    public_url = get_config_value("APP_PUBLIC_URL")
    login_url = public_url if public_url else "your Streamlit app URL"
    subject = f"[Quant UI] Signup request: {username}"
    body = (
        f"New user signup is pending approval.\n\n"
        f"Username: {username}\n"
        f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}\n\n"
        f"Open app and approve in Admin panel:\n{login_url}\n"
    )
    payload = {
        "event": "signup_pending_approval",
        "username": username,
        "app_url": login_url,
        "time_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "text": f"New Quant UI signup pending approval: {username}",
    }

    results = []
    sent_any = False

    webhook_sent, webhook_msg = send_notification_webhook(payload)
    results.append(webhook_msg)
    sent_any = sent_any or webhook_sent

    email_sent, email_msg = send_notification_email(subject, body)
    results.append(email_msg)
    sent_any = sent_any or email_sent

    return sent_any, "; ".join(results)


def create_user(username: str, password: str, is_admin: bool = False, is_approved: bool = False) -> tuple[bool, str]:
    uname = normalize_username(username)
    if len(uname) < 3:
        return False, "Username must be at least 3 characters."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if get_user(uname) is not None:
        return False, "Username already exists."

    salt = secrets.token_bytes(16)
    pwd_hash = hash_password(password, salt)

    try:
        if using_postgres():
            with open_postgres_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO users (username, password_hash, salt, is_admin, is_approved)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (uname, pwd_hash, salt.hex(), bool(is_admin), bool(is_approved)),
                    )
                conn.commit()
        else:
            with open_sqlite_db() as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, salt, is_admin, is_approved)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (uname, pwd_hash, salt.hex(), int(is_admin), int(is_approved)),
                )
                conn.commit()
        return True, "Account created."
    except Exception as exc:
        return False, f"Failed to create account: {exc}"


def get_user(username: str):
    uname = normalize_username(username)
    if using_postgres():
        with open_postgres_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, password_hash, salt, is_admin, is_approved
                    FROM users
                    WHERE username = %s
                    """,
                    (uname,),
                )
                return cur.fetchone()
    with open_sqlite_db() as conn:
        return conn.execute(
            "SELECT id, username, password_hash, salt, is_admin, is_approved FROM users WHERE username = ?",
            (uname,),
        ).fetchone()


def verify_user(username: str, password: str):
    row = get_user(username)
    if row is None:
        return None

    salt_bytes = bytes.fromhex(row["salt"])
    calc_hash = hash_password(password, salt_bytes)
    if hmac.compare_digest(calc_hash, row["password_hash"]):
        return row
    return None


def set_user_approval(user_id: int, approved: bool) -> None:
    if using_postgres():
        with open_postgres_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET is_approved = %s WHERE id = %s",
                    (bool(approved), user_id),
                )
            conn.commit()
    else:
        with open_sqlite_db() as conn:
            conn.execute("UPDATE users SET is_approved = ? WHERE id = ?", (int(approved), user_id))
            conn.commit()


def list_regular_users():
    if using_postgres():
        with open_postgres_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, is_approved, created_at
                    FROM users
                    WHERE is_admin = FALSE
                    ORDER BY created_at DESC
                    """
                )
                return cur.fetchall()
    with open_sqlite_db() as conn:
        return conn.execute(
            """
            SELECT id, username, is_approved, created_at
            FROM users
            WHERE is_admin = 0
            ORDER BY created_at DESC
            """
        ).fetchall()


def count_pending_users() -> int:
    if using_postgres():
        with open_postgres_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(1) AS c FROM users WHERE is_admin = FALSE AND is_approved = FALSE")
                row = cur.fetchone()
                return int(row["c"])
    with open_sqlite_db() as conn:
        row = conn.execute("SELECT COUNT(1) AS c FROM users WHERE is_admin = 0 AND is_approved = 0").fetchone()
    return int(row["c"])


def ensure_admin_user() -> bool:
    admin_username = get_config_value("APP_ADMIN_USERNAME")
    admin_password = get_config_value("APP_ADMIN_PASSWORD")

    if using_postgres():
        with open_postgres_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(1) AS c FROM users WHERE is_admin = TRUE")
                admin_count = int(cur.fetchone()["c"])
    else:
        with open_sqlite_db() as conn:
            admin_count = int(conn.execute("SELECT COUNT(1) AS c FROM users WHERE is_admin = 1").fetchone()["c"])

    if admin_count > 0:
        return True

    if not admin_username or not admin_password:
        return False

    ok, _ = create_user(admin_username, admin_password, is_admin=True, is_approved=True)
    if ok:
        return True

    row = get_user(admin_username)
    if row is None:
        return False

    salt = secrets.token_bytes(16)
    pwd_hash = hash_password(admin_password, salt)
    if using_postgres():
        with open_postgres_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE users
                    SET password_hash = %s, salt = %s, is_admin = TRUE, is_approved = TRUE
                    WHERE id = %s
                    """,
                    (pwd_hash, salt.hex(), row["id"]),
                )
            conn.commit()
    else:
        with open_sqlite_db() as conn:
            conn.execute(
                """
                UPDATE users
                SET password_hash = ?, salt = ?, is_admin = 1, is_approved = 1
                WHERE id = ?
                """,
                (pwd_hash, salt.hex(), row["id"]),
            )
            conn.commit()
    return True


def init_auth_state() -> None:
    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None
    if "auth_user_id" not in st.session_state:
        st.session_state.auth_user_id = None
    if "auth_is_admin" not in st.session_state:
        st.session_state.auth_is_admin = False
    if "auth_is_approved" not in st.session_state:
        st.session_state.auth_is_approved = False


def logout() -> None:
    st.session_state.auth_user = None
    st.session_state.auth_user_id = None
    st.session_state.auth_is_admin = False
    st.session_state.auth_is_approved = False


def render_admin_panel() -> None:
    with st.sidebar.expander("Admin: Access Control", expanded=False):
        st.caption("Approve or revoke user accounts.")
        st.write(f"Pending approvals: `{count_pending_users()}`")
        users = list_regular_users()
        if not users:
            st.write("No non-admin users yet.")
            return

        for row in users:
            uid = int(row["id"])
            uname = str(row["username"])
            approved = bool(row["is_approved"])
            status = "approved" if approved else "pending"
            st.write(f"{uname} ({status})")
            c1, c2 = st.columns(2)
            if c1.button("Approve", key=f"approve_{uid}", disabled=approved):
                set_user_approval(uid, True)
                st.rerun()
            if c2.button("Revoke", key=f"revoke_{uid}", disabled=not approved):
                set_user_approval(uid, False)
                st.rerun()


def require_auth() -> None:
    init_auth_db()
    init_auth_state()

    if not ensure_admin_user():
        st.title("Initial Admin Setup")
        st.caption("Create the first admin account to secure this app.")
        with st.form("first_admin_setup", clear_on_submit=False):
            admin_user = st.text_input("Admin username")
            admin_pass = st.text_input("Admin password", type="password")
            admin_pass_confirm = st.text_input("Confirm admin password", type="password")
            setup_submit = st.form_submit_button("Create admin account")

        if setup_submit:
            if admin_pass != admin_pass_confirm:
                st.error("Passwords do not match.")
            else:
                ok, message = create_user(
                    admin_user,
                    admin_pass,
                    is_admin=True,
                    is_approved=True,
                )
                if ok:
                    st.success("Admin account created. Please log in.")
                    st.rerun()
                else:
                    st.error(message)

        st.info(
            "For production deployment, set APP_ADMIN_USERNAME and APP_ADMIN_PASSWORD in secrets before going public."
        )
        st.stop()

    if st.session_state.auth_user:
        with st.sidebar:
            st.markdown("### Account")
            st.write(f"User: `{st.session_state.auth_user}`")
            role = "admin" if st.session_state.auth_is_admin else "member"
            st.caption(f"Role: {role}")
            if st.button("Log out"):
                logout()
                st.rerun()

        if st.session_state.auth_is_admin:
            render_admin_panel()
        elif not st.session_state.auth_is_approved:
            st.warning("Your account is pending approval by admin.")
            st.stop()
        return

    st.title("Sign In Required")
    st.caption("Only approved users can access this app.")
    login_tab, signup_tab = st.tabs(["Login", "Create Account"])

    with login_tab:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", key="login_user")
            password = st.text_input("Password", type="password", key="login_pass")
            login_submit = st.form_submit_button("Login")

        if login_submit:
            row = verify_user(username, password)
            if row is None:
                st.error("Invalid username or password.")
            else:
                st.session_state.auth_user = row["username"]
                st.session_state.auth_user_id = int(row["id"])
                st.session_state.auth_is_admin = bool(row["is_admin"])
                st.session_state.auth_is_approved = bool(row["is_approved"])
                st.rerun()

    with signup_tab:
        invite_code_config = get_config_value("APP_INVITE_CODE")
        with st.form("signup_form", clear_on_submit=True):
            new_username = st.text_input("New username")
            new_password = st.text_input("New password", type="password")
            confirm_password = st.text_input("Confirm password", type="password")
            invite_code = st.text_input("Invite code", type="password")
            signup_submit = st.form_submit_button("Create account")

        if signup_submit:
            if new_password != confirm_password:
                st.error("Passwords do not match.")
            elif invite_code_config and invite_code != invite_code_config:
                st.error("Invalid invite code.")
            else:
                ok, message = create_user(new_username, new_password, is_admin=False, is_approved=False)
                if ok:
                    st.success("Account created. Wait for admin approval before logging in.")
                    sent, notify_message = notify_admin_new_signup(normalize_username(new_username))
                    if sent:
                        st.info("Admin notification sent.")
                    else:
                        st.warning(f"Account created, but admin notification was not sent ({notify_message}).")
                else:
                    st.error(message)

        if invite_code_config:
            st.caption("Account creation requires a valid invite code.")
        else:
            st.caption("Invite code is optional because APP_INVITE_CODE is not set.")

    st.stop()


require_auth()
st.title("Quant Trading UI - Phase 5 (Market Regime)")

# ========= Sidebar =========
st.sidebar.header("Filters")
ticker = st.text_input("Enter Ticker", "SPY").upper().strip()

dte_min, dte_max = st.sidebar.slider("DTE Range (days)", 0, 90, (7, 30))
top_n = st.sidebar.slider("Top N candidates", 5, 50, 10)
max_spread_pct = st.sidebar.slider("Max Spread % of Mid", 1, 50, 15)
atm_band_pct = st.sidebar.slider("ATM Band % (|K-S|/S)", 1, 30, 10)

st.sidebar.header("Signal Settings (existing)")
ma_fast = st.sidebar.number_input("Fast MA", min_value=5, max_value=50, value=20, step=1)
ma_slow = st.sidebar.number_input("Slow MA", min_value=20, max_value=200, value=50, step=1)
rsi_len = st.sidebar.number_input("RSI length", min_value=5, max_value=30, value=14, step=1)
breakout_lookback = st.sidebar.number_input("Breakout lookback (days)", min_value=10, max_value=100, value=20, step=5)

st.sidebar.header("Regime Settings (new)")
adx_len = st.sidebar.number_input("ADX length", min_value=7, max_value=50, value=14, step=1)
adx_trend_th = st.sidebar.slider("ADX Trend Threshold", 10, 40, 25)
atr_len = st.sidebar.number_input("ATR length", min_value=7, max_value=50, value=14, step=1)
atr_exp_lookback = st.sidebar.number_input("ATR Expansion Lookback (days)", min_value=10, max_value=80, value=20, step=5)
atr_exp_mult = st.sidebar.slider("ATR Expansion Multiplier", 10, 30, 15) / 10.0  # 1.0~3.0
bb_len = st.sidebar.number_input("Bollinger length", min_value=10, max_value=80, value=20, step=5)
bb_k = st.sidebar.slider("Bollinger k", 10, 30, 20) / 10.0  # 1.0~3.0

# ========= Helpers =========
def compute_rsi(close: pd.Series, length: int = 14) -> pd.Series:
    delta = close.diff()
    gain = delta.where(delta > 0, 0.0)
    loss = (-delta).where(delta < 0, 0.0)
    avg_gain = gain.rolling(length).mean()
    avg_loss = loss.rolling(length).mean()
    rs = avg_gain / avg_loss.replace(0, np.nan)
    rsi = 100 - (100 / (1 + rs))
    return rsi

def compute_atr(high: pd.Series, low: pd.Series, close: pd.Series, length: int = 14) -> pd.Series:
    prev_close = close.shift(1)
    tr = pd.concat(
        [(high - low).abs(), (high - prev_close).abs(), (low - prev_close).abs()],
        axis=1
    ).max(axis=1)
    atr = tr.rolling(length).mean()
    return atr

def compute_adx(high: pd.Series, low: pd.Series, close: pd.Series, length: int = 14) -> pd.Series:
    up_move = high.diff()
    down_move = -low.diff()

    plus_dm = up_move.where((up_move > down_move) & (up_move > 0), 0.0)
    minus_dm = down_move.where((down_move > up_move) & (down_move > 0), 0.0)

    atr = compute_atr(high, low, close, length)
    plus_di = 100 * (plus_dm.rolling(length).sum() / atr.replace(0, np.nan))
    minus_di = 100 * (minus_dm.rolling(length).sum() / atr.replace(0, np.nan))

    dx = 100 * (plus_di - minus_di).abs() / (plus_di + minus_di).replace(0, np.nan)
    adx = dx.rolling(length).mean()
    return adx

def compute_bollinger_width(close: pd.Series, length: int = 20, k: float = 2.0) -> pd.Series:
    ma = close.rolling(length).mean()
    sd = close.rolling(length).std()
    upper = ma + k * sd
    lower = ma - k * sd
    width = (upper - lower) / ma.replace(0, np.nan)
    return width

def decide_bias(close: pd.Series, high: pd.Series, low: pd.Series) -> dict:
    c = close.copy()
    ma1 = c.rolling(int(ma_fast)).mean()
    ma2 = c.rolling(int(ma_slow)).mean()
    rsi = compute_rsi(c, int(rsi_len))

    hh = high.rolling(int(breakout_lookback)).max()
    ll = low.rolling(int(breakout_lookback)).min()

    last = c.iloc[-1]
    last_ma1 = ma1.iloc[-1]
    last_ma2 = ma2.iloc[-1]
    last_rsi = rsi.iloc[-1]
    last_hh = hh.iloc[-2] if len(hh) >= 2 else np.nan
    last_ll = ll.iloc[-2] if len(ll) >= 2 else np.nan

    trend_up = (pd.notna(last_ma1) and pd.notna(last_ma2)) and (last_ma1 > last_ma2) and (last > last_ma1)
    trend_dn = (pd.notna(last_ma1) and pd.notna(last_ma2)) and (last_ma1 < last_ma2) and (last < last_ma1)

    breakout_up = bool(pd.notna(last_hh) and last > last_hh)
    breakout_dn = bool(pd.notna(last_ll) and last < last_ll)

    score = 0
    score += 1 if trend_up else 0
    score -= 1 if trend_dn else 0

    score += 1 if (pd.notna(last_rsi) and last_rsi > 55) else 0
    score -= 1 if (pd.notna(last_rsi) and last_rsi < 45) else 0

    score += 1 if breakout_up else 0
    score -= 1 if breakout_dn else 0

    if score >= 2:
        bias = "Bullish"
        direction = "CALL"
    elif score <= -2:
        bias = "Bearish"
        direction = "PUT"
    else:
        bias = "Neutral"
        direction = "NO_TRADE"

    return {
        "bias": bias,
        "direction": direction,
        "score": score,
        "ma_fast": float(last_ma1) if pd.notna(last_ma1) else None,
        "ma_slow": float(last_ma2) if pd.notna(last_ma2) else None,
        "rsi": float(last_rsi) if pd.notna(last_rsi) else None,
        "breakout_up": breakout_up,
        "breakout_dn": breakout_dn,
    }

def determine_regime(df: pd.DataFrame) -> dict:
    close = df["Close"]
    high = df["High"]
    low = df["Low"]

    ma1 = close.rolling(int(ma_fast)).mean()
    ma2 = close.rolling(int(ma_slow)).mean()

    adx = compute_adx(high, low, close, int(adx_len))
    atr = compute_atr(high, low, close, int(atr_len))
    bb_width = compute_bollinger_width(close, int(bb_len), float(bb_k))

    last_close = float(close.iloc[-1])
    last_ma1 = ma1.iloc[-1]
    last_ma2 = ma2.iloc[-1]
    last_adx = adx.iloc[-1]
    last_atr = atr.iloc[-1]
    last_bw = bb_width.iloc[-1]

    # ATR expansion test: ATR_now > mult * ATR_mean(past lookback)
    atr_base = atr.rolling(int(atr_exp_lookback)).mean().iloc[-1]
    atr_expand = bool(pd.notna(last_atr) and pd.notna(atr_base) and (last_atr > atr_exp_mult * atr_base))

    # Trend test: MA separation + ADX
    ma_sep_ok = bool(pd.notna(last_ma1) and pd.notna(last_ma2) and (abs(last_ma1 - last_ma2) / last_close > 0.003))
    trend = bool(pd.notna(last_adx) and (last_adx >= adx_trend_th) and ma_sep_ok)

    if atr_expand:
        regime = "VOL_EXPANSION"
    elif trend:
        regime = "TREND"
    else:
        regime = "RANGE"

    return {
        "regime": regime,
        "adx": float(last_adx) if pd.notna(last_adx) else None,
        "atr": float(last_atr) if pd.notna(last_atr) else None,
        "atr_base": float(atr_base) if pd.notna(atr_base) else None,
        "atr_expand": atr_expand,
        "bb_width": float(last_bw) if pd.notna(last_bw) else None,
        "ma_fast": float(last_ma1) if pd.notna(last_ma1) else None,
        "ma_slow": float(last_ma2) if pd.notna(last_ma2) else None,
    }

def pick_candidates(df: pd.DataFrame, opt_type: str, spot: float, top_n: int,
                    atm_band_pct: float, max_spread_pct: float) -> pd.DataFrame:
    d = df.copy()
    d["type"] = opt_type
    d["spread"] = d["ask"] - d["bid"]
    d["mid"] = (d["ask"] + d["bid"]) / 2
    d["atm_dist_pct"] = (d["strike"] - spot).abs() / spot * 100

    d = d[(d["bid"] > 0) & (d["ask"] > 0)]
    d = d[d["spread"] >= 0]
    d = d[d["mid"] > 0]

    d = d[d["atm_dist_pct"] <= atm_band_pct]

    d["spread_pct"] = d["spread"] / d["mid"] * 100
    d = d[d["spread_pct"] <= max_spread_pct]

    d = d[(d["volume"].fillna(0) > 0) | (d["openInterest"].fillna(0) > 0)]

    d["liq"] = d["volume"].fillna(0) + 0.5 * d["openInterest"].fillna(0)
    d["score"] = d["liq"] - 30 * d["spread_pct"] - 2 * d["atm_dist_pct"]

    cols = [
        "contractSymbol", "type", "strike", "lastPrice",
        "bid", "ask", "mid",
        "spread", "spread_pct",
        "impliedVolatility", "volume", "openInterest",
        "inTheMoney", "atm_dist_pct", "score"
    ]
    return d.sort_values("score", ascending=False)[cols].head(top_n)

# ========= Main =========
if not ticker:
    st.stop()

data = yf.download(
    ticker,
    period="6mo",
    interval="1d",
    auto_adjust=False,
    progress=False
)

if data is None or data.empty:
    st.error("No price data found.")
    st.stop()

if isinstance(data.columns, pd.MultiIndex):
    data.columns = data.columns.get_level_values(0)
else:
    data.columns = [str(c).strip() for c in data.columns]

# ===== Price Chart (last 1mo) =====
st.subheader("Price Chart (last 1mo)")
data_1m = data.tail(22)

fig = go.Figure()
fig.add_trace(go.Candlestick(
    x=data_1m.index,
    open=data_1m["Open"],
    high=data_1m["High"],
    low=data_1m["Low"],
    close=data_1m["Close"],
    name="Candlestick"
))
fig.update_layout(height=520, xaxis_rangeslider_visible=False)
st.plotly_chart(fig, use_container_width=True)

# ===== Volatility Metrics =====
st.subheader("Volatility Metrics")
returns = data["Close"].pct_change()
hist_vol_20 = returns.rolling(20).std() * (252 ** 0.5)
today_range = (data_1m["High"].iloc[-1] - data_1m["Low"].iloc[-1]) / data_1m["Close"].iloc[-1] * 100

c1, c2, c3 = st.columns(3)
c1.metric("Last Close", f"{data_1m['Close'].iloc[-1]:.2f}")
c2.metric("20D Hist Vol", f"{hist_vol_20.iloc[-1]:.2%}" if pd.notna(hist_vol_20.iloc[-1]) else "NA")
c3.metric("Today Range %", f"{today_range:.2f}%")

# ===== Market Regime (new) =====
st.subheader("Market Regime (new)")
reg = determine_regime(data)

r1, r2, r3, r4 = st.columns(4)
r1.metric("Regime", reg["regime"])
r2.metric("ADX", f"{reg['adx']:.1f}" if reg["adx"] is not None else "NA")
r3.metric("ATR", f"{reg['atr']:.2f}" if reg["atr"] is not None else "NA")
r4.metric("BB Width", f"{reg['bb_width']:.3f}" if reg["bb_width"] is not None else "NA")

st.caption(
    f"ATR expand? {reg['atr_expand']} (ATR_now vs {atr_exp_mult:.1f}×ATR_mean{atr_exp_lookback}) | "
    f"Trend test uses ADX≥{adx_trend_th} + MA separation"
)

# ===== Signals (existing; NOT changed by regime yet) =====
st.subheader("Signals (existing)")
sig = decide_bias(data["Close"], data["High"], data["Low"])

s1, s2, s3, s4 = st.columns(4)
s1.metric("Bias", sig["bias"])
s2.metric("Direction", sig["direction"])
s3.metric("Signal Score", str(sig["score"]))
s4.metric("RSI", f"{sig['rsi']:.1f}" if sig["rsi"] is not None else "NA")

st.caption(
    f"MA{ma_fast}={sig['ma_fast']:.2f} | MA{ma_slow}={sig['ma_slow']:.2f} | "
    f"BreakoutUp={sig['breakout_up']} | BreakoutDn={sig['breakout_dn']}"
)

# ===== Options =====
st.subheader("Options Data")
stock = yf.Ticker(ticker)
expirations = stock.options

if not expirations:
    st.write("No options data available.")
    st.stop()

today = datetime.today().date()

def dte_of(exp_str: str) -> int:
    exp_date = datetime.strptime(exp_str, "%Y-%m-%d").date()
    return (exp_date - today).days

exp_filtered = [e for e in expirations if dte_min <= dte_of(e) <= dte_max]
if not exp_filtered:
    st.warning(f"No expirations in DTE range {dte_min}-{dte_max}. Widen the range.")
    st.stop()

exp = st.selectbox("Select Expiration (filtered by DTE)", exp_filtered, index=0)
dte = dte_of(exp)
st.caption(f"Selected Expiration: {exp} | DTE: {dte} days")

oc = stock.option_chain(exp)
spot = float(data["Close"].iloc[-1])

calls = oc.calls.copy()
puts = oc.puts.copy()

c_top = pick_candidates(calls, "CALL", spot, top_n, atm_band_pct, max_spread_pct)
p_top = pick_candidates(puts, "PUT", spot, top_n, atm_band_pct, max_spread_pct)

# Keep your existing behavior: direction decides what to show first
if sig["direction"] == "CALL":
    st.success("Suggested Trade: CALL bias. Showing CALL candidates first.")
    st.subheader("Recommended CALL candidates")
    st.dataframe(c_top, use_container_width=True)
    st.subheader("PUT candidates (for reference)")
    st.dataframe(p_top, use_container_width=True)
elif sig["direction"] == "PUT":
    st.success("Suggested Trade: PUT bias. Showing PUT candidates first.")
    st.subheader("Recommended PUT candidates")
    st.dataframe(p_top, use_container_width=True)
    st.subheader("CALL candidates (for reference)")
    st.dataframe(c_top, use_container_width=True)
else:
    st.info("Bias is Neutral. No-trade by signal. Showing both sides for research.")
    st.subheader("CALL candidates")
    st.dataframe(c_top, use_container_width=True)
    st.subheader("PUT candidates")
    st.dataframe(p_top, use_container_width=True)

st.caption("Phase 6 will route strategies by Regime (TREND/RANGE/VOL_EXPANSION) and add entry/exit rules.")
