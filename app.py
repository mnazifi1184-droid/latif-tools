"""Latif Tools — web app entry point (Flask).

Real user system: register with a username + password, login, change password
from the dashboard. Passwords are hashed with scrypt + a per-user random salt
in a local SQLite database (latif.db).
"""
import hashlib
import json
import os
import re
import secrets
import sqlite3
from contextlib import closing

from flask import (Flask, jsonify, redirect, render_template, request,
                   send_from_directory, session, url_for)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "latif.db")

app = Flask(__name__)

# Persistent secret key: survive restarts so sessions do not break.
_SECRET_FILE = os.path.join(BASE_DIR, ".secret_key")


def _load_secret() -> str:
    try:
        with open(_SECRET_FILE) as f:
            token = f.read().strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    token = secrets.token_hex(32)
    with open(_SECRET_FILE, "w") as f:
        f.write(token)
    return token


app.secret_key = _load_secret()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,20}$")
MIN_PASS_LEN = 8

CREATE_USERS = """CREATE TABLE IF NOT EXISTS users (
                      id         INTEGER PRIMARY KEY AUTOINCREMENT,
                      username   TEXT UNIQUE NOT NULL,
                      pass_hash  TEXT NOT NULL,
                      salt       BLOB NOT NULL,
                      created_at TEXT DEFAULT (datetime('now'))
                  )"""


# ---------------------------------------------------------------- database
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ensure_schema() -> None:
    """Create the users table if the DB is missing/empty (self-healing)."""
    with closing(db()) as conn:
        conn.execute(CREATE_USERS)
        conn.commit()


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=2**14, r=8, p=1, dklen=32).hex()


def verify_password(password: str, salt: bytes, expected_hex: str) -> bool:
    return secrets.compare_digest(hash_password(password, salt), expected_hex)


def get_user(username: str):
    try:
        return _query_user(username)
    except sqlite3.OperationalError:  # e.g. wiped DB file — rebuild schema
        ensure_schema()
        return _query_user(username)


def _query_user(username: str):
    with closing(db()) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def insert_user(username: str, password: str) -> None:
    salt = os.urandom(16)
    try:
        _exec_insert(username, hash_password(password, salt), salt)
    except sqlite3.OperationalError:
        ensure_schema()
        _exec_insert(username, hash_password(password, salt), salt)


def _exec_insert(username: str, pass_hash: str, salt: bytes) -> None:
    with closing(db()) as conn:
        conn.execute(
            "INSERT INTO users (username, pass_hash, salt) VALUES (?, ?, ?)",
            (username, pass_hash, salt),
        )
        conn.commit()


def update_password(user_id: int, password: str) -> None:
    salt = os.urandom(16)
    with closing(db()) as conn:
        conn.execute("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?",
                     (hash_password(password, salt), salt, user_id))
        conn.commit()


def norm_username(raw: str) -> str:
    """Trim + lowercase so Ali / ali are the same account."""
    return str(raw).strip().lower()


def current_user() -> dict | None:
    return session.get("user")


# ------------------------------------------------------------------- pages
@app.get("/")
def login_page():
    if current_user():
        return redirect(url_for("dashboard_page"))
    return render_template("login.html")


@app.get("/dashboard")
def dashboard_page():
    if not current_user():
        return redirect(url_for("login_page"))
    return render_template("dashboard.html",
                           user_json=json.dumps(session["user"], ensure_ascii=False))


@app.get("/healthz")
def healthz():
    return jsonify(ok=True)


@app.get("/fonts/<path:fname>")
def fonts(fname: str):
    return send_from_directory("static/fonts", fname)


@app.get("/vendor/<path:fname>")
def vendor(fname: str):
    return send_from_directory("static/vendor", fname)


# --------------------------------------------------------------------- api
@app.post("/api/register")
def api_register():
    data = request.get_json(silent=True) or {}
    username = norm_username(data.get("username", ""))
    password = str(data.get("password", ""))

    if not USERNAME_RE.fullmatch(username):
        return jsonify(ok=False, error="نام کاربری باید ۳ تا ۲۰ کاراکتر انگلیسی، عدد، نقطه یا زیرخط باشد."), 400
    if len(password) < MIN_PASS_LEN:
        return jsonify(ok=False, error="رمز عبور باید حداقل ۸ کاراکتر باشد."), 400
    if get_user(username):
        return jsonify(ok=False, error="این نام کاربری قبلاً گرفته شده؛ یکی دیگر انتخاب کن."), 409

    insert_user(username, password)

    user = {"username": username, "name": username}
    session["user"] = user
    return jsonify(ok=True, user=user)


@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    username = norm_username(data.get("username", ""))
    password = str(data.get("password", ""))

    row = get_user(username)
    if not row or not verify_password(password, row["salt"], row["pass_hash"]):
        return jsonify(ok=False, error="نام کاربری یا رمز عبور اشتباه است."), 401

    user = {"username": row["username"], "name": row["username"]}
    session["user"] = user
    return jsonify(ok=True, user=user)


@app.post("/api/change-password")
def api_change_password():
    user = current_user()
    if not user:
        return jsonify(ok=False, error="ابتدا وارد شو."), 401

    data = request.get_json(silent=True) or {}
    current = str(data.get("current", ""))
    new = str(data.get("new", ""))

    row = get_user(user["username"])
    if not row or not verify_password(current, row["salt"], row["pass_hash"]):
        return jsonify(ok=False, error="رمز فعلی اشتباه است."), 401
    if len(new) < MIN_PASS_LEN:
        return jsonify(ok=False, error="رمز جدید باید حداقل ۸ کاراکتر باشد."), 400
    if new == current:
        return jsonify(ok=False, error="رمز جدید نباید با رمز فعلی یکسان باشد."), 400

    update_password(row["id"], new)
    return jsonify(ok=True)


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)


ensure_schema()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
