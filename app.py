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

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # TODO: از متغیر محیطی بخوان در استقرار واقعی

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "latif.db")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,20}$")
MIN_PASS_LEN = 8


# ---------------------------------------------------------------- database
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with closing(db()) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   username   TEXT UNIQUE NOT NULL,
                   pass_hash  TEXT NOT NULL,
                   salt       BLOB NOT NULL,
                   created_at TEXT DEFAULT (datetime('now'))
               )"""
        )
        conn.commit()


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=2**14, r=8, p=1, dklen=32).hex()


def verify_password(password: str, salt: bytes, expected_hex: str) -> bool:
    return secrets.compare_digest(hash_password(password, salt), expected_hex)


def get_user(username: str):
    with closing(db()) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


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
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not USERNAME_RE.fullmatch(username):
        return jsonify(ok=False, error="نام کاربری باید ۳ تا ۲۰ کاراکتر انگلیسی، عدد، نقطه یا زیرخط باشد."), 400
    if len(password) < MIN_PASS_LEN:
        return jsonify(ok=False, error="رمز عبور باید حداقل ۸ کاراکتر باشد."), 400
    if get_user(username):
        return jsonify(ok=False, error="این نام کاربری قبلاً گرفته شده؛ یکی دیگر انتخاب کن."), 409

    salt = os.urandom(16)
    with closing(db()) as conn:
        conn.execute(
            "INSERT INTO users (username, pass_hash, salt) VALUES (?, ?, ?)",
            (username, hash_password(password, salt), salt),
        )
        conn.commit()

    user = {"username": username, "name": username}
    session["user"] = user
    return jsonify(ok=True, user=user)


@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
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

    salt = os.urandom(16)
    with closing(db()) as conn:
        conn.execute("UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?",
                     (hash_password(new, salt), salt, row["id"]))
        conn.commit()
    return jsonify(ok=True)


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
