"""Latif Tools — web app entry point (Flask)."""
import json as _json
import random
import re
import secrets
import time

from flask import (Flask, jsonify, redirect, render_template, request,
                   send_from_directory, session, url_for)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # TODO: از متغیر محیطی بخوان در استقرار واقعی

FA_DIGITS = "۰۱۲۳۴۵۶۷۸۹"
AR_DIGITS = "٠١٢٣٤٥٦٧٨٩"

OTP_TTL = 120  # seconds
_otp_store: dict[str, dict] = {}  # email -> {"code": str, "expires": float}

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def normalize_digits(value: str) -> str:
    """Convert Persian/Arabic digits to English digits."""
    out = []
    for ch in value:
        if ch in FA_DIGITS:
            out.append(str(FA_DIGITS.index(ch)))
        elif ch in AR_DIGITS:
            out.append(str(AR_DIGITS.index(ch)))
        else:
            out.append(ch)
    return "".join(out)


def valid_phone(phone: str) -> bool:
    return bool(re.fullmatch(r"09\d{9}", phone))


def valid_email(email: str) -> bool:
    return bool(EMAIL_RE.fullmatch(email))


def is_email(identifier: str) -> bool:
    return "@" in identifier


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:2]}***@{domain}" if len(local) > 2 else f"***@{domain}"


def mask_phone(phone: str) -> str:
    return f"{phone[:4]}***{phone[-3:]}"


# ---------------- صفحات ----------------

@app.get("/")
def index():
    return render_template("login.html")


@app.get("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))
    return render_template("dashboard.html", user_json=_json.dumps(user, ensure_ascii=False))


# ---------------- فونت‌ها (مسیر مشترک برای نسخه فلسک و استاتیک) ----------------

@app.get("/fonts/<path:fname>")
def fonts(fname: str):
    return send_from_directory("static/fonts", fname)


@app.get("/vendor/<path:fname>")
def vendor(fname: str):
    return send_from_directory("static/vendor", fname)


# ---------------- API ورود ----------------

@app.post("/api/login")
def api_login():
    """Password login with phone OR email — demo mode.

    TODO: replace with a real user lookup (database / LDAP / ...).
    """
    data = request.get_json(silent=True) or {}
    identifier = normalize_digits(str(data.get("identifier", ""))).strip().replace(" ", "")
    password = str(data.get("password", ""))

    if is_email(identifier):
        if not valid_email(identifier):
            return jsonify(ok=False, error="ایمیل معتبر نیست."), 400
        identity = {"email": identifier, "phone": None, "name": identifier.split("@")[0]}
    else:
        if not valid_phone(identifier):
            return jsonify(ok=False, error="شماره موبایل یا ایمیل معتبر نیست."), 400
        identity = {"phone": identifier, "email": None, "name": "کاربر لاتیف تولز"}

    if len(password) < 8:
        return jsonify(ok=False, error="رمز عبور باید حداقل ۸ کاراکتر باشد."), 400

    # TODO: احراز هویت واقعی اینجا — چک هش رمز در دیتابیس
    session["user"] = identity
    return jsonify(ok=True, user=identity)


@app.post("/api/otp/request")
def api_otp_request():
    """Send an OTP code by EMAIL — demo mode returns the code for testing.

    TODO: ارسال واقعی با SMTP جی‌میل (App Password) یا سرویس ایمیل؛
          کد هرگز نباید در پاسخ برگردانده شود.
    """
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    if not valid_email(email):
        return jsonify(ok=False, error="ایمیل معتبر نیست؛ مثل example@gmail.com واردش کن."), 400

    code = f"{random.randint(0, 999999):06d}"  # noqa: S311 (demo only)
    _otp_store[email] = {"code": code, "expires": time.time() + OTP_TTL}

    return jsonify(ok=True, ttl=OTP_TTL, demo_code=code, masked=mask_email(email))


@app.post("/api/otp/verify")
def api_otp_verify():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    code = normalize_digits(str(data.get("code", ""))).replace(" ", "")

    if not valid_email(email):
        return jsonify(ok=False, error="ایمیل معتبر نیست."), 400

    record = _otp_store.get(email)
    if not record or time.time() > record["expires"]:
        return jsonify(ok=False, error="کد منقضی شده است؛ دوباره درخواست بده."), 400
    if code != record["code"]:
        return jsonify(ok=False, error="کد وارد شده اشتباه است."), 400

    _otp_store.pop(email, None)
    identity = {"email": email, "phone": None, "name": email.split("@")[0]}
    session["user"] = identity
    return jsonify(ok=True, user=identity)


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/healthz")
def healthz():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
