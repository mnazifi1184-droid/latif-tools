"""Latif Tools — web app entry point (Flask)."""
import random
import re
import secrets
import time

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

FA_DIGITS = "۰۱۲۳۴۵۶۷۸۹"
AR_DIGITS = "٠١٢٣٤٥٦٧٨٩"

OTP_TTL = 120  # seconds
_otp_store: dict[str, dict] = {}  # phone -> {"code": str, "expires": float}


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


def mask_phone(phone: str) -> str:
    return f"{phone[:4]}***{phone[-3:]}"


@app.get("/")
def index():
    return render_template("login.html")


@app.post("/api/login")
def api_login():
    """Password login — demo mode: any valid phone + password >= 8 chars.

    TODO: replace with a real user lookup (database / LDAP / ...).
    """
    data = request.get_json(silent=True) or {}
    phone = normalize_digits(str(data.get("phone", ""))).replace(" ", "")
    password = str(data.get("password", ""))

    if not valid_phone(phone):
        return jsonify(ok=False, error="شماره موبایل معتبر نیست."), 400
    if len(password) < 8:
        return jsonify(ok=False, error="رمز عبور باید حداقل ۸ کاراکتر باشد."), 400

    # TODO: real authentication here.
    return jsonify(ok=True, user={"phone": phone, "name": "کاربر لاتیف تولز"})


@app.post("/api/otp/request")
def api_otp_request():
    """Send an OTP — demo mode returns the code so the flow can be tested."""
    data = request.get_json(silent=True) or {}
    phone = normalize_digits(str(data.get("phone", ""))).replace(" ", "")

    if not valid_phone(phone):
        return jsonify(ok=False, error="شماره موبایل معتبر نیست."), 400

    code = f"{random.randint(0, 999999):06d}"  # noqa: S311 (demo only)
    _otp_store[phone] = {"code": code, "expires": time.time() + OTP_TTL}

    # TODO: integrate a real SMS provider; never return the code in production.
    return jsonify(ok=True, ttl=OTP_TTL, demo_code=code)


@app.post("/api/otp/verify")
def api_otp_verify():
    data = request.get_json(silent=True) or {}
    phone = normalize_digits(str(data.get("phone", ""))).replace(" ", "")
    code = normalize_digits(str(data.get("code", ""))).replace(" ", "")

    if not valid_phone(phone):
        return jsonify(ok=False, error="شماره موبایل معتبر نیست."), 400

    record = _otp_store.get(phone)
    if not record or time.time() > record["expires"]:
        return jsonify(ok=False, error="کد منقضی شده است؛ دوباره درخواست بده."), 400
    if code != record["code"]:
        return jsonify(ok=False, error="کد وارد شده اشتباه است."), 400

    _otp_store.pop(phone, None)
    return jsonify(ok=True, user={"phone": phone, "name": "کاربر لاتیف تولز"})


@app.get("/healthz")
def healthz():
    return jsonify(ok=True)


if __name__ == "__main__":
    app.secret_key = secrets.token_hex(32)
    app.run(host="0.0.0.0", port=8000, debug=False)
