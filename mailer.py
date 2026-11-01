"""Email sending for Latif Tools — HTTPS email APIs (works everywhere, port 443).

Providers, chosen by EMAIL_PROVIDER or auto-detected from env:

    1) Brevo  (300 free emails/day)   BREVO_API_KEY=SAPIKeyValue
    2) Resend (100 free emails/day)   RESEND_API_KEY=re_...
    3) Gmail SMTP (needs port 465/587 — NOT possible on restricted hosts)
                                      SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS

Optional overrides:
    MAIL_FROM   = "Latif Tools <you@gmail.com>"   (sender; must be verified in the provider panel)
    EMAIL_PROVIDER = brevo | resend | smtp | auto (default: auto)

Credentials are read from environment variables or a `.env` file next to app.py.
Only stdlib + `requests` (preinstalled) are used.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage

import requests


def _load_env_file(path: str) -> None:
    """Tiny .env loader — no external dependency."""
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


_load_env_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "1") != "0"
MAIL_FROM = os.environ.get("MAIL_FROM", "")

BREVO_API_BASE = os.environ.get("BREVO_API_BASE", "https://api.brevo.com/v3")
RESEND_API_BASE = os.environ.get("RESEND_API_BASE", "https://api.resend.com")

_FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")


def _provider() -> str | None:
    """Pick the email provider explicitly, or auto-detect."""
    explicit = os.environ.get("EMAIL_PROVIDER", "auto").strip().lower()
    if explicit in ("brevo", "resend", "smtp"):
        return explicit
    if BREVO_API_KEY:
        return "brevo"
    if RESEND_API_KEY:
        return "resend"
    if SMTP_HOST and SMTP_USER and SMTP_PASS:
        return "smtp"
    return None


def smtp_configured() -> bool:
    """True when any email provider is fully configured."""
    return _provider() is not None


def _fa(code: str) -> str:
    return code.translate(_FA_DIGITS)


def _sender_address() -> str:
    """Extract the bare address from MAIL_FROM ("Name <a@b.c>" -> a@b.c)."""
    raw = MAIL_FROM.strip()
    if "<" in raw and ">" in raw:
        return raw.split("<", 1)[1].split(">", 1)[0].strip()
    return raw


def build_otp_message(to_email: str, code: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"کد ورود لاتیف تولز: {_fa(code)}"
    msg["From"] = MAIL_FROM or SMTP_USER
    msg["To"] = to_email
    msg.set_content(
        f"""سلام!

کد یکبارمصرف ورود به «لاتیف تولز»:

    {code}

این کد تا ۵ دقیقه اعتبار دارد و فقط یک‌بار قابل استفاده است.
اگر شما درخواست نداده بودید، این ایمیل را نادیده بگیرید.

— لاتیف تولز | جعبه‌ابزار آنلاین
"""
    )
    return msg


def _subject_text(code: str) -> tuple[str, str]:
    subject = f"کد ورود لاتیف تولز: {_fa(code)}"
    text = (
        "سلام!\n\n"
        f"کد یکبارمصرف ورود به «لاتیف تولز»:\n\n    {code}\n\n"
        "این کد تا ۵ دقیقه اعتبار دارد و فقط یک‌بار قابل استفاده است.\n"
        "اگر شما درخواست نداده بودید، این ایمیل را نادیده بگیرید.\n\n"
        "— لاتیف تولز | جعبه‌ابزار آنلاین\n"
    )
    return subject, text


def _send_brevo(to_email: str, code: str) -> tuple[bool, str]:
    subject, text = _subject_text(code)
    sender = _sender_address()
    if not sender:
        return False, "MAIL_FROM تنظیم نشده است (ایمیل فرستنده لازم است)."
    try:
        r = requests.post(
            f"{BREVO_API_BASE}/smtp/email",
            headers={"api-key": BREVO_API_KEY, "content-type": "application/json",
                     "accept": "application/json"},
            json={
                "sender": {"name": "لاتیف تولز", "email": sender},
                "to": [{"email": to_email}],
                "subject": subject,
                "textContent": text,
            },
            timeout=15,
        )
    except requests.RequestException as exc:
        return False, f"اتصال به Brevo برقرار نشد: {exc.__class__.__name__}"
    if r.status_code in (200, 201):
        return True, ""
    try:
        detail = r.json().get("message", "")
    except ValueError:
        detail = r.text[:200]
    return False, f"Brevo کد {r.status_code} برگرداند: {detail}"


def _send_resend(to_email: str, code: str) -> tuple[bool, str]:
    subject, text = _subject_text(code)
    # Without a verified domain, Resend only allows the account owner's
    # own address as sender (onboarding@resend.dev) — fine for self-OTP.
    sender = _sender_address() or "onboarding@resend.dev"
    try:
        r = requests.post(
            f"{RESEND_API_BASE}/emails",
            headers={"authorization": f"Bearer {RESEND_API_KEY}",
                     "content-type": "application/json"},
            json={
                "from": f"لاتیف تولز <{sender}>",
                "to": [to_email],
                "subject": subject,
                "text": text,
            },
            timeout=15,
        )
    except requests.RequestException as exc:
        return False, f"اتصال به Resend برقرار نشد: {exc.__class__.__name__}"
    if r.status_code in (200, 201):
        return True, ""
    try:
        detail = r.json().get("message", "")
    except ValueError:
        detail = r.text[:200]
    return False, f"Resend کد {r.status_code} برگرداند: {detail}"


def _send_smtp(to_email: str, code: str) -> tuple[bool, str]:
    msg = build_otp_message(to_email, code)
    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT,
                                  context=ssl.create_default_context(),
                                  timeout=15) as smtp:
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
                if SMTP_STARTTLS:
                    smtp.starttls(context=ssl.create_default_context())
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
        return True, ""
    except smtplib.SMTPAuthenticationError:
        return False, "احراز هویت ناموفق: App Password یا آدرس ایمیل اشتباه است."
    except smtplib.SMTPException as exc:
        return False, f"ارسال ایمیل ناموفق بود: {exc}"
    except OSError as exc:
        return False, f"اتصال به سرور ایمیل برقرار نشد: {exc}"


_SENDERS = {"brevo": _send_brevo, "resend": _send_resend, "smtp": _send_smtp}


def send_otp_email(to_email: str, code: str) -> tuple[bool, str]:
    """Send the OTP by email. Returns (ok, persian_error_message)."""
    provider = _provider()
    if provider is None:
        return False, "هیچ سرویس ایمیل تنظیم نشده است (BREVO_API_KEY یا RESEND_API_KEY یا SMTP)."
    return _SENDERS[provider](to_email, code)
