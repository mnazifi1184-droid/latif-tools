"""Email sending for Latif Tools — Gmail SMTP with an App Password.

Credentials come from environment variables, or a `.env` file next to app.py:

    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=465
    SMTP_USER=your.address@gmail.com
    SMTP_PASS=abcdefghijklmnop      ← 16-char App Password (NOT the Gmail password)
    MAIL_FROM=Latif Tools <your.address@gmail.com>
    SMTP_STARTTLS=1                 ← 1 for port 587, 0 for plain/SSL servers

Only the stdlib is used (smtplib + email), no extra dependencies.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage


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

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
MAIL_FROM = os.environ.get("MAIL_FROM", SMTP_USER)
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "1") != "0"

_FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")


def smtp_configured() -> bool:
    """True when all SMTP credentials are present."""
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASS)


def _fa(code: str) -> str:
    return code.translate(_FA_DIGITS)


def build_otp_message(to_email: str, code: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"کد ورود لاتیف تولز: {_fa(code)}"
    # MAIL_FROM may already contain a display name: "Latif Tools <you@gmail.com>"
    msg["From"] = MAIL_FROM or SMTP_USER
    msg["To"] = to_email
    msg.set_content(
        f"""سلام!

کد یکبارمصرف ورود به «لاتیف تولز»:

    {code}

این کد تا ۲ دقیقه اعتبار دارد و فقط یک‌بار قابل استفاده است.
اگر شما درخواست نداده بودید، این ایمیل را نادیده بگیرید.

— لاتیف تولز | جعبه‌ابزار آنلاین
"""
    )
    return msg


def send_otp_email(to_email: str, code: str) -> tuple[bool, str]:
    """Send the OTP by email. Returns (ok, persian_error_message)."""
    if not smtp_configured():
        return False, "SMTP تنظیم نشده است."
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
