import logging
from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from jinja2 import Environment, FileSystemLoader

from app.core.config import mail_config, settings


_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)))
template = env.get_template("verification_email.html")
password_reset_template = env.get_template("password_reset_email.html")

async def _send_html_email(
    *,
    subject: str,
    recipients: list[str],
    body: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    reply_to: list[str] | None = None,
) -> None:
    cc = cc or []
    bcc = bcc or []
    reply_to = reply_to or []

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail_config.MAIL_FROM
    message["To"] = ", ".join(recipients)
    if cc:
        message["Cc"] = ", ".join(cc)
    if reply_to:
        message["Reply-To"] = ", ".join(reply_to)
    message.set_content(body, subtype="html")

    await aiosmtplib.send(
        message,
        hostname=mail_config.MAIL_SERVER,
        port=mail_config.MAIL_PORT,
        start_tls=mail_config.MAIL_STARTTLS and not mail_config.MAIL_SSL_TLS,
        use_tls=mail_config.MAIL_SSL_TLS,
        username=mail_config.MAIL_USERNAME if mail_config.USE_CREDENTIALS else None,
        password=mail_config.MAIL_PASSWORD if mail_config.USE_CREDENTIALS else None,
        validate_certs=mail_config.VALIDATE_CERTS,
        recipients=[*recipients, *cc, *bcc],
    )


# Send verification email
async def send_verification_email(token: str, email: str, name: str):
    verification_link = f"{settings.BACKEND_URL}/api/v1/auth/verify-page?token={token}"
    body = template.render(email=email, verification_link=verification_link, name=name)

    await _send_html_email(
        subject="Verify your Tech_Pulse account",
        recipients=[email],
        cc=["support@techpulse.com"],
        bcc=["admin@techpulse.com"],
        reply_to=["support@techpulse.com"],
        body=body,
    )
    logging.info("verification email sent to %s", email)


async def send_password_reset_email(token: str, email: str, name: str):
    reset_link = f"{settings.BACKEND_URL}/api/v1/auth/password-reset/page?token={token}"
    body = password_reset_template.render(email=email, password_reset_link=reset_link, name=name)

    await _send_html_email(
        subject="Reset your Tech_Pulse password",
        recipients=[email],
        body=body,
    )
    logging.info("password reset email sent to %s", email)
        
