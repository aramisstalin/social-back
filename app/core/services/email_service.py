import aiosmtplib
from app.core.config import settings
from email.message import EmailMessage

from app.utils.get_app_root import get_app_root


async def send_email(email_to: str, subject: str, html_content: str):
    msg = EmailMessage()
    msg["From"] = f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>"
    msg["To"] = email_to
    msg["Subject"] = subject
    msg.set_content(html_content)
    msg.add_alternative(html_content, subtype="html")

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        start_tls=False
    )


async def send_verification_email(email_to: str, token: str):
    verify_url = f"{settings.FRONTEND_URL}/auth/verificar-email?token={token}"
    email_html = load_email_template("verify_email_template.html", verify_url)

    await send_email(email_to, "Verifique seu e-mail", email_html)


async def send_reset_password_email(email_to: str, token: str):
    verify_url = f"{settings.FRONTEND_URL}/auth/redefinir-senha?token={token}"
    email_html = load_email_template("reset_password_email_template.html", verify_url)

    await send_email(email_to, "Redefinição de senha", email_html)


def load_email_template(template_name, verify_url):
    with (open(f"{get_app_root()}/app/templates/{template_name}", "r", encoding="utf-8") as file):
        return file.read().replace("{{VERIFY_URL}}", verify_url).replace("{{FRONTEND_URL}}", settings.FRONTEND_URL)
