from pydantic import EmailStr

from app.core.schemas import BaseSchema


class PasswordResetRequest(BaseSchema):
    email: EmailStr


class PasswordReset(BaseSchema):
    password: str
    token: str

class SendVerificationEmail(BaseSchema):
    user_id: str
