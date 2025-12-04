from typing import Optional
from pydantic import EmailStr

from app.core.schemas import BaseSchema

# Google OAuth Response
class MicrosoftTokenResponse(BaseSchema):
    access_token: str
    expires_in: int
    scope: str
    token_type: str
    id_token: str
    refresh_token: Optional[str] = None


class MicrosoftUserInfo(BaseSchema):
    sub: str  # Google user ID
    email: EmailStr
    email_verified: bool
    name: Optional[str]
    picture: Optional[str]
    given_name: Optional[str]
    family_name: Optional[str]
    locale: Optional[str]