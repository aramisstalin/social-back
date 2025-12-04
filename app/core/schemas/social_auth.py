from typing import Optional
from .base import BaseSchema


# --- Schemas ---
class SocialUser(BaseSchema):
    id: str
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None
    emailVerified: bool

class TokenData(BaseSchema):
    user_id: str
    exp: int
    sub: str