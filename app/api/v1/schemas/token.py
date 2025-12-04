from datetime import datetime
from typing import Optional
from pydantic import Field
from app.core.schemas import BaseSchema
from uuid import UUID
from app.api.v1.schemas import UserRead as User


class Token(BaseSchema):
    access_token: str
    refresh_token: str
    token_type: str = 'Bearer'


class TokenData(BaseSchema):
    username: Optional[str] = None


# Request Models
class TokenExchangeRequest(BaseSchema):
    code: str = Field(..., description="Authorization code from Google")
    code_verifier: str = Field(..., description="PKCE code verifier")


class RefreshTokenRequest(BaseSchema):
    """Refresh token is sent via HttpOnly cookie"""
    pass


class RefreshToken(BaseSchema):
    id: UUID
    user_id: UUID
    token_hash: str
    expires_at: datetime
    created_at: datetime
    revoked_at: Optional[datetime]
    replaced_by_token_id: Optional[UUID]
    device_info: Optional[dict]


# Response Models
class TokenResponse(BaseSchema):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: User
