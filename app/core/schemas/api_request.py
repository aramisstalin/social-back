from app.core.schemas import BaseSchema, SocialUser

class CodeExchangeRequest(BaseSchema):
    code: str
    code_verifier: str
    provider: str # Expected to be 'google'

class TokenResponse(BaseSchema):
    access_token: str
    expires_in: int
    user: SocialUser