from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from uuid import UUID, uuid4

from jose import jwt, JWTError
from fastapi import HTTPException, status

from app.core.config import settings


# --------------
# CONSTANTS
# --------------

ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS

JWT_ALGORITHM = "RS256"   # Use RSA only in 2025+ (industry standard)
JWT_ISSUER = settings.BASE_URL
JWT_AUDIENCE = settings.BASE_URL

with open("./keys/private.pem", "r") as f:
    JWT_PRIVATE_KEY = f.read()

with open("./keys/public.pem", "r") as f:
    JWT_PUBLIC_KEY = f.read()


# --------------
# INTERNAL HELPERS
# --------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _generate_jti() -> str:
    """Generate a globally unique token ID."""
    return uuid4().hex


# --------------
# CREATE TOKENS
# --------------

def create_access_token(user_id: UUID, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    """
    Create an access token signed with RSA private key.
    Always short-lived & non-refreshable.
    """
    now = _utcnow()
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": user_id,           # Subject = internal user ID
        "iat": int(now.timestamp()),        # Issued at
        "nbf": int(now.timestamp()),        # Not valid before
        "exp": int(expire.timestamp()),     # Expiration
        "jti": jwt.utils.base64url_encode(jwt.utils.force_bytes(jwt.utils.create_signature()[:16])).decode()
        if hasattr(jwt.utils, "create_signature") else _generate_jti(), # Token identifier (auditing)
        "type": "access",                   # Token type
        "iss": JWT_ISSUER,                  # Token issuer (your API)
        "aud": JWT_AUDIENCE,                # Audience
    }

    if extra_claims:
        # whitelist allowed extra claims to avoid PII leakage
        for k, v in extra_claims.items():
            if k in ("role", "scopes", "tenant"):
                payload[k] = v

    token = jwt.encode(
        payload,
        JWT_PRIVATE_KEY, # RSA PRIVATE KEY
        algorithm=JWT_ALGORITHM,
    )

    return token


def create_refresh_token(user_id: UUID) -> str:
    """
    Create refresh token (also JWT), long-lived but MUST NOT be used to access the API.
    Should be stored HttpOnly + Secure cookie.
    """
    now = _utcnow()
    expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": _generate_jti(),
        "type": "refresh",
        "iss": settings.BASE_URL,
        "aud": settings.BASE_URL,
    }

    token = jwt.encode(
        payload,
        JWT_PRIVATE_KEY,
        algorithm=JWT_ALGORITHM,
    )

    return token


# --------------
# VERIFY TOKENS
# --------------

def verify_jwt_token(token: str, expected_type: str = "access") -> Dict[str, Any]:
    """
    Verify access or refresh token using RSA PUBLIC KEY.

    Performs:
    - Signature validation
    - Algorithm enforcement
    - Exp, nbf, iat validation
    - Audience & issuer validation
    - Type validation ("access" or "refresh")
    """

    try:
        payload = jwt.decode(
            token,
            JWT_PUBLIC_KEY,       # RSA PUBLIC KEY
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={
                # "verify_at_hash": False,   # Not needed since we handle auth separately
                "require_exp": True,
                "require_iat": True,
                "require_nbf": True,
                "require_sub": True,
            },
        )

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(e)}"
        )

    # Validate token type safely
    if expected_type == "access" and payload.get("type") == "refresh":
        raise HTTPException(
            status_code=401,
            detail="Refresh token cannot be used as access token."
        )

    if expected_type == "refresh" and payload.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token."
        )

    return payload


# --------------
# HELPER FOR FASTAPI DEPENDENCY
# --------------

def extract_user_id(token_payload: Dict[str, Any]) -> str:
    """Ensure the token has a valid subject."""
    user_id = token_payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid token payload: missing subject.")
    return user_id
