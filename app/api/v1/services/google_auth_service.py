import hashlib
import secrets
import httpx
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from uuid import UUID
from sqlalchemy import select

from jose import jwt, JWTError
from fastapi import HTTPException, status, Request, Response, APIRouter
from fastapi.security import HTTPBearer

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.models import OAuthAccount, RefreshToken, User
from app.core.config import settings
from app.core.middlewares.logging import logger


router = APIRouter(prefix="/api/auth", tags=["authentication"])
security = HTTPBearer(auto_error=False)


# ===================== Utility Functions =====================
def hash_token(token: str) -> str:
    """
    Hash refresh token for storage
    Security: Prevents token theft if database is compromised
    """
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(user_id: UUID, email: str, extra_claims: Dict = None) -> str:
    """
    Generate JWT access token
    Security: Short-lived (15min), stateless validation
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_SECONDS)
    to_encode = {
        "sub": str(user_id),  # Subject: user ID
        "email": email,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": settings.JWT_ISSUER,  # "https://yourapp.com"
        "aud": settings.JWT_AUDIENCE,  # "https://yourapp.com"
        "type": "access"
    }
    if extra_claims:
        to_encode.update(extra_claims)

    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token() -> str:
    """
    Generate cryptographically secure refresh token
    Security: 32 bytes = 256 bits of entropy
    """
    return secrets.token_urlsafe(32)


async def verify_google_id_token(id_token: str) -> Dict[str, Any]:
    """
    Verify Google ID token signature and extract claims
    Security: Validates JWT signature using Google's public keys (JWKS)
    """
    # Fetch Google's public keys (cache these in production with Redis)
    async with httpx.AsyncClient() as client:
        jwks_response = await client.get("https://www.googleapis.com/oauth2/v3/certs")
        jwks = jwks_response.json()

    try:
        # Decode and verify ID token
        # jose library handles JWKS key selection automatically
        header = jwt.get_unverified_header(id_token)
        key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])

        claims = jwt.decode(
            id_token,
            key,
            algorithms=["RS256"],
            audience=settings.GOOGLE_CLIENT_ID,  # Must match your OAuth client
            issuer="https://accounts.google.com"  # Google's issuer
        )

        # Validate required claims
        if "email" not in claims or "sub" not in claims:
            raise ValueError("Missing required claims in ID token")

        return claims

    except (JWTError, KeyError, StopIteration) as e:
        logger.error(f"ID token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid ID token"
        )


async def exchange_code_for_tokens(code: str, code_verifier: str) -> Dict[str, Any]:
    """
    Exchange authorization code for tokens with Google
    Security: Uses PKCE code_verifier for additional protection
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,  # Stored securely
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,  # Must match registered URI
                "grant_type": "authorization_code",
                "code_verifier": code_verifier  # PKCE verification
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.text}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange authorization code"
            )

        return response.json()


async def get_or_create_user(
        db_session: AsyncSession,
        google_claims: Dict[str, Any]
) -> User:
    """
    Find existing user or create new one from Google claims
    Security: Links OAuth account to prevent duplicate users
    """
    google_id = google_claims["sub"]
    email = google_claims["email"]

    # Check if OAuth account exists
    stmt = select(OAuthAccount).where(
        OAuthAccount.oauth_name == "google",
        OAuthAccount.account_id == google_id
    )
    result = await db_session.execute(stmt)
    oauth_account: OAuthAccount = result.scalar_one_or_none()

    if oauth_account is not None:
        # Existing user - update last login and profile
        user = oauth_account.user
        user.last_login = datetime.now(timezone.utc)
        user.full_name = google_claims.get("name")
        user.picture_url = google_claims.get("picture")
        user.is_verified = google_claims.get("email_verified", False)
        await db_session.commit()
        return user

    # New user - create user and link OAuth account
    user = User(
        email=email,
        full_name=google_claims.get("name"),
        picture_url=google_claims.get("picture"),
        is_verified=google_claims.get("email_verified", False),
        is_active=True,
        last_login=datetime.now(timezone.utc)
    )
    db_session.add(user)
    await db_session.flush()  # Get user.id

    # Create OAuth account link
    oauth_account = OAuthAccount(
        user_id=user.id,
        oauth_name="google",
        account_id=google_id,
        account_email=email
    )
    db_session.add(oauth_account)
    await db_session.commit()

    logger.info(f"New user created via Google OAuth: {user.id}")
    return user


async def store_refresh_token(
        db_session: AsyncSession,
        user_id: UUID,
        token: str,
        request: Request
) -> RefreshToken:
    """
    Store refresh token hash with metadata
    Security: Hashes token, stores fingerprint for theft detection
    """
    token_hash = hash_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_SECONDS)

    refresh_token_record = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        user_agent=request.headers.get("user-agent", "")[:512],
        ip_address=request.client.host if request.client else None
    )

    db_session.add(refresh_token_record)
    await db_session.commit()
    return refresh_token_record


def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    """
    Set secure HttpOnly cookies for tokens
    Security: HttpOnly prevents XSS, Secure requires HTTPS, SameSite prevents CSRF
    """
    # Access token cookie (short-lived)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Not accessible via JavaScript
        secure=True,  # HTTPS only
        samesite="strict",  # Strict CSRF protection
        max_age=settings.ACCESS_TOKEN_EXPIRE_SECONDS,
        path="/",
        domain=settings.COOKIE_DOMAIN  # e.g., ".yourapp.com"
    )

    # Refresh token cookie (long-lived)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=settings.REFRESH_TOKEN_EXPIRE_SECONDS,
        path="/api/auth",  # Limited scope for security
        domain=settings.COOKIE_DOMAIN
    )