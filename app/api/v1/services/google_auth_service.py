import hashlib
import secrets
import httpx
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Annotated
from uuid import UUID
from fastapi import HTTPException, status, Request, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError

import json

from app.api.v1.models.social_account import ProviderName
from app.core.config import settings
from app.api.v1.schemas import (
    GoogleTokenResponse, 
    GoogleUserInfo, 
    UserRead as User,
    RefreshToken
)
import asyncpg

from app.core.helpers import verify_jwt_token
from app.db import get_connection, db_manager

from google.oauth2 import id_token
from google.auth.transport import requests


# Google JWKS cache (in production, use Redis)
_jwks_cache: Optional[Dict] = None
_jwks_cache_time: Optional[datetime] = None


async def get_google_jwks() -> Dict:
    """Fetch and cache Google's public keys for JWT verification"""
    global _jwks_cache, _jwks_cache_time
    
    # Cache for 24 hours
    if _jwks_cache and _jwks_cache_time:
        if datetime.now(timezone.utc) - _jwks_cache_time < timedelta(hours=24):
            return _jwks_cache
    
    async with httpx.AsyncClient() as client:
        response = await client.get(settings.GOOGLE_JWKS_URL)
        response.raise_for_status()
        _jwks_cache = response.json()
        _jwks_cache_time = datetime.now(timezone.utc)
        return _jwks_cache


async def exchange_code_for_tokens(code: str, code_verifier: str) -> GoogleTokenResponse:
    # Exchange authorization code for tokens with Google
    token_data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,  # PKCE verification
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                settings.GOOGLE_TOKEN_URL,
                data=token_data,
                timeout=10.0
            )
            response.raise_for_status()
            return GoogleTokenResponse(**response.json())
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to exchange code: {e.response.text}"
            )


async def get_google_user_info(access_token: str) -> GoogleUserInfo:
    """Fetch user info from Google using access token"""
    headers = {"Authorization": f"Bearer {access_token}"}
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                settings.GOOGLE_USERINFO_URL,
                headers=headers,
                timeout=10.0
            )
            response.raise_for_status()
            return GoogleUserInfo(**response.json())
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to fetch user info: {e.response.text}"
            )


async def verify_google_id_token(id_token_str: str) -> dict:
    """
    Enterprise-grade Google ID Token verification.
    Uses Google's official verifier with automatic JWK caching,
    signature validation, issuer validation, audience check,
    and token integrity enforcement.
    """
    try:
        # Google's verifier (validates signature, iss, aud, exp, iat, alg, etc.)
        payload = id_token.verify_oauth2_token(
            id_token_str,
            requests.Request(),
            settings.GOOGLE_CLIENT_ID
        )

        # Optional: strictly require Google's issuer (recommended)
        if payload.get("iss") not in (
            "accounts.google.com",
            "https://accounts.google.com"
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid issuer in token"
            )

        return payload

    except ValueError as e:
        # Google verification errors return ValueError
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google ID token: {str(e)}"
        )


async def create_or_update_user(user_info: GoogleUserInfo) -> User:
    """Create new user or update existing user in database"""

    async with db_manager.transaction() as conn:
        # Check if user exists
        existing_user = await conn.fetchrow(
            f"SELECT * FROM social_accounts WHERE provider_name = $1 AND provider_user_id = $2",
            ProviderName.google,
            user_info.sub
        )

        # for consistency in the created_at, updated_at and last_login_at fields at creation time
        now = datetime.now(timezone.utc)

        if existing_user:
            # Update existing user
            user_record = await conn.fetchrow("""
                UPDATE users
                SET email = $1, 
                    is_email_verified = $2,
                    name = $3,
                    avatar = $4,
                    locale = $5,
                    last_login_at = $6
                WHERE id = $7
                RETURNING *
            """, user_info.email, user_info.email_verified, user_info.name,
                user_info.picture, user_info.locale, now, existing_user.get("user_id"))
        else:
            # Create new user
            user_record = await conn.fetchrow("""
                        INSERT INTO users (
                            email, is_email_verified, 
                            name, first_name, last_name, 
                            avatar,
                            locale,
                            last_login_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        RETURNING *
                    """, user_info.email, user_info.email_verified,
                        user_info.name, user_info.given_name, user_info.family_name,
                        user_info.picture,
                        user_info.locale,
                        now
            )

            await conn.fetchrow("""
                INSERT INTO social_accounts (
                    provider_name, provider_user_id, user_id
                )
                VALUES ($1, $2, $3)
                RETURNING *
            """, ProviderName.google, user_info.sub, user_record.get("id")
            )

        return User(**dict(user_record))


def hash_token(token: str) -> str:
    """SHA256 hash for storing refresh tokens securely"""
    return hashlib.sha256(token.encode()).hexdigest()


async def store_refresh_token(
    user_id: UUID, 
    refresh_token: str,
    device_info: Optional[Dict] = None
) -> RefreshToken:
    """Store refresh token in database with hash"""
    token_hash = hash_token(refresh_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    conn: asyncpg.Connection = get_connection()
    record = await conn.fetchrow("""
        INSERT INTO refresh_tokens (
            user_id, token_hash, expires_at, device_info
        )
        VALUES ($1, $2, $3, $4)
        RETURNING *
    """, user_id, token_hash, expires_at, json.dumps(device_info) if device_info else None)

    return RefreshToken(**dict(record))


async def verify_refresh_token(refresh_token: str) -> Optional[User]:
    """Verify refresh token and return associated user"""
    token_hash = hash_token(refresh_token)
    
    conn: asyncpg.Connection = get_connection()
    # Check token exists, not revoked, and not expired
    record = await conn.fetchrow("""
        SELECT rt.*, u.* 
        FROM refresh_tokens rt
        JOIN users u ON rt.user_id = u.id
        WHERE rt.token_hash = $1 
            AND rt.revoked_at IS NULL
            AND rt.expires_at > NOW()
            AND u.is_active = TRUE
    """, token_hash)

    if not record:
        return None

    # Convert to User object (skip refresh_token fields)
    user_data = {k: v for k, v in dict(record).items() if k in User.model_fields}
    return User(**user_data)


async def revoke_refresh_token(refresh_token: str, replaced_by: Optional[UUID] = None):
    """Revoke a refresh token"""
    token_hash = hash_token(refresh_token)
    
    conn: asyncpg.Connection = get_connection()
    await conn.execute("""
        UPDATE refresh_tokens
        SET revoked_at = NOW(), replaced_by_token_id = $1
        WHERE token_hash = $2
    """, replaced_by, token_hash)


async def revoke_all_user_tokens(user_id: UUID):
    """Revoke all refresh tokens for a user (logout all devices)"""
    conn: asyncpg.Connection = get_connection()
    await conn.execute("""
        UPDATE refresh_tokens
        SET revoked_at = NOW()
        WHERE user_id = $1 AND revoked_at IS NULL
    """, user_id)


def generate_refresh_token() -> str:
    """Generate a cryptographically secure refresh token"""
    return secrets.token_urlsafe(32)


async def create_audit_log(
    user_id: Optional[UUID],
    event_type: str,
    event_data: Optional[Dict],
    request: Request
):
    """Log authentication events for audit trail"""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    conn: asyncpg.Connection = get_connection()
    await conn.execute("""
        INSERT INTO audit_logs (
            user_id, event_type, event_data, ip_address, user_agent
        )
        VALUES ($1, $2, $3, $4, $5)
    """, user_id, event_type, json.dumps(event_data) if event_data else None,
        ip_address, user_agent)


security = HTTPBearer(
    scheme_name="BearerAuth",
    description="Provide a valid Google ID Token as Bearer <token>."
)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]
) -> User:
    """
    Extracts the bearer token, validates it using Google's public JWKS,
    checks all OpenID Connect claims, and returns the authenticated user
    from the database.

    This method guarantees:
    - The token is a valid
    - Signature is verified using the right algorithm
    - Token is not expired
    - Audience matches your id
    - Issuer is valid
    - The user exists and is active in your DB
    """

    token = credentials.credentials

    # ---- Validate Token ----
    try:
        payload = verify_jwt_token(token)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token."
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token."
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token payload missing subject")

    # ---- Fetch user from DB ----
    # conn: asyncpg.Connection = get_connection()
    async with db_manager.acquire_connection() as conn:
        user_record = await conn.fetchrow(
            """
            SELECT *
            FROM users
            WHERE id = $1
              AND is_active = TRUE
            LIMIT 1
            """,
            UUID(user_id),
        )

        if not user_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive."
            )

        # Optional: audit log successful token-based auth
        # Note: For a dependency we don't have Request, so we only log lightweight audit here.
        # If you want IP/user-agent include Request in function param.
        # try:
        #     # best-effort, do not block request on audit failure
        #     await create_audit_log(user_id, "auth.token_use", {"jti": payload.get("jti")},
        #                            Request(scope={"type": "http"}))
        # except Exception:
        #     # swallow to avoid breaking API; optionally log to app logger
        #     pass

        # ---- Convert DB row → Pydantic User ----
        return User(**dict(user_record))
