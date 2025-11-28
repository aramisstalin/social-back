import hashlib
import secrets
import httpx
from datetime import datetime, timedelta
from typing import Optional, Dict
from uuid import UUID
from jose import jwt, JWTError
from fastapi import HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import json

from app.core.config import settings
from app.api.v1.schemas import (
    GoogleTokenResponse, 
    GoogleUserInfo, 
    User, 
    RefreshToken
)
from app.db.session import get_db
from app.api.v1.repositories import get_user_repository

#settings = get_settings()
security = HTTPBearer()


# Google JWKS cache (in production, use Redis)
_jwks_cache: Optional[Dict] = None
_jwks_cache_time: Optional[datetime] = None


async def get_google_jwks() -> Dict:
    """Fetch and cache Google's public keys for JWT verification"""
    global _jwks_cache, _jwks_cache_time
    
    # Cache for 24 hours
    if _jwks_cache and _jwks_cache_time:
        if datetime.utcnow() - _jwks_cache_time < timedelta(hours=24):
            return _jwks_cache
    
    async with httpx.AsyncClient() as client:
        response = await client.get(settings.GOOGLE_JWKS_URL)
        response.raise_for_status()
        _jwks_cache = response.json()
        _jwks_cache_time = datetime.utcnow()
        return _jwks_cache


async def exchange_code_for_tokens(code: str, code_verifier: str) -> GoogleTokenResponse:
    """Exchange authorization code for tokens with Google"""
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


async def verify_google_id_token(id_token: str) -> Dict:
    """Verify Google ID token signature and claims"""
    try:
        # Decode header to get key ID
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get("kid")
        
        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing key ID"
            )
        
        # Get Google's public keys
        jwks = await get_google_jwks()
        
        # Find matching key
        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break
        
        if not rsa_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: key not found"
            )
        
        # Verify and decode token
        payload = jwt.decode(
            id_token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.GOOGLE_CLIENT_ID,
            issuer="https://accounts.google.com"
        )
        
        # Additional validations
        if payload.get("aud") != settings.GOOGLE_CLIENT_ID:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: audience mismatch"
            )
        
        # Check expiration
        exp = payload.get("exp")
        if not exp or datetime.utcfromtimestamp(exp) < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired"
            )
        
        return payload
        
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )


async def create_or_update_user(user_info: GoogleUserInfo) -> User:
    """Create new user or update existing user in database"""
    user_repo = get_user_repository()
    existing_user = await user_repo._get_user_orm_by_email(user_info.email)
    """
    async with db.pool.acquire() as conn:
        # Check if user exists
        existing_user = await conn.fetchrow(
            "SELECT * FROM users WHERE google_id = $1",
            user_info.sub
        )
        
        now = datetime.utcnow()
        
        if existing_user:
            # Update existing user
            user_record = await conn.fetchrow(
                UPDATE users 
                SET email = $1, 
                    email_verified = $2,
                    name = $3,
                    picture = $4,
                    locale = $5,
                    updated_at = $6,
                    last_login_at = $6
                WHERE google_id = $7
                RETURNING *
            , user_info.email, user_info.email_verified, user_info.name,
                user_info.picture, user_info.locale, now, user_info.sub)
        else:
            # Create new user
            user_record = await conn.fetchrow(
                INSERT INTO users (
                    google_id, email, email_verified, name, 
                    picture, locale, last_login_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING *
            , user_info.sub, user_info.email, user_info.email_verified,
                user_info.name, user_info.picture, user_info.locale, now)
    """
    # now = datetime.utcnow()
    return await user_repo.update(get_db(), user_info, existing_user.id, User) if existing_user else user_repo.create(get_db(), user_info, User)

    # return User(**dict(user_record))


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
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    async with db.pool.acquire() as conn:
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
    
    async with db.pool.acquire() as conn:
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
        user_data = {k: v for k, v in dict(record).items() if k in User.__fields__}
        return User(**user_data)


async def revoke_refresh_token(refresh_token: str, replaced_by: Optional[UUID] = None):
    """Revoke a refresh token"""
    token_hash = hash_token(refresh_token)
    
    async with db.pool.acquire() as conn:
        await conn.execute("""
            UPDATE refresh_tokens
            SET revoked_at = NOW(), replaced_by_token_id = $1
            WHERE token_hash = $2
        """, replaced_by, token_hash)


async def revoke_all_user_tokens(user_id: UUID):
    """Revoke all refresh tokens for a user (logout all devices)"""
    async with db.pool.acquire() as conn:
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
    
    async with db.pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO audit_logs (
                user_id, event_type, event_data, ip_address, user_agent
            )
            VALUES ($1, $2, $3, $4, $5)
        """, user_id, event_type, json.dumps(event_data) if event_data else None,
            ip_address, user_agent)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = security
) -> User:
    """Dependency to extract and verify current user from JWT token"""
    token = credentials.credentials
    
    try:
        # Verify Google ID token
        payload = await verify_google_id_token(token)
        google_id = payload.get("sub")
        
        if not google_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject"
            )
        
        # Fetch user from database
        async with db.pool.acquire() as conn:
            user_record = await conn.fetchrow(
                "SELECT * FROM users WHERE google_id = $1 AND is_active = TRUE",
                google_id
            )
            
            if not user_record:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )
            
            return User(**dict(user_record))
            
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}"
        )