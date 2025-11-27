from fastapi import APIRouter, HTTPException, status, Response, Request, Depends
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.v1.models import AuditLog
from app.api.v1.schemas.google import GoogleCallbackRequest
from app.api.v1.services.google_auth_service import create_access_token, create_refresh_token, set_auth_cookies, \
    get_or_create_user
from app.core.config import settings
from app.api.v1.schemas import (
    TokenResponse,
    User,
    RefreshToken,
)
from app.api.v1.services import (
    exchange_code_for_tokens,
    verify_google_id_token,
    store_refresh_token,
)
from app.core.middlewares.logging import logger
from app.core.security import hash_token
from app.db.session import get_db


router = APIRouter(prefix="/google-auth", tags=["Google Authentication"])


@router.post("/callback", response_model=TokenResponse)
async def google_callback(
        payload: GoogleCallbackRequest,
        request: Request,
        response: Response,
        db: AsyncSession = Depends(get_db)  # Your DB dependency
):
    """
    Handle OAuth callback from Angular
    1. Exchange code for tokens with Google
    2. Verify ID token
    3. Create/update user
    4. Issue internal tokens
    """
    try:
        # Exchange authorization code for Google tokens
        google_tokens = await exchange_code_for_tokens(
            payload.code,
            payload.code_verifier
        )

        # Verify ID token and extract claims
        id_token = google_tokens["id_token"]
        google_claims = await verify_google_id_token(id_token)

        # Get or create user
        user = await get_or_create_user(db, google_claims)

        # Generate internal tokens
        access_token = create_access_token(
            user.id,
            user.email,
            extra_claims={"is_superuser": user.is_superuser}
        )
        refresh_token = create_refresh_token()

        # Store refresh token
        await store_refresh_token(db, user.id, refresh_token, request)

        # Set secure cookies
        set_auth_cookies(response, access_token, refresh_token)

        # Audit log
        audit = AuditLog(
            user_id=user.id,
            event_type="login",
            event_status="success",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit)
        await db.commit()

        logger.info(f"User authenticated: {user.id}")

        return TokenResponse(
            user={
                "id": str(user.id),
                "email": user.email,
                "full_name": user.full_name,
                "picture_url": user.picture_url,
                "is_verified": user.is_verified
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/refresh")
async def refresh_token_endpoint(
        request: Request,
        response: Response,
        db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token from cookie
    Security: Validates refresh token, optionally rotates it
    """
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided"
        )

    token_hash = hash_token(refresh_token)

    # Find refresh token in database
    stmt = select(RefreshToken).where(
        RefreshToken.token_hash == token_hash,
        RefreshToken.revoked_at.is_(None),
        RefreshToken.expires_at > datetime.utcnow()
    )
    result = await db.execute(stmt)
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    # Optional: Validate user_agent matches (fingerprinting)
    # current_ua = request.headers.get("user-agent", "")[:512]
    # if token_record.user_agent != current_ua:
    #     logger.warning(f"User-agent mismatch for user {token_record.user_id}")

    # Get user
    stmt = select(User).where(User.id == token_record.user_id)
    result = await db.execute(stmt)
    user = result.scalar_one()

    # Generate new access token
    new_access_token = create_access_token(
        user.id,
        user.email,
        extra_claims={"is_superuser": user.is_superuser}
    )

    # Optional: Rotate refresh token (best practice)
    new_refresh_token = create_refresh_token()
    token_record.revoked_at = datetime.utcnow()
    token_record.replaced_by_id = (await store_refresh_token(
        db, user.id, new_refresh_token, request
    )).id
    await db.commit()

    # Set new cookies
    set_auth_cookies(response, new_access_token, new_refresh_token)

    logger.info(f"Token refreshed for user: {user.id}")

    return {"success": True}


@router.post("/logout")
async def logout(
        request: Request,
        response: Response,
        db: AsyncSession = Depends(get_db)
):
    """
    Logout user and revoke refresh token
    Security: Adds token to revocation list
    """
    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        token_hash = hash_token(refresh_token)

        # Revoke refresh token
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        result = await db.execute(stmt)
        token_record = result.scalar_one_or_none()

        if token_record:
            token_record.revoked_at = datetime.utcnow()

            # Audit log
            audit = AuditLog(
                user_id=token_record.user_id,
                event_type="logout",
                event_status="success",
                ip_address=request.client.host if request.client else None
            )
            db.add(audit)
            await db.commit()

    # Clear cookies
    response.delete_cookie("access_token", path="/", domain=settings.COOKIE_DOMAIN)
    response.delete_cookie("refresh_token", path="/api/auth", domain=settings.COOKIE_DOMAIN)

    return {"success": True, "message": "Logged out successfully"}


# ============ Dependency for Protected Routes ============

async def get_current_user(
        request: Request,
        db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency to extract and validate user from access token cookie
    Usage: user = Depends(get_current_user)
    """
    access_token = request.cookies.get("access_token")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    try:
        # Decode and validate JWT
        payload = jwt.decode(
            access_token,
            settings.JWT_SECRET_KEY,
            algorithms=[ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER
        )

        user_id_str: str = payload.get("sub")
        if user_id_str is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        user_id = uuid.UUID(user_id_str)

    except JWTError as e:
        logger.error(f"JWT validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

    # Fetch user from database
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    return user