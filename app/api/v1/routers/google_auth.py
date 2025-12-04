from fastapi import APIRouter, HTTPException, status, Response, Request, Cookie, Depends
from typing import Optional

from app.core.config import settings
from app.api.v1.schemas import (
    TokenExchangeRequest,
    TokenResponse,
    UserRead as User
)
from app.api.v1.services import (
    exchange_code_for_tokens,
    get_google_user_info,
    verify_google_id_token,
    create_or_update_user,
    store_refresh_token,
    verify_refresh_token,
    revoke_refresh_token,
    revoke_all_user_tokens,
    generate_refresh_token,
    create_audit_log,
    get_current_user
)
# from models import User

router = APIRouter(prefix="/google-auth", tags=["Google Authentication"])


@router.post("/token", response_model=TokenResponse)
async def token_exchange(
    request: Request,
    response: Response,
    body: TokenExchangeRequest
):
    """
    Exchange authorization code for tokens.
    
    Security: PKCE code_verifier is validated by Google.
    Returns access_token in body, refresh_token in HttpOnly cookie.
    """
    try:
        # Exchange code with Google (includes PKCE verification)
        google_tokens = await exchange_code_for_tokens(body.code, body.code_verifier)
        
        # Verify ID token
        await verify_google_id_token(google_tokens.id_token)
        
        # Get user info from Google
        user_info = await get_google_user_info(google_tokens.access_token)
        
        # Create or update user in database
        user = await create_or_update_user(user_info)
        
        # Generate our own refresh token (don't expose Google's)
        refresh_token = generate_refresh_token()
        
        # Store refresh token in database
        device_info = {
            "user_agent": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None
        }
        await store_refresh_token(user.id, refresh_token, device_info)
        
        # Set HttpOnly cookie with refresh token
        # CRITICAL: Secure=True in production (HTTPS), SameSite=Strict for CSRF protection
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,  # Prevents XSS access
            secure=not settings.DEBUG,  # HTTPS only in production
            samesite="strict",  # CSRF protection
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            path="/api/google-auth"  # Limit cookie scope
        )
        
        # Audit log
        await create_audit_log(
            user_id=user.id,
            event_type="login",
            event_data={"method": "google_oauth"},
            request=request
        )
        
        # Return access token in response body (Google's ID token)
        return TokenResponse(
            access_token=google_tokens.id_token,  # Use Google's ID token as access token
            token_type="bearer",
            expires_in=google_tokens.expires_in,
            user=User(
                id=user.id,
                email=user.email,
                username=user.name,
                avatar=user.picture,
                is_email_verified=user.email_verified
            )
        )
        
    except Exception as e:
        # Log error for monitoring
        print(f"Token exchange error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange authorization code"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(None, alias="refresh_token")
):
    """
    Refresh access token using refresh token from HttpOnly cookie.
    
    Security: Implements refresh token rotation - old token is revoked.
    """
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found"
        )
    
    # Verify refresh token and get user
    user = await verify_refresh_token(refresh_token)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Generate new refresh token (rotation)
    new_refresh_token = generate_refresh_token()
    
    # Store new refresh token
    device_info = {
        "user_agent": request.headers.get("user-agent"),
        "ip": request.client.host if request.client else None
    }
    new_token_record = await store_refresh_token(user.id, new_refresh_token, device_info)
    
    # Revoke old refresh token
    await revoke_refresh_token(refresh_token, replaced_by=new_token_record.id)
    
    # Set new refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="strict",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/api/google-auth"
    )
    
    # For simplicity, we return a simple JWT here
    # In production, you might exchange with Google for a new ID token
    # or issue your own JWT signed with your secret
    
    # For now, client should re-authenticate with Google if access token expires
    # This endpoint primarily demonstrates refresh token rotation
    
    # Audit log
    await create_audit_log(
        user_id=user.id,
        event_type="token_refresh",
        event_data=None,
        request=request
    )
    
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Client should re-authenticate with Google for new access token"
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(None, alias="refresh_token"),
    current_user: User = Depends(get_current_user)
):
    """
    Logout current user by revoking refresh token.
    """
    if refresh_token:
        await revoke_refresh_token(refresh_token)
    
    # Clear refresh token cookie
    response.delete_cookie(key="refresh_token", path="/api/google-auth")
    
    # Audit log
    await create_audit_log(
        user_id=current_user.id,
        event_type="logout",
        event_data=None,
        request=request
    )
    
    return {"message": "Logged out successfully"}


@router.post("/logout-all")
async def logout_all_devices(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user)
):
    """
    Logout from all devices by revoking all refresh tokens for user.
    """
    await revoke_all_user_tokens(current_user.id)
    
    # Clear current device's refresh token cookie
    response.delete_cookie(key="refresh_token", path="/api/google-auth")
    
    # Audit log
    await create_audit_log(
        user_id=current_user.id,
        event_type="logout_all",
        event_data=None,
        request=request
    )
    
    return {"message": "Logged out from all devices"}


@router.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current authenticated user information.
    Protected endpoint example.
    """
    return User(
        id=current_user.id,
        email=current_user.email,
        username=current_user.name,
        avatar=current_user.picture,
        is_email_verified=current_user.email_verified
    )
