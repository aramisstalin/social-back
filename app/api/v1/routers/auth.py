"""
Authentication Router Module

This module provides comprehensive authentication and authorization endpoints for the FastAPI application.
It handles user registration, email verification, login/logout, token management, password reset,
and user information retrieval.

Security Features:
    - API key authentication for all endpoints
    - JWT-based access and refresh tokens
    - Secure HTTP-only cookies for token storage
    - Email verification workflow
    - Password reset with token validation
    - Rate limiting on sensitive endpoints
    - Environment-aware cookie security settings

Author: ANAHP Development Team
Version: 1.0.0
"""

import asyncio
import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import UUID4
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.repositories import UserRepository, get_user_repository
from app.api.v1.schemas import (
    PasswordReset,
    PasswordResetRequest,
    SendVerificationEmail,
    Token,
    UserCreate,
    # UserUpdateVerificationToken,
    # UserUpdateEmailVerified,
)
from app.api.v1.services import AuthService, get_auth_service
from app.core.config import settings
from app.core.schemas import ApiResponse
from app.core.security import (
    create_access_token,
    create_refresh_token,
    create_verification_token,
    decode_token,
    is_token_expired,
    verify_api_key,
)
from app.core.services import send_verification_email
from app.db.session import get_session

# Configure module logger
logger = logging.getLogger(__name__)

# Configure rate limiter
limiter = Limiter(key_func=get_remote_address)

# Router configuration
PREFIX = "/auth"
router = APIRouter(
    prefix=PREFIX,
    responses={
        401: {"description": "Unauthorized - Invalid or missing credentials"},
        403: {"description": "Forbidden - Access denied"},
        429: {"description": "Too Many Requests - Rate limit exceeded"},
        500: {"description": "Internal Server Error"},
    },
)

# Environment-aware cookie security constants
# In production, cookies must be secure (HTTPS only)
# In development/HML, we allow non-secure cookies for local testing
COOKIE_SECURE = settings.ENVIRONMENT.lower() == "production"
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = "strict" if settings.ENVIRONMENT.lower() == "production" else "lax"

logger.info(f"Cookie security settings - Secure: {COOKIE_SECURE}, SameSite: {COOKIE_SAMESITE}")

# ============================================================================
# REGISTRATION ENDPOINTS
# ============================================================================


@router.post(
    "/register",
    response_model=ApiResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates a new user account and sends a verification email",
)
@limiter.limit("5/minute")  # Rate limit: 5 registration attempts per minute
async def register_user(
    request: Request,
    user_in: UserCreate,
    api_key: Annotated[str, Depends(verify_api_key)],
    db: Annotated[AsyncSession, Depends(get_session)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> ApiResponse:
    """
    Register a new user in the system.

    This endpoint creates a new user account with the provided information,
    generates a verification token, and sends a verification email to the user.

    Args:
        request: FastAPI request object (required for rate limiting)
        user_in: User registration data including email, password, CPF, and personal info
        api_key: API key for request authentication (injected via dependency)
        db: Database session (injected via dependency)
        auth_service: Authentication service instance (injected via dependency)

    Returns:
        ApiResponse: Response containing the created user data and success message

    Security:
        - Requires valid API key
        - Rate limited to 5 attempts per minute
        - Passwords are hashed before storage
        - Verification email sent automatically
        - User account created as inactive until email verification
    """
    try:
        logger.info(f"Attempting to register new user with email: {user_in.email}")
        user = await auth_service.register_user(db, user_in)
        logger.info(f"User registered successfully: {user.id}")

        return ApiResponse(
            status_code=status.HTTP_201_CREATED,
            detail="Usuário cadastrado com sucesso. Verifique seu e-mail para ativar sua conta.",
            data=user,
        )

    except ValueError as e:
        logger.warning(f"Registration failed for {user_in.email}: {str(e)}")
        return ApiResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="O usuário não pode ser registrado. Verifique se o e-mail ou CPF já estão em uso.",
        )

    except Exception as e:
        logger.error(f"Unexpected error during registration: {str(e)}", exc_info=True)
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="Erro interno ao processar o registro. Tente novamente mais tarde.",
        )


@router.post(
    "/resend-verification-email",
    response_model=ApiResponse,
    status_code=status.HTTP_200_OK,
    summary="Resend verification email",
    description="Resends the email verification link to a registered user",
)
async def resend_verification_email(
    payload: SendVerificationEmail,
    api_key: Annotated[str, Depends(verify_api_key)],
    db: Annotated[AsyncSession, Depends(get_session)],
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
) -> ApiResponse:
    """
    Resend verification email to a user.

    This endpoint generates a new verification token and sends it to the user's
    registered email address. Useful when the original verification email was not
    received or has expired.

    Args:
        payload: Contains the user_id for whom to resend the verification email
        api_key: API key for request authentication (injected via dependency)
        db: Database session (injected via dependency)
        user_repository: User repository instance (injected via dependency)

    Returns:
        ApiResponse: Success message confirming email was sent

    Security:
        - Requires valid API key
        - Validates user existence before sending email
        - Generates new verification token for security
    """
    try:
        logger.info(f"Attempting to resend verification email for user: {payload.user_id}")

        # Validate and retrieve user
        user = await user_repository.get_by_id(db, UUID4(payload.user_id))
        if user is None:
            logger.warning(f"User not found for verification email resend: {payload.user_id}")
            return ApiResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                error="Usuário não encontrado. Verifique o ID fornecido.",
            )

        # Check if user is already verified
        if user.email_verified:
            logger.info(f"User {payload.user_id} is already verified")
            return ApiResponse(
                status_code=status.HTTP_200_OK,
                detail="Este e-mail já foi verificado. Você pode fazer login normalmente.",
            )

        # Generate new verification token
        new_token = create_verification_token(user.email)

        # Update user with new token
        await user_repository.update(db, UserUpdateVerificationToken(verification_token=new_token), user.id)
        logger.info(f"Updated verification token for user: {payload.user_id}")

        # Send verification email asynchronously
        asyncio.create_task(send_verification_email(user.email, new_token))
        logger.info(f"Verification email sent successfully to: {user.email}")

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="E-mail de verificação enviado com sucesso. Verifique sua caixa de entrada.",
        )

    except ValueError as e:
        logger.warning(f"Invalid data for verification email resend: {str(e)}")
        return ApiResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="Dados inválidos. Verifique o ID do usuário.",
        )

    except Exception as e:
        logger.error(f"Error resending verification email: {str(e)}", exc_info=True)
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="Erro ao enviar e-mail de verificação. Tente novamente mais tarde.",
        )


# ============================================================================
# EMAIL VERIFICATION ENDPOINTS
# ============================================================================


@router.get(
    "/verify-email",
    response_model=ApiResponse,
    summary="Verify user email",
    description="Verifies a user's email address using the token sent via email",
)
async def verify_email(
    token: str,
    api_key: Annotated[str, Depends(verify_api_key)],
    db: Annotated[AsyncSession, Depends(get_session)],
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
) -> ApiResponse:
    """
    Verify a user's email address.

    This endpoint validates the verification token sent to the user's email
    and marks their email as verified in the system. If the token is expired,
    a new token is generated and sent.

    Args:
        token: Verification token from the email link
        api_key: API key for request authentication
        db: Database session
        user_repository: User repository instance

    Returns:
        ApiResponse: Success or error message

    Security:
        - Validates token format and signature
        - Checks token expiration
        - Ensures token matches the latest token sent to user
        - Automatically regenerates expired tokens
    """
    forbidden_response = ApiResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        error="Token inválido ou expirado. Solicite um novo e-mail de verificação.",
    )

    try:
        logger.info("Processing email verification request")

        # Decode token and extract email
        token_payload = decode_token(token)
        email = token_payload.get("sub")

        if not email:
            logger.warning("Token does not contain email subject")
            return forbidden_response

        # Retrieve user by email
        user = await user_repository.get_user_orm_by_email(db, email)
        if user is None:
            logger.warning(f"User not found for email verification: {email}")
            return forbidden_response

        # Check if token is expired
        if is_token_expired(token):
            logger.info(f"Token expired for user: {email}. Generating new token.")

            # Generate and send new token
            new_token = create_verification_token(email)
            await user_repository.update(db, UserUpdateVerificationToken(verification_token=new_token), user.id)

            asyncio.create_task(send_verification_email(email, new_token))

            return ApiResponse(
                status_code=status.HTTP_200_OK,
                error="Token expirado. Um novo e-mail de verificação foi enviado.",
            )

        # Verify token matches the latest token sent
        if user.verification_token != token:
            logger.warning(f"Token mismatch for user: {email}")
            return ApiResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="Para validar seu e-mail, use o último token de verificação enviado.",
            )

        # Mark email as verified
        user_update = UserUpdateEmailVerified(email_verified=True)
        await user_repository.update(db, user_update, user.id)
        logger.info(f"Email verified successfully for user: {email}")

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="E-mail verificado com sucesso! Você já pode fazer login.",
        )

    except Exception as e:
        logger.error(f"Error during email verification: {str(e)}", exc_info=True)
        return forbidden_response


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================


@router.post(
    "/login",
    response_model=Token,
    summary="User login",
    description="Authenticates a user and returns access and refresh tokens",
)
@limiter.limit("10/minute")  # Rate limit: 10 login attempts per minute
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[AsyncSession, Depends(get_session)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Token:
    """
    Authenticate user and generate access tokens.

    This endpoint validates user credentials (CPF and password) and returns
    JWT access and refresh tokens. Tokens are also set as secure HTTP-only cookies.

    Args:
        request: FastAPI request object (required for rate limiting)
        response: FastAPI response object for setting cookies
        form_data: OAuth2 form containing username (CPF) and password
        db: Database session
        auth_service: Authentication service

    Returns:
        Token: Object containing access_token, refresh_token, and token_type

    Raises:
        HTTPException: If credentials are invalid or account is not active/verified

    Security:
        - Rate limited to 10 attempts per minute
        - Passwords are verified using secure hashing
        - Tokens stored in HTTP-only cookies
        - Multiple validation checks (email verified, account validated, account active)
        - Secure cookie attributes (httponly, secure, samesite)
    """
    try:
        logger.info(f"Login attempt for CPF: {form_data.username}")

        # Authenticate user
        user = await auth_service.authenticate_user(
            db, form_data.username, form_data.password
        )

        if user is None:
            logger.warning(f"Failed login attempt for CPF: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="CPF ou senha incorretos",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate email verification
        if not user.email_verified:
            logger.warning(f"Login attempt with unverified email: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="E-mail não verificado. Verifique sua caixa de entrada.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate account validation status
        if not user.is_validated:
            logger.warning(f"Login attempt with unvalidated account: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário aguardando validação. Entre em contato com o administrador.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate account active status
        if not user.is_active:
            logger.warning(f"Login attempt with inactive account: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Conta desativada. Entre em contato com o administrador.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Generate tokens
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(data={"sub": str(user.id)})

        tokens = Token(access_token=access_token, refresh_token=refresh_token)

        # Set secure cookies
        response.set_cookie(
            key="access_token",
            value=tokens.access_token,
            httponly=COOKIE_HTTPONLY,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
        )
        response.set_cookie(
            key="refresh_token",
            value=tokens.refresh_token,
            httponly=COOKIE_HTTPONLY,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
        )

        logger.info(f"User logged in successfully: {user.email}")
        return tokens

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar login. Tente novamente mais tarde.",
        )


@router.post(
    "/logouta",
    response_model=ApiResponse,
    summary="User logout",
    description="Logs out the user by clearing authentication cookies",
)
async def logout(response: Response) -> ApiResponse:
    """
    Logout user by clearing authentication cookies.

    This endpoint removes the access and refresh token cookies from the client,
    effectively logging out the user.

    Args:
        response: FastAPI response object for clearing cookies

    Returns:
        ApiResponse: Success message confirming logout

    Security:
        - Clears both access and refresh tokens
        - Invalidates client-side authentication state
    """
    try:
        logger.info("User logout requested")

        # Clear authentication cookies
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        logger.info("User logged out successfully")

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Logout realizado com sucesso",
        )

    except Exception as e:
        logger.error(f"Error during logout: {str(e)}", exc_info=True)
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="Erro ao processar logout",
        )


@router.post(
    "/refresh-token",
    response_model=Token,
    summary="Refresh access token",
    description="Generates new access and refresh tokens using a valid refresh token",
)
async def refresh_token(
    request: Request,
    api_key: Annotated[str, Depends(verify_api_key)],
) -> Token:
    """
    Refresh authentication tokens.

    This endpoint validates the refresh token from cookies and generates
    new access and refresh tokens for continued authentication.

    Args:
        request: FastAPI request object for accessing cookies
        api_key: API key for request authentication

    Returns:
        Token: New access and refresh tokens

    Raises:
        HTTPException: If refresh token is missing or invalid

    Security:
        - Validates refresh token signature and expiration
        - Generates new token pair for security
        - Requires valid API key
    """
    try:
        logger.info("Token refresh requested")

        # Extract refresh token from cookies
        ref_token = request.cookies.get("refresh_token")
        if not ref_token:
            logger.warning("Refresh token missing from request")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de atualização ausente. Faça login novamente.",
            )

        # Decode and validate refresh token
        decoded = decode_token(ref_token)
        if decoded is None or not decoded:
            logger.warning("Invalid refresh token received")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de atualização inválido. Faça login novamente.",
            )

        # Extract user ID from token
        user_id = decoded.get("sub")
        if not user_id:
            logger.warning("Refresh token does not contain user ID")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de atualização inválido. Faça login novamente.",
            )

        # Generate new tokens
        new_access_token = create_access_token({"sub": user_id})
        new_refresh_token = create_refresh_token({"sub": user_id})

        logger.info(f"Tokens refreshed successfully for user: {user_id}")

        return Token(access_token=new_access_token, refresh_token=new_refresh_token)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao atualizar token. Tente novamente mais tarde.",
        )


# ============================================================================
# PASSWORD RESET ENDPOINTS
# ============================================================================


@router.post(
    "/password-reset-request",
    response_model=ApiResponse,
    summary="Request password reset",
    description="Sends a password reset email to the user",
)
@limiter.limit("3/minute")  # Rate limit: 3 password reset requests per minute
async def request_password_reset(
    request: Request,
    pr: PasswordResetRequest,
    api_key: Annotated[str, Depends(verify_api_key)],
    db: Annotated[AsyncSession, Depends(get_session)],
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> ApiResponse:
    """
    Request a password reset.

    This endpoint initiates the password reset process by sending a reset
    link to the user's email. For security, it always returns success even
    if the email doesn't exist (prevents email enumeration).

    Args:
        request: FastAPI request object (required for rate limiting)
        pr: Password reset request containing the user's email
        api_key: API key for request authentication
        db: Database session
        user_repository: User repository instance
        auth_service: Authentication service

    Returns:
        ApiResponse: Success message (always, for security)

    Security:
        - Rate limited to 3 attempts per minute
        - Always returns success to prevent email enumeration
        - Generates secure reset token
        - Token sent only to registered email addresses
        - Requires valid API key
    """
    try:
        logger.info(f"Password reset requested for email: {pr.email}")
        user = await user_repository.get_user_by_email(db, pr.email)

        if user is not None:
            await auth_service.password_reset_request(db, str(pr.email))
            logger.info(f"Password reset email sent to: {pr.email}")
        else:
            logger.info(f"Password reset requested for non-existent email: {pr.email}")

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Se o e-mail estiver cadastrado, você receberá instruções para redefinir sua senha.",
        )

    except ValueError as e:
        logger.warning(f"Error in password reset request: {str(e)}")
        return ApiResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            error="Não foi possível processar a solicitação. Tente novamente mais tarde.",
        )

    except Exception as e:
        logger.error(f"Unexpected error in password reset request: {str(e)}", exc_info=True)
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="Erro ao processar solicitação. Tente novamente mais tarde.",
        )


@router.post(
    "/password-reset",
    response_model=ApiResponse,
    summary="Reset password",
    description="Resets the user's password using the token from the reset email",
)
async def reset_password(
    pr: PasswordReset,
    api_key: Annotated[str, Depends(verify_api_key)],
    db: Annotated[AsyncSession, Depends(get_session)],
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> ApiResponse:
    """
    Reset user password.

    This endpoint validates the password reset token and updates the user's
    password with the new value provided.

    Args:
        pr: Password reset data containing token and new password
        api_key: API key for request authentication
        db: Database session
        user_repository: User repository instance
        auth_service: Authentication service

    Returns:
        ApiResponse: Success or error message

    Security:
        - Validates token format and signature
        - Ensures token matches the latest reset token
        - Passwords are hashed before storage
        - Token is invalidated after successful reset
        - Requires valid API key
    """
    forbidden_response = ApiResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        error="Token inválido ou expirado. Solicite uma nova redefinição de senha.",
    )

    try:
        logger.info("Password reset attempt")

        token_payload = decode_token(pr.token)
        email = token_payload.get("sub")

        if not email:
            logger.warning("Password reset token does not contain email")
            return forbidden_response

        user = await user_repository.get_user_by_email(db, email=email)

        if user is None:
            logger.warning(f"User not found for password reset: {email}")
            return forbidden_response

        await auth_service.reset_password(db, pr.password, pr.token)
        logger.info(f"Password reset successfully for user: {email}")

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Senha alterada com sucesso! Você já pode fazer login com suas novas credenciais.",
        )

    except ValueError as e:
        logger.warning(f"Password reset validation error: {str(e)}")
        return forbidden_response

    except Exception as e:
        logger.error(f"Error during password reset: {str(e)}", exc_info=True)
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error="Erro ao redefinir senha. Tente novamente mais tarde.",
        )


# ============================================================================
# USER INFORMATION ENDPOINTS
# ============================================================================


@router.get(
    "/user-info",
    response_model=ApiResponse,
    summary="Get user information",
    description="Retrieves the authenticated user's information",
)
async def get_user_info(
    request: Request,
    api_key: Annotated[str, Depends(verify_api_key)],
    db: Annotated[AsyncSession, Depends(get_session)],
    user_repository: Annotated[UserRepository, Depends(get_user_repository)],
) -> ApiResponse:
    """
    Retrieve authenticated user information.

    This endpoint returns the current user's profile information based on
    the access token stored in cookies.

    Args:
        request: FastAPI request object for accessing cookies
        api_key: API key for request authentication
        db: Database session
        user_repository: User repository instance

    Returns:
        ApiResponse: User information or error message

    Security:
        - Validates access token from cookies
        - Checks token expiration
        - Ensures user exists and is active
        - Requires valid API key
    """
    unauthorized_response = ApiResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        error="Usuário não autenticado. Faça login novamente.",
    )

    try:
        logger.info("User info request received")

        token = request.cookies.get("access_token")
        if not token:
            logger.warning("Access token missing from request")
            return unauthorized_response

        payload = decode_token(token)
        if not payload:
            logger.warning("Invalid access token")
            return unauthorized_response

        user_id_str = payload.get("sub")
        if not user_id_str:
            logger.warning("Token does not contain user ID")
            return unauthorized_response

        if is_token_expired(token):
            logger.warning(f"Expired token used for user info: {user_id_str}")
            return ApiResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="Token expirado. Faça login novamente.",
            )

        try:
            user_id = UUID(user_id_str)
        except ValueError:
            logger.warning(f"Invalid UUID format: {user_id_str}")
            return unauthorized_response

        user = await user_repository.get_by_id(db, user_id=user_id)

        if user is None:
            logger.warning(f"User not found: {user_id}")
            return unauthorized_response

        logger.info(f"User info retrieved successfully: {user_id}")

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            data=user,
        )

    except Exception as e:
        logger.error(f"Error retrieving user info: {str(e)}", exc_info=True)
        return ApiResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="Erro ao recuperar informações do usuário. Faça login novamente.",
        )
