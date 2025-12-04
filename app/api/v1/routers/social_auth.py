from typing import Annotated, Dict, Any
from fastapi import APIRouter, Response, HTTPException, status, Depends, Cookie
from fastapi.security import HTTPBearer
import httpx

from app.api.v1.schemas import GoogleUserInfo
from app.api.v1.services import create_or_update_user, get_current_user, verify_google_id_token
from app.core.services import HTTPClientManager, get_http_client_manager
from app.core.helpers import clear_refresh_cookie, create_refresh_token, create_access_token, set_refresh_cookie, verify_jwt_token
from app.core.schemas import TokenResponse, SocialUser as User, CodeExchangeRequest
from app.core.config import settings

security = HTTPBearer()

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
# --- Provider Configuration Mapping (Scalability Layer) ---
PROVIDER_CONFIGS: Dict[str, Dict[str, str]] = {
    "google": {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "token_url": "https://oauth2.googleapis.com/token",
    },
    "microsoft": {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    },
    # Add 'github' here when ready
}


def standardize_claims(provider: str, payload: Dict[str, Any]) -> Any: # Tuple[str, Dict[str, Any]]:
    """
    Enterprise Standard: Converts provider-specific ID token claims into a
    standardized dictionary for internal use (Upsert).

    Returns: (provider_user_id, standardized_user_data)

    {
        "at_hash": "0S-3T1h9uOD3X7X7OXhlow",
        "aud": "1034657792918-o2miscccej64q171kjm27rckjr4hbvbc.apps.googleusercontent.com",
        "azp": "1034657792918-o2miscccej64q171kjm27rckjr4hbvbc.apps.googleusercontent.com",
        "email": "name@example.com",
        "email_verified": True,
        "exp": 1764618360,
        "family_name": "Doe",
        "given_name": "John",
        "iat": 1764614760,
        "iss": "https://accounts.google.com",
        "name": "John Doe",
        "picture": "https://lh3.googleusercontent.com/a/ACg8ocIHjjBw6-c2TbgT5JkAAs6ZfUmF33j24OAEKyFJEDhVD06sOA=s96-c",
        "sub": "103528303292260204473"
    }
    """
    if provider == "google":
        return GoogleUserInfo(
            sub=payload.get("sub"),  # 'sub' is the unique user ID
            email=payload.get("email"),
            email_verified=payload.get("email_verified"),
            name=payload.get("name"),
            picture=payload.get("picture"),
            given_name=payload.get("given_name"),
            family_name=payload.get("family_name"),
            locale=payload.get("locale"),
        )

    elif provider == "microsoft":
        # Microsoft can use 'sub' or 'oid' for the unique identifier. We'll use 'sub'
        # for consistency, but 'oid' is often the best unique identifier for MS Azure tenants.
        return {
            "sub": payload.get("sub"),
            "email": payload.get("preferred_username") or payload.get("email"),
            "name": payload.get("name"),
            # Microsoft tokens generally include verified status if issued after login
            "is_verified": True,
        }

    raise ValueError("Unsupported provider")

# =================================================================
#                         Authentication Endpoints
# =================================================================

@router.post("/token", response_model=TokenResponse)
async def exchange_code_for_token(
        req: CodeExchangeRequest,
        response: Response,
        http_manager: Annotated[HTTPClientManager, Depends(get_http_client_manager)]
):
    """
    Handles SIGN UP/LOG IN for any supported social provider via PKCE code exchange.
    """
    # Check if provider is supported
    provider_config = PROVIDER_CONFIGS.get(req.provider)
    if not provider_config:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {req.provider}")

    # 1. Prepare Google Token Exchange Payload
    data = {
        "code": req.code,
        "client_id": provider_config["client_id"],
        "client_secret": provider_config["client_secret"],
        "redirect_uri": provider_config["redirect_uri"],
        "grant_type": "authorization_code",
        "code_verifier": req.code_verifier # PKCE verification
    }

    # 2. Execute Token Exchange using asynchronous httpx client
    client = http_manager.get_client()  # Get the shared, pooled client

    try:
        r = await client.post(provider_config["token_url"], data=data, timeout=10.0)  # Await the asynchronous request
        r.raise_for_status()
        provider_tokens = r.json()
    except httpx.RequestError as e:  # Catch the httpx-specific exception
        raise HTTPException(status_code=400, detail=f"{req.provider} token exchange failed: Connection error: {e}")
    except httpx.HTTPStatusError as e:
        error_content = e.response.text
        error_detail = f"{req.provider} token exchange failed: {error_content[:100]}..."
        raise HTTPException(status_code=400, detail=error_detail)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

    # 3. Extract and Standardize User Data
    # ID Token is required for user info
    id_token_str = provider_tokens.get("id_token")
    if not id_token_str:
        raise HTTPException(status_code=500, detail=f"No ID token received from {req.provider}")

    # Verify and decode id token
    id_token_payload = await verify_google_id_token(id_token_str)

    # Use the standardization function
    standardized_claims = standardize_claims(req.provider, id_token_payload)

    if not standardized_claims: # provider_user_id:
        raise HTTPException(status_code=500, detail=f"Could not extract unique user ID from {req.provider} token.")

    # 4. User Upsert (Sign Up or Log In) - Provider Agnostic
    user = await create_or_update_user(standardized_claims)

    # 5. Create Backend JWTsand Set Cookies
    # Use the application's internal ID (db_user.id) for JWT signing, not the provider id.
    # token_data = {"user_id": str(user.id)}
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    # 6. Set Secure HttpOnly Refresh Cookie
    set_refresh_cookie(response, refresh_token, settings.REFRESH_TOKEN_EXPIRE_DAYS)

    # 7. Return Access Token (Memory Token) and User
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Return in seconds
        user=user.model_dump() #.to_auth_user()  # Convert internal model to API model
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_session(
        response: Response,
        refresh_token: Annotated[str | None, Cookie(alias="refresh_token")] = None
):
    # 1. Check for Refresh Token Cookie
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token provided")

    # 2. Validate Refresh Token
    token_data = verify_jwt_token(refresh_token)
    if not token_data:
        # Token is invalid or expired - force client to log in
        clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    # 3. Check user exists and is active
    # This step is critical to ensure the user still exists and is active
    user_id = token_data.get("sub")


    # 4. Issue New Tokens (Refresh Token Rotation - Best Practice)
    new_access_token = create_access_token(user_id)
    new_refresh_token = create_refresh_token(user_id)

    # 5. Set New Refresh Cookie (Rotation)
    set_refresh_cookie(response, new_refresh_token, settings.REFRESH_TOKEN_EXPIRE_DAYS)

    # 6. Return New Access Token to Frontend
    return TokenResponse(
        access_token=new_access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user.model_dump()
    )


@router.post("/logout")
async def logout(response: Response):
    # Log out by clearing the secure HttpOnly cookie
    clear_refresh_cookie(response)
    # In a real app, you might also blacklist the Access Token here
    return {"message": "Successfully logged out"}


# =================================================================
#                         Protected Endpoints
# =================================================================

@router.get("/me", response_model=User)
async def get_current_user_details(
        current_user: Annotated[User, Depends(get_current_user)]
        # current_user: Annotated[User, Depends(get_current_user_from_access_token)]
):
    """
    Protected endpoint: Verifies a valid Access Token in the Authorization header.
    Used by the Angular APP_INITIALIZER to check session status.
    """
    return current_user

"""
@router.get("/data")
async def get_protected_data(
        credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
        current_user: Annotated[User, Depends(get_current_user(credentials))]
):
    # Example protected endpoint.
    return {"data": f"Hello, {current_user.name}. Your data is secured!"}
"""