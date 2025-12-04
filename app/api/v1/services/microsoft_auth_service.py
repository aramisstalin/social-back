import httpx
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import jwt, JWTError
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.api.v1.models.social_account import ProviderName
from app.core.config import settings
from app.api.v1.schemas import (
    MicrosoftTokenResponse,  # You must define this in schemas
    MicrosoftUserInfo,  # You must define this in schemas
    UserRead as User,
)
from app.db import db_manager

# --- Configuration Constants ---
# Use 'common' for multi-tenant apps, or a specific Tenant UUID for internal enterprise apps
TENANT_ID = getattr(settings, "MICROSOFT_TENANT_ID", "common")
DISCOVERY_URL = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration"

# --- Cache Globals ---
_jwks_cache: Optional[Dict] = None
_jwks_cache_time: Optional[datetime] = None
_authorization_endpoint: Optional[str] = None
_token_endpoint: Optional[str] = None
_jwks_uri: Optional[str] = None

security = HTTPBearer()


async def get_microsoft_discovery_config() -> Dict[str, Any]:
    """
    Fetches the OpenID Connect discovery document to dynamically
    resolve endpoints and key locations.
    """
    global _authorization_endpoint, _token_endpoint, _jwks_uri

    # Return cached values if they exist
    if _authorization_endpoint and _token_endpoint and _jwks_uri:
        return {
            "authorization_endpoint": _authorization_endpoint,
            "token_endpoint": _token_endpoint,
            "jwks_uri": _jwks_uri
        }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(DISCOVERY_URL, timeout=10.0)
            response.raise_for_status()
            config = response.json()

            _authorization_endpoint = config.get("authorization_endpoint")
            _token_endpoint = config.get("token_endpoint")
            _jwks_uri = config.get("jwks_uri")

            return config
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to fetch Microsoft discovery document: {str(e)}"
            )


async def get_microsoft_jwks() -> Dict:
    """Fetch and cache Microsoft's public keys for JWT verification"""
    global _jwks_cache, _jwks_cache_time

    # Cache for 24 hours
    if _jwks_cache and _jwks_cache_time:
        if datetime.now(timezone.utc) - _jwks_cache_time < timedelta(hours=24):
            return _jwks_cache

    # Ensure we have the JWKS URI
    config = await get_microsoft_discovery_config()
    jwks_url = config.get("jwks_uri")

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(jwks_url, timeout=10.0)
            response.raise_for_status()
            _jwks_cache = response.json()
            _jwks_cache_time = datetime.now(timezone.utc)
            return _jwks_cache
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to fetch Microsoft JWKS: {str(e)}"
            )


async def exchange_code_for_tokens(code: str, code_verifier: str) -> MicrosoftTokenResponse:
    """Exchange authorization code for tokens with Microsoft"""

    config = await get_microsoft_discovery_config()
    token_url = config.get("token_endpoint")

    token_data = {
        "code": code,
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
        # 'scope' is usually not required here if requested during auth code flow,
        # but good practice to include if scopes changed.
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                token_url,
                data=token_data,
                timeout=10.0
            )
            response.raise_for_status()
            return MicrosoftTokenResponse(**response.json())
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to exchange Microsoft code: {e.response.text}"
            )


async def get_microsoft_user_info(access_token: str) -> MicrosoftUserInfo:
    """
    Fetch user info from Microsoft Graph API.
    Graph API is preferred over ID Token claims for accuracy in profile data.
    """
    headers = {"Authorization": f"Bearer {access_token}"}

    # Select fields explicitly to prevent over-fetching
    # userPrincipalName is often used as a fallback for email in Azure AD
    graph_url = "https://graph.microsoft.com/v1.0/me?$select=id,displayName,givenName,surname,mail,userPrincipalName,preferredLanguage"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                graph_url,
                headers=headers,
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()

            # Normalization logic: Azure AD users might have 'mail' as null, fallback to UPN
            email = data.get("mail") or data.get("userPrincipalName")

            # Map Graph API response to our internal Schema
            user_info = {
                "sub": data.get("id"),  # Stable Microsoft ID
                "name": data.get("displayName"),
                "given_name": data.get("givenName"),
                "family_name": data.get("surname"),
                "email": email,
                "email_verified": True,  # Azure AD accounts are generally verified
                "picture": None,  # Retrieving photo requires a separate Graph call (/me/photo/$value)
                "locale": data.get("preferredLanguage", "en-US")
            }

            return MicrosoftUserInfo(**user_info)

        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to fetch Microsoft user info: {e.response.text}"
            )


async def verify_microsoft_id_token(id_token: str) -> Dict:
    """Verify Microsoft ID token signature and claims"""
    try:
        # Decode header to get key ID
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get("kid")

        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing key ID"
            )

        # Get Microsoft's public keys
        jwks = await get_microsoft_jwks()

        # Find matching key
        rsa_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                rsa_key = key
                break

        if not rsa_key:
            # Force cache refresh if key not found (key rotation scenario)
            global _jwks_cache_time
            _jwks_cache_time = None
            jwks = await get_microsoft_jwks()
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    rsa_key = key
                    break

            if not rsa_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: key not found"
                )

        # Determine allowed issuers based on tenant config
        # 'common' endpoint issues tokens with specific tenant IDs in the issuer url
        # Logic: If strict checking is required, we need to know the exact issuer string.
        # For multi-tenant apps, the issuer contains the specific tenant UUID.
        # We skip issuer check in decode() but validate it manually if it's a single tenant app.

        payload = jwt.decode(
            id_token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.MICROSOFT_CLIENT_ID,
            options={"verify_iss": False}  # We verify issuer manually below
        )

        # Manual Issuer Validation
        iss = payload.get("iss")
        if settings.MICROSOFT_TENANT_ID != "common":
            expected_iss = f"https://login.microsoftonline.com/{settings.MICROSOFT_TENANT_ID}/v2.0"
            if iss != expected_iss:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token: issuer mismatch. Expected {expected_iss}, got {iss}"
                )
        else:
            # Sanity check for multi-tenant: must be from microsoft online
            if "login.microsoftonline.com" not in iss:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token: untrusted issuer"
                )

        # Check expiration
        exp = payload.get("exp")
        if not exp or datetime.fromtimestamp(exp, timezone.utc) < datetime.now(timezone.utc):
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


async def create_or_update_user(user_info: MicrosoftUserInfo) -> User:
    """Create new user or update existing user in database"""

    # Microsoft mapping: sub -> provider_user_id
    # Note: Microsoft Graph IDs are unique and stable.

    async with db_manager.transaction() as conn:
        # Check if user exists
        existing_user = await conn.fetchrow(
            f"SELECT * FROM social_accounts WHERE provider_name = $1 AND provider_user_id = $2",
            ProviderName.microsoft,  # Ensure this Enum exists
            user_info.sub
        )

        now = datetime.now(timezone.utc)

        if existing_user:
            # Update existing user
            # Note: We do NOT update email here blindly if it's null from Microsoft
            # but schemas usually enforce email presence.
            user_record = await conn.fetchrow("""
                UPDATE users
                SET email = $1, 
                    is_email_verified = $2,
                    name = $3,
                    avatar = COALESCE($4, avatar), -- Keep existing avatar if Microsoft doesn't return one
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
            """, ProviderName.microsoft, user_info.sub, user_record.get("id")
                                )

        return User(**dict(user_record))


async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Dependency to extract and verify current user from JWT token.
    This assumes the client is sending the Microsoft ID Token.
    """
    token = credentials.credentials

    try:
        # Verify Microsoft ID token
        payload = await verify_microsoft_id_token(token)

        # Microsoft uses 'sub' as the unique immutable identifier in v2 tokens (mapped to user_id in DB)
        # OR 'oid' (Object ID) depending on configuration.
        # We standardized on 'sub' in create_or_update_user.
        microsoft_id = payload.get("sub")

        if not microsoft_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject"
            )

        # Fetch user from database
        # Note: join with social_accounts to find by provider ID
        # because users table might not have a direct 'microsoft_id' column
        # unless you added it specifically like 'google_id' in your example.
        # Assuming a normalized approach here:
        conn = await db_manager.connect()
        try:
            user_record = await conn.fetchrow("""
                SELECT u.* FROM users u
                JOIN social_accounts sa ON u.id = sa.user_id
                WHERE sa.provider_name = $1 
                AND sa.provider_user_id = $2
                AND u.is_active = TRUE
            """, ProviderName.microsoft, microsoft_id)
        finally:
            await conn.close()

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