# --- Cookie Management ---
from datetime import timedelta


def set_refresh_cookie(response, refresh_token: str, expires_in_days: int):
    """
        Set a secure HttpOnly refresh cookie.
        - Path: /auth/refresh (restrict where cookie is sent)
        - HttpOnly: True (not accessible to JavaScript)
        - Secure: True (HTTPS only, set False in dev if needed)
        - SameSite: 'lax' (SPA friendly) or 'strict' if your UX allows
    """
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=expires_in_days * 24 * 60 * 60, # Convert days to seconds
        expires=timedelta(days=expires_in_days),
        path="/api/auth", # Crucial: limits cookie scope to auth endpoints
    )

def clear_refresh_cookie(response):
    response.delete_cookie(
        key="refresh_token",
        httponly=True,
        secure=True,
        samesite="Lax",
        path="/api/auth",
    )