# --- Cookie Management ---
def set_refresh_cookie(response, refresh_token: str, expires_in_days: int):
    # HttpOnly: Prevents JS access
    # Secure: HTTPS required
    # SameSite: CSRF protection
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=expires_in_days * 24 * 3600, # Convert days to seconds
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