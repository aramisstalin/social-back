from fastapi import Request
from typing import Callable

from app.core import settings


async def security_headers_middleware(request: Request, call_next: Callable):
    """
    Add security headers to all responses
    Mitigates: XSS, Clickjacking, MIME sniffing, etc.
    """
    response = await call_next(request)

    # Content Security Policy
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://accounts.google.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com; "
        "frame-ancestors 'none';"
        "base-uri 'self'; "
        "form-action 'self'"
    )

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # XSS protection (legacy browsers)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # HSTS (Strict Transport Security) - force HTTPS
    # Only set this if you have HTTPS properly configured
    if not settings.DEBUG:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    # Permissions policy (restrict browser features)
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response