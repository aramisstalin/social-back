from fastapi import Request
from typing import Callable


async def security_headers_middleware(request: Request, call_next: Callable):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "frame-ancestors 'none';"
    )
    #    "connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com; "
    #    "default-src 'self'; "
    #    "style-src 'self' 'unsafe-inline'; "
    #    "script-src 'self' https://accounts.google.com; "
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response