from fastapi import Request, HTTPException, status
from datetime import datetime, timedelta
from typing import Dict, List

from app.core.config import settings


class RateLimiter:

    def __init__(self):
        self.requests: Dict[str, List[datetime]] = {}

    def is_allowed(self, client_ip: str, limit: int = settings.RATE_LIMIT_PER_MINUTE) -> bool:
        """Check if request is allowed based on rate limit."""
        now = datetime.utcnow()
        minute_ago = now - timedelta(minutes=1)

        if client_ip not in self.requests:
            self.requests[client_ip] = []

        # Clean old requests
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip]
            if req_time > minute_ago
        ]

        if len(self.requests[client_ip]) >= limit:
            return False

        self.requests[client_ip].append(now)
        return True


rate_limiter = RateLimiter()


async def check_rate_limit(request: Request):
    """Check rate limit for client IP."""
    client_ip = request.client.host
    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )