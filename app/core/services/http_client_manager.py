from functools import lru_cache

import httpx
from app.core.config import settings
from typing import Optional


class HTTPClientManager:
    """Manages HTTP client with connection pooling and configuration."""

    def __init__(self):
        self.client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self.client is None:
            self.client = httpx.AsyncClient(
                timeout=httpx.Timeout(settings.REQUEST_TIMEOUT),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=10),
                headers={"User-Agent": "FastAPI-External-API-Router/1.0"},
                verify=False
            )
        return self.client

    async def close(self):
        """Close HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None


@lru_cache
def get_http_client_manager() -> HTTPClientManager:
    """Get a singleton instance of HTTPClientManager."""
    return HTTPClientManager()
