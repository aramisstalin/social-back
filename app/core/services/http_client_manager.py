from functools import lru_cache
from typing import Optional, Awaitable
from contextlib import asynccontextmanager

import httpx
from app.core.config import settings  # Assuming you have a 'settings' object here

# Define the structure for the cleanup function
CleanupType = Awaitable[None]


class HTTPClientManager:
    """
    HTTPClientManager is a singleton class responsible for managing the global,
    persistent httpx.AsyncClient instance.

    It ensures connection pooling, timeout configurations, and header standardization
    are applied consistently across all external API calls (e.g., Google OAuth).

    This is an enterprise-grade pattern for high-performance, non-blocking I/O
    in asynchronous applications like FastAPI.
    """

    def __init__(self):
        """Initialize the client instance to None."""
        # The client will be created lazily on the first request
        self._client: Optional[httpx.AsyncClient] = None
        # Flag to prevent race conditions during initialization
        self._is_initialized: bool = False

    async def initialize(self):
        """
        Initializes the httpx.AsyncClient with defined global settings.
        Should only be called once, typically during application startup.
        """
        if self._is_initialized:
            return

        # Define limits for connection pooling, crucial for performance
        limits = httpx.Limits(
            max_keepalive_connections=settings.HTTPX_MAX_KEEPALIVE,
            max_connections=settings.HTTPX_MAX_CONNECTIONS,
            keepalive_expiry=settings.HTTPX_KEEPALIVE_EXPIRY,
        )

        # Timeout configuration: Default request timeout
        timeout = httpx.Timeout(settings.REQUEST_TIMEOUT)

        # Standard headers for identifying our service to external APIs
        headers = {
            "User-Agent": f"FastAPI-{settings.VERSION}-External-Router/{settings.VERSION}",
            "Accept": "application/json",
        }

        # NOTE on verify=False: This is generally unsafe in production.
        # Only use this in development/staging with proper justification.
        # In production, this should be True (the default).
        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            headers=headers,
            # Prefer True in production for certificate validation
            verify=settings.HTTPX_VERIFY_SSL
        )
        self._is_initialized = True

    def get_client(self) -> httpx.AsyncClient:
        """
        Provides direct access to the globally configured httpx.AsyncClient instance.
        Raises an error if the client has not been initialized.
        """
        if not self._client:
            raise RuntimeError("HTTPClientManager has not been initialized. Call initialize() first.")
        return self._client

    async def close(self) -> None:
        """
        Gracefully closes the underlying client session and connection pool.
        This must be called during application shutdown.
        """
        if self._client:
            await self._client.aclose()
            self._client = None
            self._is_initialized = False


@lru_cache
def get_http_client_manager() -> HTTPClientManager:
    """
    Dependency injector and singleton pattern implementation using lru_cache.
    Returns the single instance of the HTTPClientManager.
    """
    return HTTPClientManager()