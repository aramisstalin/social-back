"""
Asyncpg Database Manager

This module provides enterprise-grade, asynchronous connection pooling and
transaction management for PostgreSQL using the high-performance 'asyncpg' driver.

It encapsulates the database setup, connection/disconnection lifecycle, and provides
safe, request-scoped dependencies (connections and transactions) for use in
frameworks like FastAPI.

Classes:
    AsyncpgDatabaseManager: Manages the asyncpg connection pool and lifecycle.

Functions:
    get_connection: FastAPI dependency for acquiring a non-transactional connection.
    get_transaction_connection: FastAPI dependency for acquiring a connection within
                                an atomic transaction block.

Usage:
    The db_manager instance must be initialized using the .connect() method
    during application startup (e.g., in a FastAPI lifespan event) and
    cleaned up using .disconnect() upon shutdown.
"""

import asyncpg
from typing import Optional, AsyncGenerator
from contextlib import asynccontextmanager

# Assuming this path is correct for your settings module
from app.core.config import settings


# ----------------------------------------------------------------------
# 1. Database Manager Class
# ----------------------------------------------------------------------

class AsyncpgDatabaseManager:
    """
    Manages the lifecycle and pooling of connections for an asynchronous
    PostgreSQL database using the asyncpg driver.

    This class provides robust methods for initializing (connecting),
    shutting down (disconnecting), and safely managing transactions.
    """

    def __init__(self, database_url: str):
        """
        Initializes the Database Manager.

        Args:
            database_url (str): The connection string for the PostgreSQL database.
        """
        self._database_url = database_url
        self._pool: Optional[asyncpg.Pool] = None

    @property
    def pool(self) -> asyncpg.Pool:
        """
        Provides access to the initialized asyncpg connection pool.

        Raises:
            RuntimeError: If the pool has not been initialized via the connect() method.

        Returns:
            asyncpg.Pool: The active connection pool instance.
        """
        if self._pool is None:
            raise RuntimeError("Database connection pool is not initialized. Call .connect() first.")
        return self._pool

    async def connect(self):
        """
        Initializes the asynchronous database connection pool.

        The pool size and timeout settings are loaded from application settings.
        This method should typically be called during application startup (e.g., FastAPI lifespan event).

        Aspect	            Description
        What it Does	    Acquires a connection from the pool using db_manager.acquire_connection() and yields an asyncpg.Connection.
        Transaction State	No explicit transaction is started. You are running in autocommit mode for simple statements.
        When to Use	        For read-only operations (e.g., SELECT). You can also use it for simple INSERT, UPDATE, or DELETE statements that do not need to be grouped with other operations.
        Why Use It          It's slightly more efficient as it skips the overhead of starting and committing/rolling back an explicit transaction block (BEGIN/COMMIT).

        Example	async def get_user(conn: asyncpg.Connection = Depends(get_connection)):
        """
        # Note: asyncpg can accept the URL string directly for create_pool.
        self._pool = await asyncpg.create_pool(
            self._database_url,
            # Use specific settings for pool management
            min_size=settings.DB_POOL_MIN_SIZE,  # Use concrete settings variables
            max_size=settings.DB_POOL_MAX_SIZE,
            command_timeout=settings.DB_COMMAND_TIMEOUT_SECONDS,  # Timeout for individual commands
            # Other potential enterprise settings:
            # statement_cache_size=0, # Disable cache for certain complex setups
            # max_queries=50000, # Max queries before reconnecting a connection
        )

    async def disconnect(self):
        """
        Closes all connections in the database connection pool gracefully.

        This method should typically be called during application shutdown.
        It waits for all active connections to be returned before closing the pool.
        """
        if self._pool:
            await self._pool.close()
            self._pool = None  # Ensure it is set to None after closing

    @asynccontextmanager
    async def acquire_connection(self) -> AsyncGenerator[asyncpg.Connection, None]:
        """
        Context manager to acquire and release a single connection from the pool.

        This is useful for read operations or simple single-command executions.

        Yields:
            asyncpg.Connection: An asynchronous connection object.
        """
        async with self.pool.acquire() as conn:
            yield conn

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[asyncpg.Connection, None]:
        """
        Context manager for executing an atomic database transaction.

        Acquires a connection from the pool and starts a transaction block.
        If the block completes without exception, the transaction is committed;
        otherwise, it is automatically rolled back, and the connection is released.

        Yields:
            asyncpg.Connection: An asynchronous connection object within an active transaction.
        """
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                yield conn


# ----------------------------------------------------------------------
# 3. Instance Initialization (Using centralized settings)
# ----------------------------------------------------------------------

# Initialize the manager using the global settings.
db_manager = AsyncpgDatabaseManager(settings.DATABASE_URL)


# Optional: Define a simple utility function for dependency injection
# if the application uses a framework like FastAPI that benefits from it.
async def get_connection() -> AsyncGenerator[asyncpg.Connection, None]:
    """FastAPI dependency to acquire a connection for a request.

    Aspect	            Description
    What it Does	    Acquires a connection from the pool using db_manager.acquire_connection() and yields an asyncpg.Connection.
    Transaction State	No explicit transaction is started. You are running in autocommit mode for simple statements.
    When to Use	        For read-only operations (e.g., SELECT). You can also use it for simple INSERT, UPDATE, or DELETE statements that do not need to be grouped with other operations.
    Why Use It	        It's slightly more efficient as it skips the overhead of starting and committing/rolling back an explicit transaction block (BEGIN/COMMIT).

    Example	async def get_user(conn: asyncpg.Connection = Depends(get_connection)):
    """

    async with db_manager.acquire_connection() as conn:
        yield conn


async def get_transaction_connection() -> AsyncGenerator[asyncpg.Connection, None]:
    """FastAPI dependency to acquire a connection within a transaction for a request.

    Aspect	            Description
    What it Does	    Acquires a connection and immediately starts a transaction using db_manager.transaction(). It yields an asyncpg.Connection that is inside an active transaction.
    Transaction State	An explicit transaction is active (BEGIN). The connection will automatically COMMIT on success or ROLLBACK if an exception is raised in the route handler.
    When to Use	        For atomic operations where multiple SQL statements must succeed or fail as a single unit (e.g., transferring funds, creating a user and their profile settings).
    Why Use It	        Data Integrity: Ensures ACID properties. If the first statement succeeds but the second fails (e.g., a unique constraint error), the entire operation is rolled back, preventing partial, corrupt data.

    Example	async def create_order(conn: asyncpg.Connection = Depends(get_transaction_connection)):
    """

    async with db_manager.transaction() as conn:
        yield conn