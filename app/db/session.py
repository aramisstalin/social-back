from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
    AsyncEngine,
)
from sqlalchemy.orm import declarative_base

# Assuming this path is correct for your settings module
from app.core.config import settings

# ----------------------------------------------------------------------
# 1. Base Declaration
# ----------------------------------------------------------------------

# The base class which your model classes will inherit from.
# It connects the model definitions to the SQLAlchemy ORM.
Base = declarative_base()


# ----------------------------------------------------------------------
# 2. Database Manager Class
# ----------------------------------------------------------------------

class DatabaseManager:
    """
    Manages the SQLAlchemy AsyncEngine and the AsyncSession factory.

    Encapsulates database connection setup and session creation logic for
    the application. This centralizes configuration and allows for easier
    testing or modification of the database backend.
    """

    def __init__(self, db_url: str):
        """
        Initializes the DatabaseManager with the database connection URL.

        Args:
            db_url (str): The connection string for the asynchronous database driver.
        """
        # Engine setup (internal variable)
        self._engine: AsyncEngine = create_async_engine(
            db_url,
            # Checks connection validity on pool checkout. Good practice for robust systems.
            pool_pre_ping=True,
            # Set to True only for debugging generated SQL.
            echo=bool(settings.DEBUG),
        )

        # Session factory (internal variable)
        # Renamed from AsyncSessionLocal to AsyncSessionFactory for clarity.
        self._async_session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            class_=AsyncSession,
            expire_on_commit=False,  # Prevents unnecessary loading of objects after a commit.
            autocommit=False,
            autoflush=False,
            bind=self._engine,
        )

    @property
    def engine(self) -> AsyncEngine:
        """
        Provides access to the configured SQLAlchemy AsyncEngine.

        Returns:
            AsyncEngine: The configured engine instance.
        """
        return self._engine

    @property
    def async_session_factory(self) -> async_sessionmaker[AsyncSession]:
        """
        Provides access to the configured asynchronous session maker.

        Returns:
            async_sessionmaker[AsyncSession]: The session factory.
        """
        return self._async_session_factory


# Initialize the DatabaseManager with the URL from settings
db_manager = DatabaseManager(settings.ASYNC_DATABASE_URL)


# ----------------------------------------------------------------------
# 3. FastAPI Dependency
# ----------------------------------------------------------------------

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a transactional database session per request.

    This function is designed to be used with `Depends()` in FastAPI route handlers.
    It uses a context manager (`async with`) to ensure the session is properly
    closed (and rollback/commit handled implicitly in the context) after the
    request has finished, regardless of whether an exception occurred.

    Yields:
        AsyncSession: An asynchronous SQLAlchemy session bound to the database.
    """
    # Use the session factory from the manager instance
    async_session_factory = db_manager.async_session_factory

    # Use the context manager for robust connection handling
    async with async_session_factory() as session:
        yield session