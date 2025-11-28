from sqlalchemy.ext.declarative import declarative_base
from app.core.config import settings
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=False,  # Set to True to see generated SQL statements
    )

AsyncSessionLocal = async_sessionmaker(
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# Dependency to get DB session per request
async def get_db():
    """
    FastAPI dependency that provides a database session.
    It ensures the session is properly closed after the request is finished.
    """

    async with AsyncSessionLocal() as session:
        yield session