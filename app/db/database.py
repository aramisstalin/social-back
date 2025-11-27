import asyncpg
from typing import Optional
from contextlib import asynccontextmanager
from app.core.config import settings


class Database:
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
    
    async def connect(self):
        """Initialize database connection pool"""
        self.pool = await asyncpg.create_pool(
            settings.DATABASE_URL,
            min_size=5,
            max_size=20,
            command_timeout=60
        )
    
    async def disconnect(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
    
    @asynccontextmanager
    async def transaction(self):
        """Context manager for database transactions"""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                yield conn


db = Database()