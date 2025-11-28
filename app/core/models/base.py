import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase
from sqlalchemy.dialects.postgresql import UUID


# -----------------------------------------------------------
# Base Configuration (required for Alembic/SQLAlchemy 2.0)
# -----------------------------------------------------------
class Base(DeclarativeBase):
    """Base class which provides automated table name
    and common columns like created_at."""
    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.now(timezone.utc)
    )
    # Allows models to be referenced generically
    type_annotation = 'Base'