from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    String,
    DateTime,
    ForeignKey,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB, INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.models import Base


class AuditLog(Base):
    """
    Security / compliance audit log.
    - Tracks user activity (login, logout, refresh, API call).
    - Stores structured details inside JSONB.
    - Includes IP + User-Agent for risk detection.
    """

    __tablename__ = "audit_logs"

    # BIGSERIAL primary key (monotonic, useful for forensic ordering)
    id: Mapped[int] = mapped_column(
        primary_key=True,
        autoincrement=True,
    )

    # Nullable on-delete: log entries persist even after user removal
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Event category: login, logout, refresh, api_call, etc.
    event_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # Structured event metadata (payload)
    event_data: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
    )

    # IPv4 or IPv6 address
    ip_address: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
    )

    # Raw user agent string
    user_agent: Mapped[Optional[str]] = mapped_column(
        String,
        nullable=True,
    )

    # Timestamp (DB default)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"),
        index=True,
    )

    # Relationship back to user
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="audit_logs",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} user_id={self.user_id} "
            f"event_type={self.event_type}>"
        )
