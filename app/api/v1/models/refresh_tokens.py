from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String,
    DateTime,
    ForeignKey,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.models import Base


class RefreshToken(Base):
    """
    Secure refresh token storage.
    - Stores only SHA-256 hash of the token.
    - Supports token rotation by linking replacement token.
    - Tracks device info, expiration, revocation.
    """

    __tablename__ = "refresh_tokens"

    # Primary Key — UUID v4 (PostgreSQL native)
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        nullable=False,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    # FK to users.id (CASCADE delete ensures cleanup on user removal)
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Store SHA-256 hash instead of plaintext token
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        doc="Hex-encoded SHA256(token)"
    )

    # Expiration timestamp
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    # Creation timestamp (DB-default and Python fallback)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("NOW()"), # Set the default value in the db
        default=datetime.now(timezone.utc),
    )

    # Null when active; set when manually or automatically revoked
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Rotation link: the new token that replaced this one
    replaced_by_token_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )

    # JSONB metadata: IP, device, browser, OS…
    device_info: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
    )

    # Relationship back to user
    user: Mapped["User"] = relationship(
        "User",
        back_populates="refresh_tokens",
        lazy="selectin",
    )

    # Relationship to the replacing token (for token rotation chains)
    replaced_by: Mapped[Optional["RefreshToken"]] = relationship(
        "RefreshToken",
        remote_side=[id],
        lazy="selectin",
    )

    __table_args__ = (
        Index("idx_refresh_token_expires_at", "expires_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<RefreshToken id={self.id} "
            f"user_id={self.user_id} "
            f"expires_at={self.expires_at}>"
        )
