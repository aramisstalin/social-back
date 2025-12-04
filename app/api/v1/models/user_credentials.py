from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    ForeignKey,
    String,
    UniqueConstraint,
    DateTime,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.models import Base


class UserCredential(Base):
    """
    Secure storage for user authentication secrets.

    This table isolates password hashes from the main user profile for increased
    security, which is considered best practice in enterprise IAM architectures.

    Passwords are never stored directly—only secure, computationally expensive,
    industry-standard password hashes (Argon2, PBKDF2, bcrypt, scrypt, etc.).

    Each user MUST have at most one credential record (1-to-1 relationship).
    """

    __tablename__ = "user_credentials"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            name="uq_user_credentials_user_id"
        ),
    )

    # -------------------------------------------------------------------------
    # Primary Key
    # -------------------------------------------------------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        nullable=False,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),  # PostgreSQL-side UUID gen
    )

    # -------------------------------------------------------------------------
    # Foreign Key to User (One-to-One)
    # -------------------------------------------------------------------------
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "users.id",
            ondelete="CASCADE"  # cascade ensures credentials deleted with user
        ),
        nullable=False,
        unique=True,
        index=True,
    )

    # -------------------------------------------------------------------------
    # Security Fields
    # -------------------------------------------------------------------------
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Secure password hash (Argon2, PBKDF2, etc.)"
    )

    # Optional if your hashing algorithm internally handles salting
    password_salt: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        doc="Optional per-user salt (if not using implicit hashing salt)."
    )

    last_password_change_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Timestamp of the last password update. Useful for audits & security."
    )

    # -------------------------------------------------------------------------
    # Timestamps
    # -------------------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    # -------------------------------------------------------------------------
    # Relationship Back to User
    # -------------------------------------------------------------------------
    user: Mapped["User"] = relationship(
        "User",
        back_populates="credentials",
        lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<UserCredential(id={self.id}, user_id={self.user_id})>"
