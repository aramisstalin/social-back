import uuid
from datetime import datetime, timezone
from typing import Optional

#from sqlalchemy import Column, UniqueConstraint, func
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import relationship, Mapped, mapped_column
from fastapi_users.db import SQLAlchemyBaseUserTable, SQLAlchemyUserDatabase
from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyBaseAccessTokenTable

from app.core.models import Base

"""
class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("id"),
        UniqueConstraint("cpf"),
        UniqueConstraint("email"),
    )

    id = Column(UNIQUEIDENTIFIER, primary_key=True, default=uuid.uuid4)
    cpf = Column(VARCHAR(255), nullable=False)
    nome = Column(VARCHAR(255), nullable=False)
    sobrenome = Column(VARCHAR(255), nullable=False)
    email = Column(VARCHAR(255), nullable=False)
    hashed_password = Column(VARCHAR(255), nullable=False)
    is_active = Column(BIT, nullable=True)
    is_validated = Column(BIT, nullable=True)
    created_at = Column(DATETIME2, server_default=func.now())
    updated_at = Column(DATETIME2, server_default=func.now(), onupdate=func.now())
    email_verified = Column(BIT, nullable=True)
    verification_token = Column(VARCHAR(255), nullable=True)
    reset_password_token = Column(VARCHAR(255), nullable=True)
    reset_password_token_expires = Column(DATETIMEOFFSET, nullable=True)

    roles = relationship("Role", secondary="user_role", back_populates="users")
"""

class User(SQLAlchemyBaseUserTable[uuid.UUID], Base):
    """
    Core user model with fastapi-users integration
    Security: No sensitive OAuth tokens stored here
    """
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)  # Null for OAuth-only users

    # Profile fields from Google
    full_name: Mapped[Optional[str]] = mapped_column(String(255))
    picture_url: Mapped[Optional[str]] = mapped_column(String(512))

    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # Email verified

    # Audit fields
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.now(timezone.utc))
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    oauth_accounts: Mapped[list["OAuthAccount"]] = relationship("OAuthAccount", back_populates="user",
                                                                cascade="all, delete-orphan")
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship("RefreshToken", back_populates="user",
                                                                cascade="all, delete-orphan")


class OAuthAccount(Base):
    """
    Links user to OAuth provider accounts (Google, GitHub, etc.)
    Security: Stores only provider ID, not access tokens
    """
    __tablename__ = "oauth_accounts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # OAuth provider info
    oauth_name: Mapped[str] = mapped_column(String(50), nullable=False)  # "google", "github"
    account_id: Mapped[str] = mapped_column(String(320), nullable=False)  # Provider's user ID (Google sub claim)
    account_email: Mapped[str] = mapped_column(String(320), nullable=False)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="oauth_accounts")

    __table_args__ = (
        # Unique constraint: one provider account per user
        # Security: Prevents account hijacking via multiple links
        {"schema": None},
    )


class RefreshToken(Base):
    """
    Stores refresh token metadata for token rotation and revocation
    Security: Only stores hash, not the actual token
    """
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Token security
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)  # SHA-256 hash

    # Token lifecycle
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)  # Typically 7-30 days
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)  # Set on logout/revocation

    # Security fingerprinting (helps detect token theft)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv4 or IPv6

    # Token rotation tracking
    replaced_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("refresh_tokens.id"), nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")


class AuditLog(Base):
    """
    Security audit trail for authentication events
    Compliance: GDPR/SOC2 audit requirements
    """
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
                                                         index=True)

    # Event details
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)  # "login", "logout", "refresh", "failed_login"
    event_status: Mapped[str] = mapped_column(String(20), nullable=False)  # "success", "failure"

    # Context
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(512))
    metadata1: Mapped[Optional[str]] = mapped_column(Text)  # JSON string for additional context

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc), nullable=False, index=True)