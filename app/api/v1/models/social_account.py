from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    String,
    func,
    text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

# Keep your existing BaseModel (Declarative Base) import
from app.core.models import Base as BaseModel

if TYPE_CHECKING:
    # avoid circular import at runtime; used only for typing
    from app.api.v1.models import User  # adjust import path to your project


class ProviderName(str, enum.Enum):
    google = "google"
    microsoft = "microsoft"
    apple = "apple"
    github = "gitHub"
    facebook = "facebook"


class SocialAccount(BaseModel):
    __tablename__ = "social_accounts"
    __table_args__ = (
        UniqueConstraint("provider_name", "provider_user_id", name="uq_social_provider_user"),
        Index("ix_social_user_id", "user_id"),
    )

    # Primary key: UUID, Python default + DB server default for Postgres
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        nullable=False,
        default=uuid.uuid4,  # python-side default (callable)
        server_default=text("gen_random_uuid()"),  # Postgres extension (pgcrypto) or uuid-ossp; optional
    )

    # Use a native enum type in Postgres (SQLAlchemy will create native enum when available)
    provider_name: Mapped[ProviderName] = mapped_column(
        SAEnum(ProviderName, name="providername_enum", native_enum=True),
        nullable=False,
        index=True,
    )

    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)  # external 'sub' id

    # FK to users.id (assumes users table PK is uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Relationship back to user (adjust back_populates to the attribute name on your user model)
    user: Mapped["User"] = relationship(
        "User",
        back_populates="social_accounts",
        lazy="selectin",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<SocialAccount(id={self.id!s} provider={self.provider_name.value!s} "
            f"provider_user_id={self.provider_user_id!s} user_id={self.user_id!s})>"
        )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "provider_name": self.provider_name.value,
            "provider_user_id": self.provider_user_id,
            "user_id": str(self.user_id),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

"""
Standard Example User Data from Each Major Provider

These examples show exactly what you receive from each provider’s userinfo endpoint or OAuth profile API.
These are normalized, realistic, and based on official documentation.

🔵 Google (OpenID Connect userinfo)
{
  "sub": "109876543212345678901",
  "email": "john.doe@gmail.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "picture": "https://lh3.googleusercontent.com/a-/AOh14Gg123.jpg",
  "locale": "en"
}

🔵 Facebook / Meta (/me?fields=id,name,email,picture)
{
  "id": "10234567891234567",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "picture": {
    "data": {
      "height": 200,
      "is_silhouette": false,
      "url": "https://platform-lookaside.fbsbx.com/platform/profilepic/?asid=1023456789",
      "width": 200
    }
  }
}

🔵 Apple (OpenID Connect)

⚠️ Apple does NOT return email on subsequent logins — only on the first login.

First login:
{
  "sub": "000123.a123b456c789d012e345f6789a0bcde.1234",
  "email": "john.doe@private.appleid.com",
  "email_verified": "true",
  "is_private_email": "true"
}

Later logins:
{
  "sub": "000123.a123b456c789d012e345f6789a0bcde.1234"
}

🔵 Microsoft / Azure AD v2 (/v1.0/me or UserInfo OIDC)
{
  "sub": "d9012345-6789-4abc-def0-1234567890ab",
  "email": "john.doe@outlook.com",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe"
}

🔵 GitHub (/user)
{
  "id": 1234567,
  "login": "johndoe",
  "email": "john.doe@example.com",
  "avatar_url": "https://avatars.githubusercontent.com/u/1234567?v=4",
  "name": "John Doe"
}

"""