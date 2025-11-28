from app.core.models import Base
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import List


class Tenant(Base):
    """Represents a separate scope, organization, or project boundary."""
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), index=True)

    # Relationship to scoped role assignments
    user_roles: Mapped[List["UserRole"]] = relationship(back_populates="tenant")

    def __repr__(self):
        return f"<Tenant(id='{self.id}', name='{self.name}')>"