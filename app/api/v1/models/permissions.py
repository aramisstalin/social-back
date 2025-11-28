from app.core.models import Base
from sqlalchemy.orm import relationship, mapped_column, Mapped
from typing import List, Optional
from sqlalchemy import String


class Permission(Base):
    """Defines an atomic action, typically in RESOURCE:ACTION format."""
    __tablename__ = "permissions"

    # The permission string (e.g., 'invoice:read', 'user:delete', 'project:billing')
    code: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String)

    # Relationship to role linkages
    roles: Mapped[List["RolePermission"]] = relationship(back_populates="permission")

    def __repr__(self):
        return f"<Permission(code='{self.code}')>"