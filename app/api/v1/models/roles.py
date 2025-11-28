from app.core.models import Base
from sqlalchemy.orm import relationship, mapped_column, Mapped
from typing import List, Optional
from sqlalchemy import String, ForeignKey
from uuid import UUID

class Role(Base):
    """Defines a collection of Permissions with optional hierarchy."""
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String)

    # --- Hierarchy Implementation ---
    # parent_role_id points to another Role. A child role inherits all permissions of its parent.
    parent_role_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("roles.id", ondelete="SET NULL")
    )

    # Relationship to Parent (the role this role inherits from)
    parent: Mapped[Optional["Role"]] = relationship(
        "Role",
        remote_side=[id],  # Use the primary key of the same class for remote side
        back_populates="children"
    )

    # Relationship to Children (roles that inherit from this role)
    children: Mapped[List["Role"]] = relationship(
        "Role",
        remote_side=[parent_role_id],  # Use the parent FK for remote side
        back_populates="parent"
    )

    # Relationship to permission linkages
    permissions: Mapped[List["RolePermission"]] = relationship(back_populates="role")

    # Relationship to user/tenant assignments
    user_roles: Mapped[List["UserRole"]] = relationship(back_populates="role")

    def __repr__(self):
        return f"<Role(name='{self.name}', parent_id='{self.parent_role_id}')>"