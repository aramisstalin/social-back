from app.core.models import Base
from sqlalchemy.orm import relationship, mapped_column, Mapped
from sqlalchemy import ForeignKey, UniqueConstraint
from uuid import UUID


class RolePermission(Base):
    """Association table linking Roles to Permissions."""
    __tablename__ = "role_permissions"

    # Foreign Key to Role
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    # Foreign Key to Permission
    permission_id: Mapped[UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )

    # Constraints for data integrity
    __table_args__ = (
        UniqueConstraint('role_id', 'permission_id', name='_role_permission_uc'),
    )

    role: Mapped["Role"] = relationship(back_populates="permissions")
    permission: Mapped["Permission"] = relationship(back_populates="roles")

    def __repr__(self):
        return f"<RolePermission(Role ID='{self.role_id}', Permission ID='{self.permission_id}')>"