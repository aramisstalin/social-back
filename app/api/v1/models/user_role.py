from app.core.models import Base
from sqlalchemy.orm import relationship, mapped_column, Mapped
from sqlalchemy import ForeignKey, UniqueConstraint
from uuid import UUID

class UserRole(Base):
    """
    Association table linking a User to a Role scoped within a specific Tenant.
    This is the core of the hybrid model.
    """
    __tablename__ = "user_roles"

    # --- Composite Primary Keys ---
    # We use a composite primary key to ensure uniqueness for a given user/tenant/role combination
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True
    )

    # Constraints
    __table_args__ = (
        # Ensure a User can only have a specific Role once within a Tenant
        UniqueConstraint('user_id', 'role_id', 'tenant_id', name='_user_tenant_role_uc'),
    )

    user: Mapped["User"] = relationship(back_populates="user_roles")
    role: Mapped["Role"] = relationship(back_populates="user_roles")
    tenant: Mapped["Tenant"] = relationship(back_populates="user_roles")

    def __repr__(self):
        return f"<UserRole(User ID='{self.user_id}', Role ID='{self.role_id}', Tenant ID='{self.tenant_id}')>"