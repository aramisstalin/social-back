from sqlalchemy import Column, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from app.core.models import Base

class RolePermission(Base):
    __tablename__ = "role_permission"
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id"),
    )

    role_id = Column(UNIQUEIDENTIFIER, ForeignKey("roles.id"), primary_key=True)
    permission_id = Column(UNIQUEIDENTIFIER, ForeignKey("permissions.id"), primary_key=True)
