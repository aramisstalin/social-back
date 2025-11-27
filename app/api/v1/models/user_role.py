import uuid
from sqlalchemy import Column, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.mssql import UNIQUEIDENTIFIER
from app.core.models import Base

class UserRole(Base):
    __tablename__ = "user_role"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id"),
    )

    user_id = Column(UNIQUEIDENTIFIER, ForeignKey("users.id"), primary_key=True)
    role_id = Column(UNIQUEIDENTIFIER, ForeignKey("roles.id"), primary_key=True)
