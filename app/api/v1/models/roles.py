import uuid
from sqlalchemy import Column, UniqueConstraint
from sqlalchemy.dialects.mssql import VARCHAR
from sqlalchemy.orm import relationship

from app.core.models import Base

class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("name"),)

    id = Column(primary_key=True, default=uuid.uuid4)
    name = Column(VARCHAR(255), nullable=False)
    description = Column(VARCHAR(255), nullable=True)

    users = relationship("User", secondary="user_role", back_populates="roles")
    permissions = relationship("Permission", secondary="role_permission", back_populates="roles")
