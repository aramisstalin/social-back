import uuid
from sqlalchemy import Column, UniqueConstraint
from sqlalchemy.dialects.mssql import VARCHAR
from sqlalchemy.orm import relationship

from app.core.models import Base

class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("name"),)

    id = Column(primary_key=True, default=uuid.uuid4)
    name = Column(VARCHAR(255), nullable=False)
    description = Column(VARCHAR(255), nullable=True)

    roles = relationship("Role", secondary="role_permission", back_populates="permissions")
