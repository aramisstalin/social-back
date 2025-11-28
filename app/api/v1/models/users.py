from app.core.models import Base
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String
from typing import List


class User(Base):
    """Core application user model."""
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255))

    # Relationship to scoped role assignments
    user_roles: Mapped[List["UserRole"]] = relationship(back_populates="user")

    def __repr__(self):
        return f"<User(id='{self.id}', email='{self.email}')>"