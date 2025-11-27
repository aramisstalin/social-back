from typing import Optional

from pydantic import (constr)
from uuid import UUID

from app.core.schemas import BaseSchema, BaseFilter

class PermissionBase(BaseSchema):
    name: constr(min_length=3, max_length=50)
    description: str | None = None


class PermissionCreate(PermissionBase):
    pass


class PermissionUpdate(PermissionBase):
    name: Optional[str]
    description: Optional[str]


class Permission(PermissionBase):
    id: UUID


class PermissionFilter(BaseFilter):
    name__icontains: Optional[str] = None
    description__icontains: Optional[str] = None
