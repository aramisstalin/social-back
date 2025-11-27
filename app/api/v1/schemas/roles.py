from typing import List, Optional
from uuid import UUID
from app.api.v1.schemas import Permission
from app.core.schemas import BaseSchema, BaseFilter


class RoleBase(BaseSchema):
    name: str
    description: Optional[str] = None


class RoleCreate(RoleBase):
    pass


class RoleUpdate(RoleBase):
    name: Optional[str] = None


class Role(RoleBase):
    id: UUID


class RoleWithPermissions(Role):
    permissions: List[Permission]


class RoleFilter(BaseFilter):
    name__icontains: Optional[str] = None
    description__icontains: Optional[str] = None

    """    
        def __init__(
                self,
                name_contains: str = Query(None),
                description_contains: str = Query(None),
                page: int = Query(1, ge=1),
                page_size: int = Query(20, ge=1, le=100),
                logic_operator: str = Query("or"),
                sort_by: str = Query("id"),
                sort_order: str = Query("asc")
        ):
            super().__init__(page, page_size, logic_operator, sort_by, sort_order)
            self.name_contains = name_contains
            self.description_contains = description_contains        
    """