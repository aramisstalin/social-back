from functools import lru_cache
from typing import Optional, Any, Dict
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from fastapi import HTTPException, status

from app.api.v1.models import Role as RoleModel
from app.api.v1.schemas import Role, RoleFilter
from app.core.helpers import apply_filters_and_sorting, paginate
from app.core.repositories import BaseRepository


class RoleRepository(BaseRepository):
    """
    Repository for Role entity, handling all database operations and returning validated Pydantic models.
    """
    def __init__(self):
        super().__init__(RoleModel)

    async def get_filtered_items(self, db: AsyncSession, filters: RoleFilter) -> Dict[str, Any]:
        """
        Retrieve paginated and filtered roles as validated Pydantic models.
        """
        try:
            base_query = select(self.model).options(
                selectinload(self.model.permissions)
            )
            filter_dict, sort_fields, logic_operator = self.build_filters_from_params(filters).values()
            query, _ = apply_filters_and_sorting(base_query, self.model, filters=filter_dict, sort=sort_fields, logic_operator=logic_operator)

            return await paginate(db, query, page=filters.page, page_size=filters.page_size)

        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Error filtering roles: {e}")

    async def get_by_id(self, db: AsyncSession, item_id: Any) -> Optional[Role]:
        """
        Retrieve a single role by ID as a validated Pydantic model.
        """
        result = await db.execute(select(self.model).options(
                selectinload(self.model.permissions)
        ).filter(self.model.id == item_id))
        orm_role = result.scalars().first()
        if not orm_role:
            return None
        return Role.model_validate(orm_role)

    def build_filters_from_params(self, filters: RoleFilter):
        filter_dict = filters.model_dump(exclude={"sort", "page", "page_size", "logic_operator"}, exclude_none=True)

        if filters.name__icontains is not None:
            filter_dict["name__icontains"] = filters.name__icontains

        if filters.description__icontains is not None:
            filter_dict["description__icontains"] = filters.description__icontains

        sort_fields = filters.sort or []
        logic_operator = filters.logic_operator or "and"

        return {"filter_dict": filter_dict, "sort_fields": sort_fields, "logic_operator": logic_operator}

@lru_cache()
def get_role_repository() -> RoleRepository:
    """Dependency injector for RoleRepository."""
    return RoleRepository()
