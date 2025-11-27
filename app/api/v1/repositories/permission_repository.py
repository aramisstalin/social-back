from functools import lru_cache
from app.api.v1.models import Permission
from app.core.repositories import BaseRepository


class PermissionRepository(BaseRepository):
    def __init__(self):
        super().__init__(Permission)


@lru_cache()
def get_permission_repository() -> PermissionRepository:
    return PermissionRepository()