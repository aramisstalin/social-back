from functools import lru_cache

from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.repositories import RoleRepository, PermissionRepository, get_permission_repository, get_role_repository
from app.core.schemas import ApiResponse
from app.api.v1.schemas import RoleWithPermissions


class RolePermissionsRepository:

    def __init__(self, role_service: RoleRepository, permission_service: PermissionRepository):
        self.role_service = role_service
        self.permission_service = permission_service

    async def revoke_permissions(self, db: AsyncSession, role_id, permission_ids):
        try:
            role = await self.role_service.get_by_id(db, role_id)

            for pid in permission_ids:
                permission = await self.permission_service.get_by_id(db, pid)
                if permission in role.permissions:
                    role.permissions.remove(permission)
            await db.commit()

            return ApiResponse(
                status_code=status.HTTP_200_OK,
                detail="Permissões revogadas com sucesso",
                data=role
            )
        except ValueError as e:
            return ApiResponse(
                detail="Ocorreu um erro",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error=str(e)
            )

    async def assign_permissions(self, db: AsyncSession, role_id, permission_ids):
        try:
            role = await self.role_service.get_by_id(db, role_id)

            for pid in permission_ids:
                permission = await self.permission_service.get_by_id(db, pid)
                if permission not in role.permissions:
                    role.permissions.append(permission)
            await db.commit()

            return ApiResponse(
                status_code=status.HTTP_200_OK,
                detail="Permissões atribuídas com sucesso",
                data = role
            )
        except ValueError as e:
            return ApiResponse(
                detail="Ocorreu um erro",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error=str(e)
            )


@lru_cache()
def get_role_permissions_repository() -> RolePermissionsRepository:
    return RolePermissionsRepository(
        role_service=get_role_repository(),
        permission_service=get_permission_repository()
    )