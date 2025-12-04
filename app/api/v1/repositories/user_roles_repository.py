from functools import lru_cache

from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import ApiResponse
from app.api.v1.schemas import UserRead as User
from app.api.v1.repositories import RoleRepository, UserRepository, get_role_repository, get_user_repository


class   UserRolesRepository:

    def __init__(self, user_repository: UserRepository, role_repository: RoleRepository):
        self.user_repository = user_repository
        self.role_repository = role_repository

    async def revoke_roles(self, db: AsyncSession, user_id, role_ids):
        try:
            user = await self.user_repository.get_by_id(db, user_id)

            for rid in role_ids:
                role = await self.role_repository.get_by_id(db, rid)
                if role in user.roles:
                    user.roles.remove(role)
            await db.commit()

            return ApiResponse(
                status_code=status.HTTP_200_OK,
                detail="Funções revogadas com sucesso",
                data=user
            )
        except ValueError as e:
            return ApiResponse(
                detail="Ocorreu um erro",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error=str(e)
            )

    async def assign_roles(self, db: AsyncSession, user_id, role_ids):
        try:
            user = await self.user_repository.get_by_id(db, user_id)

            for rid in role_ids:
                role = await self.role_repository.get_by_id(db, rid)
                if role not in user.roles:
                    user.roles.append(role)
            await db.commit()

            return ApiResponse(
                status_code=status.HTTP_200_OK,
                detail="Funções atribuídas com sucesso",
                data=user
            )
        except ValueError as e:
            return ApiResponse(
                detail="Ocorreu um erro",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error=str(e)
            )


@lru_cache()
def get_user_roles_repository() -> UserRolesRepository:
    return UserRolesRepository(
        user_repository=get_user_repository(),
        role_repository=get_role_repository()
    )