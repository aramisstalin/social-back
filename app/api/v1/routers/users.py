from typing import List, Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_session

from app.api.v1.models import User as UserModel
from app.api.v1.repositories import UserRolesRepository, get_user_roles_repository, UserRepository, get_user_repository
from app.api.v1.schemas import UserUpdate, UserRead as User, UserFilter, UserId
#, UserId, UserUpdateStatus, UserUpdateValidity)

from app.core.schemas import ApiResponse
from app.core.security import verify_api_key, get_current_admin_user, get_current_active_validated_user
from app.core.routers import filter

prefix = "/usuarios"
router = APIRouter(prefix=prefix)


@router.post("/{user_id}/revogar-perfis", response_model=ApiResponse)
async def revoke_roles(
        user_id: str,
        role_ids: List[str],
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_session)],
        user_role_service: Annotated[UserRolesRepository, Depends(get_user_roles_repository)]
):
    """Revogar perfis de um usuário."""
    result = await user_role_service.revoke_roles(db, user_id, role_ids)
    return ApiResponse(status_code=status.HTTP_200_OK, data=result)


@router.post("/{user_id}/atribuir-perfis", response_model=ApiResponse)
async def assign_roles(
        user_id: UUID,
        role_ids: List[str],
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_session)],
        user_role_service: Annotated[UserRolesRepository, Depends(get_user_roles_repository)]
):
    """Atribuir perfis a um usuário."""
    result = await user_role_service.assign_roles(db, user_id, role_ids)
    return ApiResponse(status_code=status.HTTP_200_OK, data=result)


@router.get("/{user_id}", response_model=ApiResponse)
async def read_user(
        user_id: UUID,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_session)],
        user_repository: Annotated[UserRepository, Depends(get_user_repository)]
):
    """Obter um usuário por ID, incluindo perfis."""
    user = await user_repository.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    return ApiResponse(status_code=status.HTTP_200_OK, data=user)


@router.put("/{user_id}", response_model=ApiResponse)
async def update_user(
        user_id: UUID,
        user: UserUpdate,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_session)],
        user_service: Annotated[UserRepository, Depends(get_user_repository)]
):
    """Atualizar um usuário e retornar o usuário atualizado."""
    updated = await user_service.update(db, user, user_id, User)
    if not updated:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    return ApiResponse(status_code=status.HTTP_200_OK, data=updated)


@router.post("/toggle-active-status", response_model=ApiResponse)
async def toggle_user_status(
        request: UserId,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_session)],
        user_service: Annotated[UserRepository, Depends(get_user_repository)]
):
    """Alternar o status ativo de um usuário."""
    db_item: User = await user_service.get_by_id(db, request.user_id)
    if db_item is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    update_item = UserUpdate(is_active=(not db_item.is_active))
    updated = await user_service.update(db, update_item, request.user_id, User)

    return ApiResponse(status_code=status.HTTP_200_OK, detail="Status atualizado com sucesso", data=updated)


@router.post("/toggle-validity-status", response_model=ApiResponse)
async def toggle_user_validity(
        request: UserId,
        current_user: Annotated[UserModel, Depends(get_current_active_validated_user)],
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_session)],
        user_service: Annotated[UserRepository, Depends(get_user_repository)]
):
    """Alternar o status de validade de um usuário."""
    user: User = await user_service.get_by_id(db, request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    update_item = UserUpdate(is_validated=(not user.is_validated))
    updated = await user_service.update(db, update_item, request.user_id, User)

    return ApiResponse(status_code=status.HTTP_200_OK, detail="Validação atualizada com sucesso", data=updated)


@router.delete("/{user_id}", response_model=ApiResponse)
async def delete_user(
        user_id: UUID,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_session)],
        user_service: Annotated[UserRepository, Depends(get_user_repository)]
):
    """Excluir um usuário pelo ID."""
    deleted = await user_service.delete(db, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return ApiResponse(status_code=status.HTTP_200_OK, detail="Usuário excluído com sucesso.")


@router.get("", response_model=ApiResponse)
async def filter_users(
        filters: Annotated[UserFilter, Depends()],
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_session)],
        user_repository: Annotated[UserRepository, Depends(get_user_repository)]
):
    """Obter uma lista paginada de usuários, incluindo perfis."""
    return await filter(filters, db, user_repository, User)
