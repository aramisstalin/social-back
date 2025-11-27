from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db

from app.core.schemas import ApiResponse
from app.core.routers import read_item, filter, update, create, delete
from app.core.security import verify_api_key, get_current_admin_user

from app.api.v1.schemas import Permission, PermissionUpdate, PermissionCreate, PermissionFilter
from app.api.v1.repositories import PermissionRepository, get_permission_repository


prefix = "/permissoes"
router = APIRouter(prefix=prefix)


@router.get("/{permission_id}", response_model=ApiResponse)
async def read_permission(
        permission_id: UUID,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        permissions_repository: Annotated[PermissionRepository, Depends(get_permission_repository)]
):
    return await read_item(permission_id, db, permissions_repository, Permission.model_validate)


@router.put("/{permission_id}", response_model=ApiResponse)
async def update_permission(
        permission_id: UUID,
        permission: PermissionUpdate,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        permissions_repository: Annotated[PermissionRepository, Depends(get_permission_repository)]
):
    return await update(permission_id, permission, db, permissions_repository, Permission.model_validate)


@router.delete("/{permission_id}", response_model=ApiResponse)
async def delete_permission(
        permission_id: UUID,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        permissions_repository: Annotated[PermissionRepository, Depends(get_permission_repository)]
):
    return await delete(permission_id, db, permissions_repository)


@router.post("", response_model=ApiResponse)
async def create_permission(
        permission: PermissionCreate,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        permissions_repository: Annotated[PermissionRepository, Depends(get_permission_repository)]
):
    return await create(db, permission, permissions_repository, Permission.model_validate)


@router.get("", response_model=ApiResponse)
async def filter_permissions(
        filters: Annotated[PermissionFilter, Depends()],
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        permissions_repository: Annotated[PermissionRepository, Depends(get_permission_repository)]
):
    return await filter(filters, db, permissions_repository, Permission.model_validate)
