from typing import List, Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from app.db.session import get_db

from app.core.schemas import ApiResponse
from app.core.security import verify_api_key, get_current_admin_user
from app.api.v1.schemas import RoleCreate, Role, RoleUpdate, RoleFilter, RoleWithPermissions
from app.api.v1.repositories import RoleRepository, get_role_repository, RolePermissionsRepository, get_role_permissions_repository
from app.core.routers import filter

prefix = "/perfis"
router = APIRouter(prefix=prefix)


@router.post("/{role_id}/revogar-permissoes", response_model=ApiResponse)
async def revoke_permissions(
        role_id: str,
        permissions_ids: List[str],
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        role_permissions_repository: Annotated[RolePermissionsRepository, Depends(get_role_permissions_repository)]
):
    """Revoke permissions from a role."""
    result = await role_permissions_repository.revoke_permissions(db, role_id, permissions_ids)
    return ApiResponse(status_code=status.HTTP_200_OK, data=result)


@router.post("/{role_id}/atribuir-permissoes", response_model=ApiResponse)
async def assign_permissions(
        role_id: UUID,
        permissions_ids: List[str],
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        role_permissions_repository: Annotated[RolePermissionsRepository, Depends(get_role_permissions_repository)]
):
    """Assign permissions to a role."""
    result = await role_permissions_repository.assign_permissions(db, role_id, permissions_ids)
    return ApiResponse(status_code=status.HTTP_200_OK, data=result)


@router.get("/{role_id}", response_model=ApiResponse)
async def read_role(
        role_id: UUID,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        role_repository: Annotated[RoleRepository, Depends(get_role_repository)]
):
    """Get a role by ID, including permissions."""
    role = await role_repository.get_by_id(db, role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    # role_with_permissions = RoleWithPermissions.model_validate(role)
    return ApiResponse(status_code=status.HTTP_200_OK, data=role)


@router.put("/{role_id}", response_model=ApiResponse)
async def update_role(
        role_id: UUID,
        role: RoleUpdate,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        role_repository: Annotated[RoleRepository, Depends(get_role_repository)]
):
    """Update a role and return the updated role."""
    updated = await role_repository.update(db, role, role_id, Role)
    if not updated:
        raise HTTPException(status_code=404, detail="Role not found")
    # role_with_permissions = RoleWithPermissions.model_validate(updated)
    return ApiResponse(status_code=status.HTTP_200_OK, data=updated)


@router.delete("/{role_id}", response_model=ApiResponse)
async def delete_role(
        role_id: UUID,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        role_repository: Annotated[RoleRepository, Depends(get_role_repository)]
):
    """Delete a role by ID."""
    deleted = await role_repository.delete(db, role_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Role not found")
    return ApiResponse(status_code=status.HTTP_200_OK, detail="Role deleted successfully.")


@router.post("", response_model=ApiResponse)
async def create_role(
        role: RoleCreate,
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        role_repository: Annotated[RoleRepository, Depends(get_role_repository)]
):
    """Create a new role and return it."""
    created = await role_repository.create(db, role, Role)
    # role_with_permissions = RoleWithPermissions.model_validate(created)
    return ApiResponse(status_code=status.HTTP_201_CREATED, data=created)


@router.get("", response_model=ApiResponse)
async def filter_roles(
        filters: Annotated[RoleFilter, Depends()],
        admin: Annotated[bool, Depends(get_current_admin_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        role_repository: Annotated[RoleRepository, Depends(get_role_repository)]
):
    """Get a paginated list of roles, including permissions."""
    # paginated = await role_repository.get_filtered_items(db, filters)
    # paginated['items'] = [RoleWithPermissions.model_validate(r) for r in paginated['items']]
    # return ApiResponse(status_code=status.HTTP_200_OK, data=paginated)
    return await filter(filters, db, role_repository, Role)