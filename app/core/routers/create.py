from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import ApiResponse
from app.core.repositories import BaseRepository
from app.core.models import Base


async def create_item(db: AsyncSession, item: Base, item_repository: BaseRepository, schema):
    try:
        item = await item_repository.create(db, item, schema)

        return ApiResponse(
            status_code=status.HTTP_201_CREATED,
            detail="Cadastrando item: item criado com sucesso",
            data=item
        )
    except ValueError as e:
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=str(e)
        )