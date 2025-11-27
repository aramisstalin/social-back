from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import ApiResponse
from app.core.repositories import BaseRepository


async def read_items(skip: int, limit: int, db: AsyncSession, item_repository: BaseRepository, schema) -> ApiResponse:
    try:
        items = await item_repository.get_all(db, skip, limit)

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Recuperando itens: itens recuperados com sucesso",
            data=items
        )
    except ValueError as e:
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=str(e)
        )


async def read_item(item_id, db: AsyncSession, item_service: BaseRepository, schema) -> ApiResponse:
    try:
        db_item = await item_service.get_by_id(db, item_id, schema)
        if db_item is None:
            return ApiResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                error="Recuperando item: esse item não existe."
            )

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Recuperando item: item recuperado com sucesso",
            data=db_item
        )
    except ValueError as e:
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=str(e)
        )