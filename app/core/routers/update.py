from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import ApiResponse
from app.core.repositories import BaseRepository


async def update_item(id, item, db: AsyncSession, item_repository: BaseRepository, schema) -> ApiResponse:
    try:
        db_item = await item_repository.get_by_id(db, id, schema)
        if db_item is None:
            return ApiResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                error="Atualizando item: esse item não existe."
            )

        result = await item_repository.update(db, item, id, schema)

        return ApiResponse(
                status_code=status.HTTP_200_OK,
                detail="Atualizando item: item atualizado com sucesso",
                data=result
            )
    except ValueError as e:
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=str(e)
        )