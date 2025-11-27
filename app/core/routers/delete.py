from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import ApiResponse
from app.core.repositories import BaseRepository


async def delete_item(item_id, db: AsyncSession, item_repository: BaseRepository) -> ApiResponse:
    try:
        result = await item_repository.delete(db, item_id)

        return ApiResponse(
                status_code=status.HTTP_200_OK,
                detail="Excluir item: item exluído com sucesso"
            ) if result else ApiResponse(
                status_code=status.HTTP_417_EXPECTATION_FAILED,
                detail="Excluir item: o item não pôde ser excluído "
            )
    except ValueError as e:
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=str(e)
        )