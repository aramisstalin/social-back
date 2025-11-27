from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import ApiResponse, BaseFilter
from app.core.repositories import BaseRepository


async def filter_items(filters: BaseFilter, db: AsyncSession, item_repository: BaseRepository, schema) -> ApiResponse:
    try:
        response = await item_repository.get_filtered_items(db, filters)
        total, items = response.values()

        items = [schema.model_validate(item) for item in items]  # quick serialization

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Filtrar itens: itens filtrados com sucesso",
            data={
                "total": total,
                "page": filters.page,
                "page_size": filters.page_size,
                "results": items
            })
    except ValueError as e:
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=str(e)
        )