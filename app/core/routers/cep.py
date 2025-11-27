from typing import Annotated
from fastapi import Depends, status, APIRouter

from app.core.schemas import CEPQuery, ApiResponse
from app.core.security import verify_api_key
from app.core.services import fetch_address_by_cep

prefix = "/cep"
router = APIRouter(prefix=prefix)


@router.get("", response_model=ApiResponse)
async def get_cep_address(
        query: CEPQuery,
        api_key: Annotated[str, Depends(verify_api_key)]
):
    try:
        cep = await fetch_address_by_cep(query.cep)
        return ApiResponse(
            status_code=status.HTTP_200_OK,
            data=cep
        )
    except ValueError as e:
        return ApiResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            error=str(e)
        )
