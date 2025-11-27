from fastapi import APIRouter, File, UploadFile, status
from fastapi.params import Depends
from typing import List, Annotated
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.models import User as UserModel
from app.core.security import verify_api_key, get_current_active_validated_user

from app.core.schemas.api_response import ApiResponse
from app.core.schemas.files import FileResponse
from app.core.repositories import FileRepository, get_file_repository
from app.db.session import get_db

prefix = "/file"
router = APIRouter(prefix=prefix)

@router.post("/upload/", response_model=ApiResponse)
async def upload_file(
        file: UploadFile,
        current_user: Annotated[UserModel, Depends(get_current_active_validated_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        file_service: Annotated[FileRepository, Depends(get_file_repository)]
):
    """
    Upload a file to the server.
    Returns a file ID and URL that can be used to access the file.
    """
    try:
        file = await file_service.upload(db, file)

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Arquivo carregado com sucesso",
            data=file
        )

    except Exception as e:
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=f"Erro ao carregar arquivo: {str(e)}"
        )


@router.post("/upload-multiple/", response_model=ApiResponse)
async def upload_multiple_files(
        files: List[UploadFile],
        current_user: Annotated[UserModel, Depends(get_current_active_validated_user)],
        api_key: Annotated[str, Depends(verify_api_key)]
):
    """
    Upload multiple files to the server.
    Returns a list of file IDs and URLs that can be used to access the files.
    """
    try:
        responses = []
        for file in files:
            response = await upload_file(file)
            if response.status_code == status.HTTP_200_OK:
                responses.append(response.data)
            else:
                for file_info in responses:
                    await delete_file(file_info)
                raise Exception(response.detail)
        return ApiResponse(
            status_code=status.HTTP_200_OK,
            data=responses,
            detail="Arquivos carregados com sucesso"
        )

    except Exception as e:
        return ApiResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        error=f"Erro ao carregar arquivos: {str(e)}"
    )


@router.get("/{file_id}", response_model=ApiResponse)
async def get_file_info(
        file_id: str,
        current_user: Annotated[UserModel, Depends(get_current_active_validated_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        file_service: Annotated[FileRepository, Depends(get_file_repository)]
):
    """
    Get file information by ID.
    """
    file = await file_service.get_by_id(db, item_id=file_id)
    if not file or file is None:
        return ApiResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Arquivo não encontrado"
        )

    return ApiResponse(
        status_code=status.HTTP_200_OK,
        detail="Dados de arquivo",
        data=file
    )


@router.delete("/{file_id}")
async def delete_file(
        file_id: str,
        current_user: Annotated[UserModel, Depends(get_current_active_validated_user)],
        api_key: Annotated[str, Depends(verify_api_key)],
        db: Annotated[AsyncSession, Depends(get_db)],
        file_service: Annotated[FileRepository, Depends(get_file_repository)]
):
    """
    Delete a file by ID.
    """
    try:
        file = await file_service.get_by_id(db, item_id=file_id)
        if not file or file is None:
            return ApiResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                error="Arquivo não encontrado"
            )

        await file_service.exclude_file(db, file)

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Arquivo excluído com sucesso!"
        )
    except Exception as e:
        return  ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=f"Erro ao excluir arquivo: {str(e)}"
        )
