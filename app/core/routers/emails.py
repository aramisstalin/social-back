from typing import Annotated
from fastapi import APIRouter, status, Depends

from app.core.schemas import ApiResponse, EmailRequest
from app.core.services import send_email
from app.core.security import verify_api_key


prefix="/email"
router = APIRouter(prefix=prefix)

@router.post("")
async def send_emails(
        email: EmailRequest,
        api_key: Annotated[str, Depends(verify_api_key)]
):
    try:
        await send_email(email.to, email.subject, email.body)

        return ApiResponse(
            status_code=status.HTTP_200_OK,
            detail="Email enviado com sucesso",
            data=""
        )
    except ValueError as e:
        return ApiResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=str(e)
        )
