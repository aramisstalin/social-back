from app.core.schemas import BaseSchema
from uuid import UUID


class FileCreate(BaseSchema):
    id: UUID
    filename: str
    url: str
    content_type: str
    size: int
    path: str


class FileResponse(BaseSchema):
    id: UUID
    filename: str
    url: str
    content_type: str
    size: int
    # path: str