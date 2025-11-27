from datetime import datetime
from typing import Any, Optional
from app.core.schemas import BaseSchema
from typing import List, Generic, TypeVar

T = TypeVar("T")

class ApiResponse(BaseSchema):
    status_code: int
    error: Optional[str] = None
    detail: Optional[str] = None
    data: Optional[Any] = None
    timestamp: str = datetime.utcnow().isoformat()


class PaginatedResponse(BaseSchema, Generic[T]):
    page: int
    page_size: int
    total: int
    items: List[T]