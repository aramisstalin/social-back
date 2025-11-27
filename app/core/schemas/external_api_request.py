from http import HTTPMethod
from typing import Optional

from app.core.schemas import BaseSchema


class ExternalApiRequest(BaseSchema):
    """
    Represents a request to an external API.
    """
    endpoint: Optional[str] = None
    method: Optional[HTTPMethod] = None
    headers: Optional[str] = None
    query_params: Optional[str] = None
    body: Optional[str] = None
