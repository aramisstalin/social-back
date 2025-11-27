from typing import Optional, List
from pydantic import BaseModel, Field
from fastapi import Query


class BaseFilter(BaseModel):
    page: int = Field(default=1, ge=1, description="Page number (starts from 1)")
    page_size: Optional[int] =  Field(default=20, ge=1, le=1000, description="Items per page")
    logic_operator: Optional[str] = Field(default="or", description="Operator to be applied on the query") #"or"
    sort: Optional[List[str]] = None


def get_base_filter(page: Optional[int] = Query(1, ge=1), page_size: Optional[int] = Query(20, ge=1, le=1000), logic_operator: Optional[str] = Query("or"), sort: Optional[List[str]] = Query(None, description="Sort fields like column+ or column-")) -> BaseFilter:
    return BaseFilter(
        page=page,
        page_size=page_size,
        logic_operator=logic_operator,
        sort=sort,
    )
