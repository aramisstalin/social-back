from typing import Optional
from datetime import date
from fastapi import Query


class ItemFilter:
    def __init__(
        self,
        name: Optional[str] = None,
        name_exact: Optional[str] = None,
        name_startswith: Optional[str] = None,
        name_endswith: Optional[str] = None,
        name_icontains: Optional[str] = None,

        created_at: Optional[date] = None,
        created_before: Optional[date] = None,
        created_after: Optional[date] = None,

        price: Optional[int] = None,
        price_min: Optional[int] = None,
        price_max: Optional[int] = None,

        sort_by: Optional[str] = Query("id", enum=["id", "name", "created_at", "price"]),
        sort_order: Optional[bool] = False,

        page: int = 1,
        page_size: int = 10,
    ):
        self.name = name
        self.name_exact = name_exact
        self.name_startswith = name_startswith
        self.name_endswith = name_endswith
        self.name_icontains = name_icontains

        self.created_at = created_at
        self.created_before = created_before
        self.created_after = created_after

        self.price = price
        self.price_min = price_min
        self.price_max = price_max

        self.sort_by = sort_by
        self.sort_order = sort_order

        self.page = page
        self.page_size = page_size