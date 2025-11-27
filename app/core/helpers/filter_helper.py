from typing import Any, Callable
from sqlalchemy.sql import operators
from sqlalchemy.orm import aliased
from sqlalchemy import select, func, and_, or_, asc, desc


OPERATOR_MAPPING: dict[str, Callable[[Any, Any], Any]] = {
    "eq": operators.eq,
    "ne": operators.ne,
    "lt": operators.lt,
    "lte": operators.le,
    "gt": operators.gt,
    "gte": operators.ge,
    "in": lambda field, value: field.in_(value),
    "not_in": lambda field, value: ~field.in_(value),
    "contains": lambda field, value: field.contains(value),
    "icontains": lambda field, value: field.ilike(f"%{value}%"),
    "startswith": lambda field, value: field.startswith(value),
    "istartswith": lambda field, value: field.ilike(f"{value}%"),
    "endswith": lambda field, value: field.endswith(value),
    "iendswith": lambda field, value: field.ilike(f"%{value}"),
    "isnull": lambda field, value: field.is_(None) if value else field.isnot(None),
    "exact": operators.eq,  # alias for clarity
}


def apply_filters_and_sorting(query, model, filters: dict, sort: list[str] = None, joins: dict = None, logic_operator: str = "or"):
    joins = joins or {}
    conditions = []
    logic_fn = and_ if logic_operator.lower() == "and" else or_

    # FILTERS
    for key, value in filters.items():
        parts = key.split("__")
        field_path = parts[0]
        operator_key = parts[1] if len(parts) > 1 else "eq"

        operator_func = OPERATOR_MAPPING.get(operator_key)
        if not operator_func:
            raise ValueError(f"Unsupported filter operator: {operator_key}")

        if "." in field_path:
            rel_name, field_name = field_path.split(".", 1)
            relationship = getattr(model, rel_name)

            if rel_name not in joins:
                related_model = relationship.property.mapper.class_
                alias = aliased(related_model)
                joins[rel_name] = alias
                query = query.join(alias, relationship)
            else:
                alias = joins[rel_name]

            column = getattr(alias, field_name)
        else:
            column = getattr(model, field_path)

        conditions.append(operator_func(column, value))

    if conditions:
        query = query.where(logic_fn(*conditions))

    # SORTING
    if sort:
        order_by = []
        for field in sort:
            direction = asc if field[-1] == "+" else desc
            field = field[:-1]

            if "." in field:
                rel_name, field_name = field.split(".", 1)
                relationship = getattr(model, rel_name)

                if rel_name not in joins:
                    related_model = relationship.property.mapper.class_
                    alias = aliased(related_model)
                    joins[rel_name] = alias
                    query = query.join(alias, relationship)
                else:
                    alias = joins[rel_name]

                column = getattr(alias, field_name)
            else:
                column = getattr(model, field)

            order_by.append(direction(column))

        if order_by:
            query = query.order_by(*order_by)

    return query, joins


async def paginate(session, query, page: int = 1, page_size: int = 20):
    # Get total count efficiently
    count_query = select(func.count()).select_from(query.subquery())
    total = await session.scalar(count_query) or 0

    offset = (page - 1) * page_size

    # Get paginated items
    paginated_query = query.limit(page_size).offset(offset)
    result = await session.execute(paginated_query)
    items = result.scalars().all()

    return {
        "total": total,
        "items": items,
    }


# USE EXAMPLE

# filters = {
#     "proposta.campanha_id__in": [1, 2],
#     "proposta.cnes.nome__icontains": "hospital",
#     "created_at__gte": "2024-01-01",
#     "ativo__eq": True
# }

# query = select(MyModel)
# query, _ = apply_filters(query, MyModel, filters)
# return await paginate(db, query, page=1, page_size=10)