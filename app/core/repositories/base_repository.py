from app.core.helpers.filter_helper import apply_filters_and_sorting, paginate
from app.core.schemas import BaseFilter

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
from typing import TypeVar, Generic
from sqlalchemy.orm import declarative_base


Base = declarative_base()
T = TypeVar("T", bound=Base)

class BaseRepository(Generic[T]):
    def __init__(self, model: Generic[T]):
        self.model = model

    async def create(self, db: AsyncSession, item, schema=None):
        item = self.model(**item.model_dump())
        db.add(item)
        try:
            await db.commit()
            await db.refresh(item)
            if schema:
                return schema.model_validate(item)
            return item.__dict__
        except IntegrityError as e:
            await db.rollback()
            raise ValueError(f"Adicionando {self.model.__name__}: ocorreu um erro. {str(e)}")

    async def get_by_id(self, db: AsyncSession, item_id, schema=None):
        result = await db.execute(select(self.model).filter(self.model.id == item_id))
        item = result.scalars().first()
        if not item:
            return None
        if schema:
            return schema.model_validate(item)
        return item.__dict__

    async def _get_by_id_orm(self, db: AsyncSession, item_id, schema=None):
        result = await db.execute(select(self.model).filter(self.model.id == item_id))
        item = result.scalars().first()
        if not item:
            return None

        return item

    async def get_all(self, db: AsyncSession, skip: int = 0, limit: int = 20, schema=None):
        result = await db.execute(select(self.model).offset(skip).limit(limit))
        items = result.scalars().all()
        if schema:
            return [schema.model_validate(item) for item in items]
        return [item.__dict__ for item in items]

    async def update(self, db: AsyncSession, item_data, item_id, schema=None):
        item = await self._get_by_id_orm(db, item_id)
        if item is None or not item:
            return None
        update_values = item_data.model_dump(exclude_unset=True)
        for key, value in update_values.items():
            setattr(item, key, value)
        try:
            await db.commit()
            await db.refresh(item)
            if schema:
                return schema.model_validate(item)
            return item.__dict__
        except IntegrityError:
            await db.rollback()
            raise ValueError(f'Atualizando {self.model.__name__}: ocorreu um erro. Verifique os dados.')

    async def delete(self, db: AsyncSession, item_id) -> bool:
        item = await self._get_by_id_orm(db, item_id)
        if not item:
            return False
        try:
            await db.delete(item)
            await db.commit()
            return True
        except IntegrityError:
            await db.rollback()
            raise ValueError(f'Excluindo {self.model.__name__}: ocorreu um erro. Verifique os dados.')

    async def get_filtered_items(self, db: AsyncSession, filters: BaseFilter):
        try:
            base_query = self.get_filter_query()

            filter_dict, sort_fields, logic_operator = self.build_filters_from_params(filters).values()

            query, _ = apply_filters_and_sorting(base_query, self.model, filters=filter_dict, sort=sort_fields,
                                                 logic_operator=logic_operator)

            return await paginate(db, query, page=filters.page, page_size=filters.page_size)
        except Exception as e:
            raise ValueError(f"Filtrando {self.model.__name__}: ocorreu um erro. Verifique os dados. {e}")

    def get_filter_query(self):
        return select(self.model)

    def build_filters_from_params(self, filters: BaseFilter):
        filter_dict = filters.model_dump(exclude={"sort", "page", "page_size", "logic_operator"}, exclude_none=True)
        sort_fields = filters.sort or []
        logic_operator = filters.logic_operator or "or"

        return {"filter_dict": filter_dict, "sort_fields": sort_fields, "logic_operator": logic_operator}
