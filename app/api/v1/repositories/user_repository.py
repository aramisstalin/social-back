from functools import lru_cache
from typing import List, Optional
from uuid import UUID

from pydantic import EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.core.helpers.filter_helper import paginate, apply_filters_and_sorting
from app.core.repositories import BaseRepository
from app.api.v1.models import User as UserModel, Role as RoleModel
from app.api.v1.schemas import User, UserFilter, UserWithRoles


class UserRepository(BaseRepository):
    def __init__(self):
        super().__init__(UserModel)

    async def get_all(self, db: AsyncSession, skip: int = 0, limit: int = 20) -> List[User]:
        users = await db.execute(select(self.model).offset(skip).limit(limit))
        orm_users = users.scalars().all()
        return [User.model_validate(u) for u in orm_users]

    async def get_filtered_items(self, db: AsyncSession, filters: UserFilter):
        try:
            base_query = select(self.model).options(
                selectinload(self.model.roles)
            )

            filter_dict, sort_fields, logic_operator = self.build_filters_from_params(filters).values()

            query, _ = apply_filters_and_sorting(
                base_query,
                self.model,
                filters=filter_dict,
                sort=sort_fields,
                logic_operator=logic_operator,
            )

            return await paginate(db, query, page=filters.page, page_size=filters.page_size)

        except Exception as e:
            raise ValueError(f"Filtrando {self.model.__name__}: ocorreu um erro. Verifique os dados. {e}")

    async def get_by_id(self, db: AsyncSession, user_id: UUID) -> Optional[UserWithRoles]:
        """
        Retrieve a User by ID and return as Pydantic schema.

        Args:
            db: Database session
            user_id: User's unique identifier

        Returns:
            UserWithRoles Pydantic schema or None if not found
        """
        query = self._build_user_query_with_relationships().where(self.model.id == user_id)
        result = await db.execute(query)
        orm_user = result.scalars().first()
        return UserWithRoles.model_validate(orm_user) if orm_user else None

    def _build_user_query_with_relationships(self):
        """
        Build a base SQLAlchemy query with eager loading of relationships.

        This helper method centralizes the query construction logic to ensure
        consistent eager loading across all user retrieval methods.

        Returns:
            SQLAlchemy Select statement with eager-loaded relationships

        Security:
            - Eager loading prevents N+1 query vulnerabilities
            - Ensures consistent data loading across all methods
        """
        return select(self.model).options(
            selectinload(self.model.roles).options(
                selectinload(RoleModel.permissions)
            )
        )

    async def _get_user_orm_by_cpf(self, db: AsyncSession, cpf: str) -> Optional[UserModel]:
        """
        Internal method to retrieve a User ORM model by CPF.

        This method returns the raw SQLAlchemy ORM model with eagerly loaded relationships.
        Use this when you need to work with the ORM model directly (e.g., for updates).

        Args:
            db: Database session
            cpf: User's CPF (Brazilian tax ID)

        Returns:
            UserModel ORM instance or None if not found

        Security:
            - CPF should be validated before calling this method
            - Eager loading prevents N+1 queries
        """
        query = self._build_user_query_with_relationships().where(self.model.cpf == cpf)
        result = await db.execute(query)
        return result.scalars().first()

    async def get_user_by_cpf(self, db: AsyncSession, cpf: str) -> Optional[UserWithRoles]:
        """
        Retrieve a User by CPF and return as Pydantic schema.

        This method returns a validated Pydantic schema with all user data and relationships.
        Use this when you need a read-only representation of the user.

        Args:
            db: Database session
            cpf: User's CPF (Brazilian tax ID)

        Returns:
            UserWithRoles Pydantic schema or None if not found

        Security:
            - CPF should be validated before calling this method
            - Returns immutable Pydantic model to prevent accidental modifications
        """
        orm_user = await self._get_user_orm_by_cpf(db, cpf)
        return UserWithRoles.model_validate(orm_user) if orm_user else None

    async def get_user_orm_by_cpf(self, db: AsyncSession, cpf: str) -> Optional[UserModel]:
        """
        Public method to retrieve a User ORM model by CPF.

        This is a public wrapper around _get_user_orm_by_cpf for external use.
        Returns the raw SQLAlchemy ORM model with eagerly loaded relationships.

        Args:
            db: Database session
            cpf: User's CPF (Brazilian tax ID)

        Returns:
            UserModel ORM instance or None if not found

        Security:
            - CPF should be validated before calling this method
            - Use this method when you need to modify the user object

        Example:
            user_orm = await user_repo.get_user_orm_by_cpf(db, "12345678900")
            if user_orm:
                user_orm.is_active = False
                await db.commit()
        """
        return await self._get_user_orm_by_cpf(db, cpf)

    async def _get_user_orm_by_email(self, db: AsyncSession, email: EmailStr) -> Optional[UserModel]:
        """
        Internal method to retrieve a User ORM model by email.

        This method returns the raw SQLAlchemy ORM model with eagerly loaded relationships.
        Use this when you need to work with the ORM model directly (e.g., for updates).

        Args:
            db: Database session
            email: User's email address

        Returns:
            UserModel ORM instance or None if not found

        Security:
            - Email should be validated before calling this method
            - Eager loading prevents N+1 queries
        """
        query = self._build_user_query_with_relationships().where(self.model.email == email)
        result = await db.execute(query)
        return result.scalars().first()

    async def get_user_by_email(self, db: AsyncSession, email: EmailStr) -> Optional[UserWithRoles]:
        """
        Retrieve a User by email and return as Pydantic schema.

        This method returns a validated Pydantic schema with all user data and relationships.
        Use this when you need a read-only representation of the user.

        Args:
            db: Database session
            email: User's email address

        Returns:
            UserWithRoles Pydantic schema or None if not found

        Security:
            - Email is validated by Pydantic EmailStr type
            - Returns immutable Pydantic model to prevent accidental modifications
        """
        orm_user = await self._get_user_orm_by_email(db, email)
        return UserWithRoles.model_validate(orm_user) if orm_user else None

    async def get_user_orm_by_email(self, db: AsyncSession, email: EmailStr) -> Optional[UserModel]:
        """
        Public method to retrieve a User ORM model by email.

        This is a public wrapper around _get_user_orm_by_email for external use.
        Returns the raw SQLAlchemy ORM model with eagerly loaded relationships.

        Args:
            db: Database session
            email: User's email address

        Returns:
            UserModel ORM instance or None if not found

        Security:
            - Email is validated by Pydantic EmailStr type
            - Use this method when you need to modify the user object

        Example:
            user_orm = await user_repo.get_user_orm_by_email(db, "user@example.com")
            if user_orm:
                user_orm.email_verified = True
                await db.commit()
        """
        return await self._get_user_orm_by_email(db, email)

    async def has_roles(self, user: User, required_roles: List[str]) -> bool:
        """
        Check if the given user has all required role names.

        Args:
            user: Pydantic User schema (includes roles)
            required_roles: List of role names to check

        Returns:
            True if the user has all required roles, False otherwise
        """
        user_roles = {role.name for role in user.roles or []}
        return all(role in user_roles for role in required_roles)

    def build_filters_from_params(self, filters: UserFilter):
        """
        Build filter dictionary, sort fields and logic operator from a UserFilter.

        Returns a dict with keys: filter_dict, sort_fields, logic_operator
        """
        filter_dict = filters.model_dump(
            exclude={"sort", "page", "page_size", "role_id", "logic_operator"},
            exclude_none=True,
        )

        # Explicitly map more complex filters if provided
        if filters.nome__icontains is not None:
            filter_dict["nome__icontains"] = filters.nome__icontains

        if filters.sobrenome__icontains is not None:
            filter_dict["sobrenome__icontains"] = filters.sobrenome__icontains

        if filters.cpf__icontains is not None:
            filter_dict["cpf__icontains"] = filters.cpf__icontains

        if filters.email__icontains is not None:
            filter_dict["email__icontains"] = filters.email__icontains

        if filters.is_active is not None:
            filter_dict["is_active"] = filters.is_active

        if filters.is_validated is not None:
            filter_dict["is_validated"] = filters.is_validated

        if filters.email_verified is not None:
            filter_dict["email_verified"] = filters.email_verified

        if filters.role_id is not None:
            filter_dict["roles.id"] = filters.role_id

        sort_fields = filters.sort or []
        logic_operator = filters.logic_operator or "and"

        return {"filter_dict": filter_dict, "sort_fields": sort_fields, "logic_operator": logic_operator}


@lru_cache()
def get_user_repository() -> UserRepository:
    return UserRepository()