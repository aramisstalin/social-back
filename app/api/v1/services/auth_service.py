import asyncio
from functools import lru_cache

from datetime import timedelta
from fastapi import Depends
from pydantic.v1 import EmailStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.services import send_verification_email, send_reset_password_email

from app.api.v1.models import Role, User as UserModel
from app.api.v1.repositories import UserRepository, get_user_repository
from app.api.v1.schemas import User, UserCreate, UserCreateToSave, UserWithRoles

from app.core.security import verify_password, get_password_hash, create_verification_token, decode_token, create_access_token

DEFAULT_ROLE_NAME = "CONSULTOR"


class AuthService:

    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    async def authenticate_user(self, db: AsyncSession, cpf: str, password: str) -> UserWithRoles | None:
        user = await self.user_repository.get_user_orm_by_cpf(db, cpf)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None

        return user

    async def register_user(self, db: AsyncSession, user_in: UserCreate) -> User:
        existing_email = await self.user_repository.get_user_by_email(db, email=user_in.email)
        if existing_email:
            raise ValueError("O usuário não pode ser registrado")

        existing_cpf = await self.user_repository.get_user_by_cpf(db, cpf=user_in.cpf)
        if existing_cpf:
            raise ValueError("O usuário não pode ser registrado")

        token = create_verification_token(str(user_in.email))

        user = UserCreateToSave(**user_in.model_dump(), verification_token=token, is_active=True, is_validated=False, email_verified=False)
        user.hashed_password =get_password_hash(user_in.hashed_password)

        try:
            result = await db.execute(
                select(Role).where(Role.name == DEFAULT_ROLE_NAME)
            )
            role = result.scalar_one_or_none()
            if not role:
                raise ValueError(f"Default role '{DEFAULT_ROLE_NAME}' not found.")

            # Create user and associate with role
            user_model = UserModel(**user.model_dump(), roles=[role])
            db.add(user_model)
            await db.flush()  # Gets ID and validates
            await db.commit()

            asyncio.create_task(send_verification_email(user_model.email, user_model.verification_token))

            return User.model_validate(user_model)

        except Exception as e:
            raise RuntimeError(f"Error creating user: {e}") from e


    async def password_reset_request(self, db: AsyncSession, email: str):
        user = await self.user_repository.get_user_orm_by_email(db, EmailStr(email))

        if user is None:
            raise ValueError("Token não válido")

        token = create_verification_token(email)
        if token is None:
            raise ValueError("Unable to create token")
        user.reset_password_token = token
        try:
            await db.commit()
            asyncio.create_task(send_reset_password_email(email, token))

        except IntegrityError:
            await db.rollback()
            raise ValueError("Reset password request: a ação não pôde ser executada.")


    async def reset_password(self, db: AsyncSession, password: str, token: str):
        payload = decode_token(token)
        email = payload["sub"]

        if email is None or not email:
            raise ValueError("Token não válido")

        user = await self.user_repository.get_user_orm_by_email(db, email)

        if user is None:
            raise ValueError("Token não válido")

        if user.reset_password_token != token:
            raise ValueError("Para validar seu e-mail, use o último token de verificação enviado")

        user.hashed_password = get_password_hash(password)
        user.reset_password_token = create_access_token({"sub": email}, timedelta(minutes=0))
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError("Reset password: a ação não pôde ser executada.")


@lru_cache()
def get_auth_service(user_repository: UserRepository = Depends(get_user_repository)) -> AuthService:
    return AuthService(user_repository)