from uuid import UUID

from pydantic import EmailStr
from typing import Optional, List
from datetime import datetime

from app.core.schemas import BaseSchema, BaseFilter
from app.api.v1.schemas import Role


class UserBase(BaseSchema):
    # cpf: str
    email: EmailStr
    user_name: str
    # sobrenome: str

class UserCreate(UserBase):
    hashed_password: Optional[str] = None

    # Password strength validator
    # @validator('hashed_password')
    # def password_strength(cls, v):
    #     """Validate that password meets strength requirements."""
    #     if not re.search(r'[A-Z]', v):
    #         raise ValueError('A senha deve conter pelo menos uma letra maiúscula')
    #     if not re.search(r'[a-z]', v):
    #         raise ValueError('A senha deve conter pelo menos uma letra minúscula')
    #     if not re.search(r'\d', v):
    #         raise ValueError('A senha deve conter pelo menos um dígito')
    #     if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
    #         raise ValueError('A senha deve conter pelo menos um caractere especial')
    #     return v


class UserCreateToSave(UserCreate):
    verification_token: str
    is_active: bool = True
    is_validated: bool = False
    email_verified: bool = False


class UserUpdate(UserBase):
    cpf: Optional[str] = None
    email: Optional[str] = None
    nome: Optional[str] = None
    sobrenome: Optional[str] = None


class UserUpdateVerificationToken(BaseSchema):
    verification_token: str


class UserUpdateEmailVerified(BaseSchema):
    email_verified: bool


class UserUpdateStatus(BaseSchema):
    is_active: bool


class UserUpdateValidity(BaseSchema):
    is_validated: bool


class UserId(BaseSchema):
    user_id: UUID


class User(UserBase):
    id: UUID
    is_active: bool
    is_verified: bool
    email_verified: bool
    created_at: datetime
    # verification_token: Optional[str] = None
    # hashed_password: str
    # updated_at: datetime


class UserWithRoles(User):
    roles: List[Role]


class UserResponse(UserBase):
    id: UUID
    email: EmailStr
    user_name: Optional[str] = None
    picture: Optional[str] = None
    email_verified: bool


# Database Models
class User(UserUpdate):
    id: UUID
    tenant_id: Optional[str] = None
    email: EmailStr
    email_verified: bool
    picture: Optional[str] = None
    locale: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime] = None
    is_active: bool    


class UserFilter(BaseFilter):
    user_name__icontains: Optional[str] = None
    email__icontains: Optional[str] = None
    role_id: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    email_verified: Optional[bool] = None
    sort: Optional[List[str]] = ['created_at-']
