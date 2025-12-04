from __future__ import annotations

from app.core.schemas import BaseFilter, BaseSchema

from uuid import UUID
"""

from pydantic import EmailStr, field_validator
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
    #     Validate that password meets strength requirements.
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

"""
"""
Pydantic schemas for User entity with robust validation.

Notes:
- Uses pydantic BaseModel (v1-compatible). If your project uses pydantic v2, adapt validators accordingly.
- Optional usage of `phonenumbers` library (recommended).
- Timezone validation uses zoneinfo.ZoneInfo to confirm a valid tz string.
"""

import re
from datetime import datetime
from typing import Optional, List
from zoneinfo import ZoneInfo

from pydantic import AnyUrl, BaseModel, EmailStr, Field, validator, field_validator

# Optional import for better phone validation. If not installed we fallback to regex.
try:
    import phonenumbers  # type: ignore
    _HAS_PHONENUMBERS = True
except Exception:
    _HAS_PHONENUMBERS = False


# --- Constants & reusable validators ------------------------------------------------

# BCP-47-ish minimal regex: language[-REGION], e.g., "en", "en-US", "pt-BR"
_LOCALE_RE = re.compile(r"^[a-zA-Z]{2,8}(-[a-zA-Z0-9]{2,8})?$")

# Basic fallback phone regex for E.164-ish numbers (e.g. +5511999999999).
_E164_RE = re.compile(r"^\+?[1-9]\d{1,14}$")


def validate_phone_e164(phone: str) -> str:
    """
    Validate phone; prefer phonenumbers library if available.
    Returns normalized E.164 string when possible.
    Raises ValueError on invalid phone.
    """
    if not phone:
        return phone

    if _HAS_PHONENUMBERS:
        try:
            parsed = phonenumbers.parse(phone, None)  # None => expect international prefix or regionless
            if not phonenumbers.is_valid_number(parsed):
                raise ValueError("Invalid phone number format")
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except phonenumbers.NumberParseException as exc:
            raise ValueError(f"Invalid phone number: {exc}") from exc
    else:
        # Fallback light validation (accept E.164-ish)
        if not _E164_RE.match(phone):
            raise ValueError("Invalid phone number format; expected E.164 or install `phonenumbers` for stricter validation")
        # Normalization: ensure leading '+' if missing
        return phone if phone.startswith("+") else f"+{phone}"


def validate_locale_string(locale: str) -> str:
    if not locale:
        return locale
    if not _LOCALE_RE.match(locale):
        raise ValueError("Invalid locale format. Example valid values: 'en', 'en-US', 'pt-BR'")
    return locale


def validate_timezone_string(tz: str) -> str:
    """
    Validate timezone using zoneinfo.ZoneInfo
    """
    if not tz:
        return tz
    try:
        ZoneInfo(tz)
    except Exception:
        raise ValueError("Invalid timezone. Provide a valid TZ database name, e.g. 'UTC', 'America/Sao_Paulo'")
    return tz


# --- Schemas ------------------------------------------------------------------------


class UserBase(BaseModel):
    """Shared fields between create/update/read schemas."""
    email: EmailStr = Field(..., description="Primary email address of the user.")
    name: Optional[str] = Field(None, max_length=255, description="Display name.")
    username: Optional[str] = Field(None, max_length=50, description="Unique username/handle.")
    avatar: Optional[AnyUrl] = Field(None, max_length=1024, description="URL to avatar image (prefer object storage).")
    locale: Optional[str] = Field(None, max_length=20, description="User locale, e.g., 'en-US', 'pt-BR'.")
    phone: Optional[str] = Field(None, max_length=32, description="Phone number, ideally E.164 format.")
    timezone: Optional[str] = Field(None, max_length=64, description="Timezone, e.g., 'UTC' or 'America/Sao_Paulo'.")


class UserCreate(UserBase):
    """Schema used when creating a new user (registration)."""
    password: str = Field(..., min_length=8, max_length=256, description="Plain password (will be hashed by the service).")
    is_email_verified: Optional[bool] = Field(False, description="Whether the email is verified (usually False on sign up).")

    @field_validator("locale")
    def _check_locale(cls, v):
        return validate_locale_string(v)

    @field_validator("phone")
    def _check_phone(cls, v):
        if v is None:
            return v
        return validate_phone_e164(v)

    @field_validator("avatar")
    def _check_avatar(cls, v):
        # AnyUrl already validates scheme & host; additional rules (size, domain) can be enforced in service layer.
        return v

    @field_validator("timezone")
    def _check_timezone(cls, v):
        return validate_timezone_string(v)


class UserUpdate(BaseModel):
    """Partial update schema (PATCH-like)."""
    name: Optional[str] = Field(None, max_length=255)
    username: Optional[str] = Field(None, max_length=50)
    avatar: Optional[AnyUrl] = Field(None, max_length=1024)
    locale: Optional[str] = Field(None, max_length=20)
    phone: Optional[str] = Field(None, max_length=32)
    timezone: Optional[str] = Field(None, max_length=64)
    is_active: Optional[bool] = Field(None)
    is_banned: Optional[bool] = Field(None)

    @field_validator("locale")
    def _check_locale(cls, v):
        return validate_locale_string(v)

    @field_validator("phone")
    def _check_phone(cls, v):
        if v is None:
            return v
        return validate_phone_e164(v)

    @field_validator("timezone")
    def _check_timezone(cls, v):
        return validate_timezone_string(v)


class UserRead(UserBase):
    """Output/response model returned to clients."""
    id: UUID = Field(..., description="UUID as string")
    is_email_verified: bool
    is_phone_verified: bool
    is_active: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    last_login_at: Optional[datetime]

    class Config:
        from_attributes = True  # allows pydantic to read SQLAlchemy objects directly


class UserFilter(BaseFilter):
    user_name__icontains: Optional[str] = None
    email__icontains: Optional[str] = None
    role_id: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    email_verified: Optional[bool] = None
    sort: Optional[List[str]] = ['created_at-']


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
