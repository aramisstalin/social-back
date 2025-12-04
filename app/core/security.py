from passlib.context import CryptContext
from jose import JWTError, jwt, ExpiredSignatureError
from datetime import datetime, timedelta, timezone

from typing import Optional, List
from typing_extensions import Annotated
from functools import wraps
from fastapi import Depends, status, HTTPException, Header, Request
from fastapi.security import OAuth2PasswordBearer
from app.db.session import get_session
from app.core.config import settings

from app.api.v1.models import User
from app.api.v1.repositories import UserRepository, get_user_repository

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

API_KEY = settings.API_KEY

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="API Key Inválida!")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"sub": data["sub"], "exp": expire}

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as e:
        raise Exception("Formato de token inválido recebido")


def is_token_expired(token: str) -> bool:
    payload = decode_token(token)
    if not payload: return True

    current_time = datetime.now(timezone.utc).timestamp()

    exp = payload.get("exp")
    if exp is None or not exp or exp < current_time:
        return True

    return False


# Validate JWT token
async def get_current_user(
        request: Request,
        db = Depends(get_session),
        user_repository: UserRepository = Depends(get_user_repository),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais."
    )
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(401, detail="Unauthorized")
    try:
        payload = decode_token(token)
        if not payload or payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sua sessão expirou. Por favor, faça login novamente.",
            )

        user_id: str = payload.get("sub")

        if not user_id or user_id is None:
            raise credentials_exception

        if is_token_expired(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sua sessão expirou. Por favor, faça login novamente.",
            )

        user = await user_repository.get_by_id(db, user_id=user_id)

        if not user or user is None:
            raise credentials_exception

        return user
    except JWTError:
        raise credentials_exception


async def get_current_active_validated_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if not current_user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail não verificado. Você precisa verificar seu e-mail antes de prosseguir"
        )

    if not current_user.is_validated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Seu usuário não foi validado, entre em contato com os administradores."
        )

    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="O usuário não está ativo, entre em contato com os administradores."
        )

    return current_user


async def get_current_admin_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if any(role.name == "ADMIN" and current_user.is_active for role in current_user.roles):
        return True

    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Você não tem privilégios suficientes para executar a ação."
        )


def create_verification_token(email: str):
    expire = datetime.now(timezone.utc) + timedelta(hours=24)  # Token expires in 24 hours
    payload = {"sub": email, "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def is_verify_email_token_valid(token: str):
    try:
        payload = decode_token(token)
        if payload is None or not payload:
            return False
        email = payload.get("sub")
        exp_timestamp = payload.get("exp")

        if email is None or not email or exp_timestamp is None or not exp_timestamp:
            return False

        if is_token_expired(token):
            return False

        return True

    except ExpiredSignatureError:
        return False  # Token has expired
    except JWTError:
        return False  # Invalid token
    except ValueError:
        return False


def require_permissions(required_permissions: List[str]):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_active_validated_user), **kwargs):
            user_permissions = set()
            for role in current_user.roles:
                for permission in role.permissions:
                    user_permissions.add(permission.name)

            # Check if user has all required permissions
            if not all(perm in user_permissions for perm in required_permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Permissões insuficientes"
                )

            return await func(*args, current_user=current_user, **kwargs)

        return wrapper

    return decorator