from fastapi import Depends, HTTPException, status
from functools import wraps
from app.api.v1.models import User
from typing import List


from app.core.security import get_current_active_validated_user


def require_permissions(required_permissions: List[str]):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_active_validated_user), **kwargs):
            # Get all permissions the user has through their roles
            user_permissions = set()
            for role in current_user.roles:
                for permission in role.permissions:
                    user_permissions.add(permission.name)

            # Check if user has all required permissions
            if not all(perm in user_permissions for perm in required_permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions"
                )

            return await func(*args, current_user=current_user, **kwargs)

        return wrapper

    return decorator