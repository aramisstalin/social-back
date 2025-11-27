from app.api.v1.routers import (users, auth, permissions, roles)
from app.core.config import settings
from app.core.routers import emails


def bootstrap_app(app):
    try:
        prefix = f"/api/{settings.VERSION}"

        app.include_router(emails.router, prefix=prefix, tags=["Emails"])
        
        app.include_router(roles.router, prefix=prefix, tags=["Perfis"])
        app.include_router(permissions.router, prefix=prefix, tags=["Permissoes"])
        app.include_router(users.router, prefix=prefix, tags=["Usuários"])
        app.include_router(auth.router, prefix=prefix, tags=["Authentication"])
        print("Application started successfully.")

    except ValueError:
        print("Failed to start the application.")
        print(ValueError)