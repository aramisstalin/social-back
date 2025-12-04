from fastapi import Request, status, HTTPException
from app.core.schemas import SocialUser as User
from app.core.helpers import verify_jwt_token


def get_current_user_from_access_token(request: Request) -> User:
    # 1. Get token from header (This is what Angular sends via the Interceptor)
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth_header.split(" ")[1]

    # 2. Validate token (Decodes token signed by our SECRET_KEY)
    token_data = verify_jwt_token(access_token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Simulate fetching user data from DB using token_data.user_id
    # Replace this with a DB call (e.g., using SQLAlchemy)
    # For now, we mock the User object structure expected by the frontend
    mock_user_db = {
        "12345": User(id="12345", email="mock@user.com", name="Mock User", emailVerified=True)
    }

    user = mock_user_db.get(token_data.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user