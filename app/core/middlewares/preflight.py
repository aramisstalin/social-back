from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

class CORSPreflightMiddleware(BaseHTTPMiddleware):
    """
    Middleware to handle OPTIONS requests before they reach route handlers.
    This prevents 405 errors on preflight requests.
    """
    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS":
            return JSONResponse(
                content={},
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                    "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, Origin, User-Agent",
                    "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Max-Age": "600",
                }
            )
        
        response = await call_next(request)
        return response