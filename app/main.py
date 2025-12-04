import traceback
from typing import Annotated

from fastapi import FastAPI, Request, status
from fastapi.params import Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager

from app.core.schemas import ApiResponse
from app.api.v1.schemas import UserRead as User
from app.api.v1.services import get_current_user
from app.core.services import get_http_client_manager
from app.core.middlewares import security_headers_middleware, request_logging_middleware, rate_limit_exceeded_handler
from app.core.bootstrap import bootstrap_app
from app.core.config import settings
from app.db import db_manager
from app.core.middlewares import CORSPreflightMiddleware
from app.api.v1.routers.auth import limiter
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown events, ensuring external resources
    like the HTTP client pool are initialized and cleaned up properly.
    """
    # Start
    logger.info("Starting application...")

    # Client Http
    manager = get_http_client_manager()
    logger.info("Initializing HTTP Client Pool...")
    await manager.initialize()
    logger.info("HTTP Client initialized.")

    # Database connection
    logger.info("Initializing database connection...")
    await db_manager.connect()
    logger.info("Database connected.")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")

    # Disconnect: Clean up the connection pool
    logger.info("Disconnecting database pool...")
    await db_manager.disconnect()
    logger.info("Database pool disconnected.")

    # Closing HTTP Client Pool
    logger.info("Closing HTTP Client Pool...")
    await manager.close()


app = FastAPI(
    title=settings.PROJECT_NAME,
    debug=settings.DEBUG,
    version=settings.VERSION,
    lifespan=lifespan,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc"
    )

# Add rate limiter state to app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(CORSPreflightMiddleware)

origins = [
    settings.FRONTEND_URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"],
    allow_headers=["*"],  # More permissive for compatibility
    expose_headers=["Content-Length", "Content-Type"],
    max_age=600,  # Cache preflight requests for 10 minutes
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler with security considerations.
    """
    tb = traceback.format_exc()

    # Log the full error server-side
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    # In production, don't expose traceback to clients
    response_content = {
        "status": "error",
        "error_type": exc.__class__.__name__,
        "message": str(exc),
    }

    # Only include traceback in development
    if settings.ENVIRONMENT.capitalize != "PRODUCTION" and settings.ENVIRONMENT.capitalize != "PROD":
        response_content["traceback"] = tb

    return JSONResponse(
        status_code=500,
        content=response_content,
    )

# Security headers middleware
app.middleware("http")(security_headers_middleware)

# Request logging middleware
app.middleware("http")(request_logging_middleware)

# Exception handlers
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)


bootstrap_app(app)


# Health check endpoint (useful for monitoring)
@app.get("/health", tags=["health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": settings.VERSION}


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "FastAPI Google OAuth API",
        "docs": "/api/docs" if settings.DEBUG else "disabled"
    }

@app.get(
    "/data",
    response_model=ApiResponse,
    status_code=status.HTTP_200_OK,
    summary="Get protected data",
    description="Returns protected data for authenticated users only."
)
async def get_protected_data(
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    Example protected endpoint that requires a valid Bearer JWT.

    The `get_current_user` dependency:
    - Extracts the bearer token via HTTPBearer
    - Validates Google ID token
    - Fetches the user from DB
    - Ensures user is active
    - Raises HTTP_401_UNAUTHORIZED if invalid
    """
    return ApiResponse(
        status_code=status.HTTP_200_OK,
        data={
            "message": f"Hello, {current_user.name}. Your data is secured!",
            "user_id": current_user.id
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0",
                port=8000,
                # reload=settings.DEBUG,
                log_level="info"
        )
