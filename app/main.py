import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.trustedhost import TrustedHostMiddleware

# from contextlib import asynccontextmanager

from app.core.middlewares import security_headers_middleware, request_logging_middleware, rate_limit_exceeded_handler
from app.core.bootstrap import bootstrap_app
from app.core.config import settings
from app.core.middlewares import CORSPreflightMiddleware
from app.api.v1.routers.auth import limiter
from app.core.middlewares.logging import logger

"""
@asynccontextmanager
async def lifespan(app: FastAPI):
    #
    Startup: Create tables, initialize connections
    Shutdown: Close connections gracefully
    #
    # Startup
    logger.info("Starting up application...")
    
    # Create tables (in production, use Alembic migrations)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("Database tables created/verified")
    
    yield  # Application runs
    
    # Shutdown
    logger.info("Shutting down application...")
    await engine.dispose()
    logger.info("Database connections closed")
"""


#    lifespan=lifespan,
app = FastAPI(
    title=settings.PROJECT_NAME,
    debug=settings.DEBUG,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"if settings.DEBUG else None,  # Disable in production
    docs_url=f"{settings.API_V1_STR}/docs" if settings.DEBUG else None,  # Disable in production,
    redoc_url=f"{settings.API_V1_STR}/redoc" if settings.DEBUG else None,  # Disable in production
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
    allow_headers=["Content-type", "Authorization", "X-Requested-With"],  #* More permissive for compatibility
    expose_headers=["Content-Length", "Content-Type"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# Trusted host middleware (prevent Host header attacks)
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS  # ["yourapp.com", "*.yourapp.com"]
    )

# Security headers middleware
app.middleware("http")(security_headers_middleware)

# Request logging middleware
app.middleware("http")(request_logging_middleware)

# Exception handlers
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Custom 404 handler"""
    return JSONResponse(
        status_code=404,
        content={"detail": "Endpoint not found"}
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    """Custom 500 handler - don't expose internal details"""
    logger.error(f"Internal server error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0",
                port=8000,
                # reload=settings.DEBUG,
                log_level="info"
        )
