from starlette.responses import JSONResponse

from app.core import settings
from fastapi import Request, status
from typing import Callable
import logging
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def request_logging_middleware(request: Request, call_next: Callable):
    """
    Log all requests for audit trail
    Production: Send to centralized logging (ELK, Datadog)
    """
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration = time.time() - start_time
    
    # Log request details (in production, use proper logging framework)
    print(f"[{request.method}] {request.url.path} - {response.status_code} - {duration:.3f}s")
    
    logger.info(f"{request.method} {request.url.path} - Client: {request.client.host if request.client else 'unknown'}")

    try:
        response = await call_next(request)
        logger.info(f"Response status: {response.status_code}")
        return response
    except Exception as e:
        logger.error(f"Request failed: {e}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"}
        )
