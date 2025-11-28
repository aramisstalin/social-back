from fastapi import Request
import time
from typing import Callable


async def request_logging_middleware(request: Request, call_next: Callable):
    """Log all requests for monitoring"""
    start_time = time.time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration = time.time() - start_time
    
    # Log request details (in production, use proper logging framework)
    print(f"[{request.method}] {request.url.path} - {response.status_code} - {duration:.3f}s")
    
    return response
