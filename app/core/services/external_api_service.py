import asyncio
import json
from enum import verify

import httpx
from fastapi import status
from datetime import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy.orm import query

from app.core.models.exceptions import CircuitBreakerError, ExternalAPIError
from http import HTTPMethod

from app.core.schemas.external_api_request import ExternalApiRequest
from app.core.services import get_circuit_breaker, get_http_client_manager


class ExternalAPIService:
    """Service for making external API calls."""

    @staticmethod
    async def make_request(
            endpoint: str,
            method: HTTPMethod,
            headers: Optional[Dict[str, str]] = None,
            query_params: Optional[Dict[str, Any]] = None,
            body: Optional[Dict[str, Any]] = None,
            request_id: Optional[str] = None,
            api_key: Optional[str] = None,
    ):
        """Make HTTP request to external service."""

        circuit_breaker = get_circuit_breaker()

        if not circuit_breaker.can_execute():
            raise CircuitBreakerError(
                message=f"Circuit breaker is open. Cannot execute request.",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        start_time = datetime.utcnow()

        # Prepare headers
        request_headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "X-Request-ID": request_id or f"req_{int(start_time.timestamp() * 1000)}"
        }
        if headers:
            request_headers.update(headers)

        client_manager = get_http_client_manager()

        try:
            client = await client_manager.get_client()
            # Make the request
            response = await client.request(
                method=method,
                url=endpoint,
                headers=request_headers,
                params=query_params,
                json=body if body else None,
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Handle response
            if response.status_code >= 400:
                circuit_breaker.record_failure()
                error_detail = f"External API error: {response.status_code}"
                try:
                    error_response = response.json()
                    error_detail = error_response.get('detail', error_detail)
                except:
                    error_detail = response.text[:200]

                raise ExternalAPIError(
                    message=error_detail,
                    status_code=response.status_code
                )

            circuit_breaker.record_success()

            # Parse response
            try:
                response_data = response.json() if response.content else {}
            except json.JSONDecodeError:
                response_data = response

            return {
                "success": response_data.get('status') or False,
                "data": response_data.get('data') or [],
                "message": f"{response_data.get('message')}" or response_data,
                "execution_time_ms": execution_time,
                "status_code": response.status_code,
                "request_id": request_headers["X-Request-ID"]
            }

        except httpx.RequestError as e:
            circuit_breaker.record_failure()
            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            raise ExternalAPIError(
                f"Request to {endpoint} failed: {str(e)}",
                status_code=503
            )
        finally:
            await client_manager.close()

    @staticmethod
    async def make_requests_batch(
            requests: List[ExternalApiRequest],
            parallel: bool = True
    ) -> List[Dict[str, Any]]:
        """Make multiple requests to external service."""

        if parallel:
            tasks = [
                ExternalAPIService.make_request(
                    endpoint=req.endpoint,
                    method=req.method,
                    headers=req.headers,
                    query_params=req.query_params,
                    body=req.body
                )
                for req in requests
            ]
            return await asyncio.gather(*tasks, return_exceptions=True)
        else:
            results = []
            for req in requests:
                try:
                    result = await ExternalAPIService.make_request(
                        endpoint=req.endpoint,
                        method=req.method,
                        headers=req.headers,
                        query_params=req.query_params,
                        body=req.body
                    )
                    results.append(result)
                except Exception as e:
                    results.append(e)
            return results
