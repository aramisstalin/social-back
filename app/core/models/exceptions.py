class ExternalAPIError(Exception):
    """Custom exception for external API errors."""

    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class CircuitBreakerError(ExternalAPIError):
    """Exception raised when circuit breaker is open."""
    pass


class RateLimitError(ExternalAPIError):
    """Exception raised when rate limit is exceeded."""
    pass