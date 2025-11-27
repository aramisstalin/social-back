from datetime import datetime, timedelta
from functools import lru_cache

from app.core import settings


class CircuitBreaker:

    def __init__(self, failure_threshold: int = settings.FAILURE_THRESHOLD, recovery_timeout: int = settings.RECOVERY_TIMEOUT):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half_open

    def can_execute(self) -> bool:
        """Check if request can be executed."""
        if self.state == "closed":
            return True
        elif self.state == "open":
            if self.last_failure_time and \
                    datetime.utcnow() - self.last_failure_time > timedelta(seconds=self.recovery_timeout):
                self.state = "half_open"
                return True
            return False
        else:  # half_open
            return True

    def record_success(self):
        """Record successful execution."""
        self.failure_count = 0
        self.state = "closed"

    def record_failure(self):
        """Record failed execution."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()

        if self.failure_count >= self.failure_threshold:
            self.state = "open"


@lru_cache
def get_circuit_breaker() -> CircuitBreaker:
    """Get a CircuitBreaker instance with configured settings."""
    return CircuitBreaker(
        settings.FAILURE_THRESHOLD,
        settings.RECOVERY_TIMEOUT
    )
