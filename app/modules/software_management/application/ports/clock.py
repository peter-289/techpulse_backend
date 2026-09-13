from typing import Protocol, runtime_checkable
from datetime import datetime


@runtime_checkable
class Clock(Protocol):
    """System clock abstraction"""

    def now(self) -> datetime:
        """Return the current UTC time."""
        raise NotImplementedError
