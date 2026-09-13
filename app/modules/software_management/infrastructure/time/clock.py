from datetime import datetime, timezone


class SystemClock:
    """System clock"""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)
