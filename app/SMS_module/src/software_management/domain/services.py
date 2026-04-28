from __future__ import annotations

from .entities.software import Software
from .entities.version import Version
from .exceptions import NotFoundError


class ReleaseSelector:
    """Domain service for selecting a downloadable release."""

    @staticmethod
    def resolve(software: Software, requested: Version | None = None) -> Version:
        if requested is not None:
            if not requested.is_downloadable():
                raise NotFoundError("Requested version is not downloadable.")
            return requested

        latest = software.latest_downloadable()
        if latest is None:
            raise NotFoundError("No downloadable versions are available.")
        return latest
