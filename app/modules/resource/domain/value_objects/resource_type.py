"""The closed vocabulary of resource types.

Replaces ``ResourceService.ALLOWED_TYPES``, a mutable class-level set of bare
strings that every caller had to remember to compare against, and which
serialized into the API as a column value.
"""

from __future__ import annotations

from enum import StrEnum

from app.modules.resource.domain.exceptions import InvalidResourceTypeError


class ResourceType(StrEnum):
    """The types a resource may have."""

    API = "api"
    KNOWLEDGE = "knowledge"
    SUPPORT = "support"
    UPDATES = "updates"

    @classmethod
    def from_input(cls, raw: str) -> "ResourceType":
        """Validate an incoming type and return it normalized.

        The membership test is on ``raw.lower()`` while the stored value is
        ``raw.strip().lower()``. That asymmetry is inherited, not chosen: the
        service tested the lowercased input but persisted the stripped one, so
        a padded value such as ``" api "`` was rejected even though stripping
        it would have produced a valid type. Validating the normalized value
        would widen the accepted set, which is a contract change, so the old
        behaviour is preserved and flagged in ``docs/REVIEW.md``.
        """
        lowered = raw.lower()
        try:
            cls(lowered)
        except ValueError:
            allowed = ", ".join(sorted(member.value for member in cls))
            raise InvalidResourceTypeError(
                f"Invalid resource type. Allowed: {allowed}"
            ) from None
        return cls(lowered.strip())
