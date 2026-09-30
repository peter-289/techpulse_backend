"""Resource-context domain errors.

The shared-kernel errors in ``app.exceptions.exceptions`` covered this
context's failures before the domain model existed. Each replacement below is
registered in ``app.exceptions.handlers`` against the *same* status code its
predecessor produced, so no route changed behaviour:

    NotFoundError    (404) -> ResourceNotFoundError        (404)
    ConflictError    (409) -> DuplicateResourceSlugError  (409)
    ValidationError  (422) -> InvalidResourceTypeError     (422)
    unhandled (500)  (500) -> ResourceRepositoryUnavailableError (500)

See ``docs/adr/0007-resource-domain-model``.
"""

from __future__ import annotations


class ResourceDomainError(Exception):
    """Base for every error the resource context raises."""


class ResourceNotFoundError(ResourceDomainError):
    """No resource exists for the requested slug."""


class DuplicateResourceSlugError(ResourceDomainError):
    """The slug is already taken by another resource."""


class InvalidResourceTypeError(ResourceDomainError):
    """The type is outside the resource type vocabulary."""


class ResourceRepositoryUnavailableError(ResourceDomainError):
    """The resource store could not be reached.

    Mapped to 500, not 503, because that is what an escaping driver error
    produced before the port existed. 503 is the more truthful code for an
    unavailable dependency, but changing it is an observable difference, so it
    waits for the phase that is allowed to change the contract.
    """
