"""User-context domain errors.

Each replacement below is registered in ``app.exceptions.handlers`` against the
*same* status code the shared-kernel error it replaces produced, so no route
changed behaviour:

    NotFoundError  (404) -> UserNotFoundError    (404)
    ConflictError  (409) -> DuplicateUserError   (409)
    unhandled      (500) -> ...RepositoryUnavailableError (500)

See ``docs/adr/0009-user-aggregate``.
"""

from __future__ import annotations


class UserDomainError(Exception):
    """Base for every error the user context raises."""


class UserNotFoundError(UserDomainError):
    """No account exists for the requested id."""


class DuplicateUserError(UserDomainError):
    """The username or email is already registered."""


class ChatMessageDomainError(UserDomainError):
    """A support exchange could not be formed."""


class ChatMessageTooShortError(ChatMessageDomainError):
    """The question was shorter than the minimum the support bot can answer.

    Replaces the shared-kernel ``ValidationError`` the service raised, so this
    is still a 422.
    """


class ChatMessageRepositoryUnavailableError(ChatMessageDomainError):
    """The chat store could not be reached.

    Mapped to 500, not 503, because that is what an escaping driver error
    produced before the port existed.
    """


class UserRepositoryUnavailableError(UserDomainError):
    """The user store could not be reached.

    Mapped to 500, not 503, because that is what an escaping driver error
    produced before the port existed.
    """


class SessionRepositoryUnavailableError(UserDomainError):
    """The session store could not be reached.

    Mapped to 500, not 503, for the same reason as
    :class:`UserRepositoryUnavailableError`.
    """
