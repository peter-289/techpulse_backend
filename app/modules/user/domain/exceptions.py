"""User-context domain errors.

Empty until Phase 6. The user context's failures still surface as shared-kernel
errors from ``app.exceptions.exceptions``; the ``User`` aggregate that would own
them is deferred to Phase 6b, and the support-chat errors below are registered in
``app.exceptions.handlers`` against the status codes their predecessors produced.
"""

from __future__ import annotations


class UserDomainError(Exception):
    """Base for every error the user context raises."""


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
