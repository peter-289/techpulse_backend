"""The port through which the user context reaches a chat model.

``SupportChatService`` imported ``requests`` and read ``app.core.config``
directly, so an application service decided the endpoint, the credentials, the
model name, the prompt and the HTTP error handling, and did it with a
*blocking* call inside a coroutine. This port replaces all of that with one
question in and one reply out.

Two decisions worth stating:

**The call is ``async``.** The previous ``requests.post(..., timeout=60)`` ran on
the event loop thread, so one slow provider could stall every other in-flight
request for up to a minute. An adapter that awaits instead of blocking is a
different contract, not just a different library.

**Configuration arrives as a value object** rather than being read from the
environment at the point of use, so the limit is visible in the signature and can
be varied per call. This follows ``UploadLimits`` and ``AlertThresholds``:
config-shaped domain inputs live in ``domain/ports`` because that is the one
domain layer the composition root is allowed to reach (R2).

The system prompt is deliberately *not* part of that configuration. It is support
policy and lives in ``domain.policies.support_chat_policy``, which the composition
root may not import; the service passes it to each call instead. That keeps the
prompt with the rules about what the bot may say, and keeps R2 intact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class SupportAIUnavailableError(Exception):
    """The chat model could not be reached, or answered unusably.

    Deliberately not a ``UserDomainError``. The service treats this as a
    degraded-mode signal and substitutes a canned reply, so it must not be
    mistaken for a domain rule violation and turned into a 400.
    """


@dataclass(frozen=True, slots=True)
class SupportAIConfig:
    """Everything needed to reach an OpenAI-compatible chat endpoint."""

    base_url: str
    api_key: str
    model: str
    timeout_seconds: float = 60.0

    @property
    def is_configured(self) -> bool:
        """Whether there is a key to authenticate with.

        An empty key is a normal state in local development, not an error, so
        the adapter reports the model as unavailable and the service falls back
        rather than raising a configuration exception.
        """
        return bool(self.api_key.strip())


@runtime_checkable
class SupportAI(Protocol):
    """A chat model that can answer a support question."""

    async def generate_reply(self, question: str, system_prompt: str) -> str:
        """Answer ``question``, or raise :class:`SupportAIUnavailableError`."""
        ...
