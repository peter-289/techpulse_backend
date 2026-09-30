"""OpenAI-compatible chat model, reached over HTTP.

Replaces a synchronous ``requests.post`` in the application layer. The blocking
call was the reason the service could not be made async-safe: ``requests``
performs real I/O on the calling thread, so with a 60-second timeout a slow
provider would occupy the event loop and stall every other request the worker was
serving. ``httpx.AsyncClient`` was already a pinned dependency and was not used
anywhere, so this adds no new package.

Response parsing is carried over unchanged, including the multi-part ``content``
list and the ``output_text`` shape some providers use.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.modules.user.domain.ports.support_ai import (
    SupportAIConfig,
    SupportAIUnavailableError,
)

logger = logging.getLogger(__name__)

#: Truncation applied to an error body before it reaches a log line. The old
#: code did the same, for the same reason: a provider can return a page of HTML.
_ERROR_BODY_LIMIT = 200


class HttpSupportAI:
    """Implements :class:`SupportAI` against an OpenAI-compatible endpoint."""

    def __init__(self, config: SupportAIConfig):
        self._config = config

    async def generate_reply(self, question: str, system_prompt: str) -> str:
        if not self._config.is_configured:
            # A normal local-development state, not a failure to report. Raising
            # here means the service logs one warning and falls back, which is
            # what used to happen silently.
            logger.info("No AI support API key configured; using the fallback reply")
            raise SupportAIUnavailableError("AI support service is not configured")

        url = f"{self._config.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._config.model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": question},
            ],
        }

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout_seconds),
                # httpx defaults to not following redirects; requests did follow
                # them. Keep the old behaviour rather than silently breaking any
                # provider that redirects.
                follow_redirects=True,
            ) as client:
                response = await client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            raise SupportAIUnavailableError("Failed to reach AI support service") from exc

        if response.status_code >= 400:
            raise SupportAIUnavailableError(
                f"AI support service failed: {response.text[:_ERROR_BODY_LIMIT]}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            logger.warning(
                "AI support service returned non-JSON response: %s",
                response.text[:_ERROR_BODY_LIMIT],
            )
            raise SupportAIUnavailableError(
                "AI support service returned an invalid response"
            ) from exc

        content = _extract_assistant_content(data)
        if not content:
            raise SupportAIUnavailableError("AI support service returned an empty response")
        return content


def _extract_assistant_content(data: dict[str, Any]) -> str:
    """Pull the assistant's text out of a provider response, or return ``""``.

    Handles the OpenAI ``choices[].message.content`` shape whether ``content`` is
    a plain string or a list of typed parts, plus the bare ``output_text`` some
    providers expose.
    """
    choices = data.get("choices") or []
    if choices:
        message = choices[0].get("message") or {}
        content = message.get("content")
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            text_parts = [
                part["text"]
                for part in content
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            ]
            if text_parts:
                return "\n".join(text_parts).strip()

    output_text = data.get("output_text")
    if isinstance(output_text, str):
        return output_text.strip()

    return ""
