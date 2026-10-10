"""Wiring for the user context.

Moved out of ``app/modules/shared/dependencies.py`` in Phase 7b. The support-chat
provider is the only one, and it is here because the endpoint, the model and the
key it needs are the user context's business: this is the only place that reads
the AI provider's settings. The service receives a :class:`SupportAI` and cannot
see the endpoint, the key or the model, and it supplies the system prompt itself,
because that is support policy rather than configuration.
"""

from __future__ import annotations

from app.core.config import settings
from app.infrastructure.external_apis.ai_support.http_support_ai import HttpSupportAI
from app.modules.user.domain.ports.support_ai import SupportAI, SupportAIConfig


def get_support_ai() -> SupportAI:
    return HttpSupportAI(
        SupportAIConfig(
            base_url=settings.AI_BASE_URL,
            api_key=settings.AI_API_KEY,
            model=settings.SUPPORT_CHAT_MODEL,
            timeout_seconds=settings.AI_TIMEOUT_SECONDS,
        )
    )
