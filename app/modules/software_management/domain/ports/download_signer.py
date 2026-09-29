from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class SignedDownloadUrl:
    """Data shape for a signed download URL.

    Carries the token and its expiry alongside the URL so a caller that has
    already resolved the URL can still verify it without re-parsing.
    """

    url: str
    expires_at: int
    token: str


@runtime_checkable
class DownloadSigner(Protocol):
    """Port responsible for generating and validating temporary download URLs.

    Implementations are responsible only for signing and verification. They
    never access storage and never perform authorization: whether a caller may
    download a given key is decided before the signer is consulted.
    """

    def create_url(self, *, storage_key: str, method: str = "GET") -> SignedDownloadUrl:
        """Generate a signed URL bound to ``method``.

        Returns:
            A SignedDownloadUrl containing a URL that can later be verified.
        """
        ...

    def verify_token(
        self,
        *,
        storage_key: str,
        expires: int,
        token: str,
        method: str = "GET",
    ) -> bool:
        """Verify a previously generated token.

        Returns:
            True if valid, otherwise False. Must not raise on a bad token: an
            invalid token is an expected outcome, not an error.
        """
        ...


