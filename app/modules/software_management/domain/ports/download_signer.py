from typing import Protocol, runtime_checkable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SignedDownloadUrl:
    """Data shape for a signed download URL."""
    url: str
    expires_at: int
    token: str


@runtime_checkable
class DownloadSigner(Protocol):
    """Port responsible for generating and validating temporary download URLs.

    Implementations are responsible only for signing and verification.
    They never access storage or perform authorization.
    """

    def create_url(
        self,
        *,
        storage_key: str,
        method: str = "GET",
    ) -> SignedDownloadUrl:
        """Generate a signed URL.

        Args:
            storage_key:
                Storage object identifier.

            method:
                HTTP method the signature is bound to.

        Returns:
            Signed SignedDownloadUrl containing a URL that can later be verified.
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
            True if valid, otherwise False.
        """
        ...


