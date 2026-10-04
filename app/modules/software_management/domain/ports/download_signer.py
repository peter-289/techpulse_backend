from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable


#: The path of the route that serves a signed artifact.
#:
#: It lives here rather than beside either of the two things that have to agree
#: about it. The signer has to build URLs for it and the router has to declare
#: it, so defining it in either one leaves the other importing across a layer it
#: should not: infrastructure from the API, or the API from infrastructure. As
#: part of the port it is read inward by both, which is the direction everything
#: else in this codebase already depends on.
#:
#: It was previously configurable as ``STORAGE_DOWNLOAD_PATH``, defaulting to
#: ``""``. Two independently-maintained spellings of one route is precisely the
#: defect this fixes: the default produced URLs of the shape
#: ``http://host//software/...``, which no route matched, and nothing failed until
#: a client followed a redirect.
SIGNED_DOWNLOAD_ROUTE = "/api/v1/software-management/storage/download"

#: The HTTP methods a signed artifact URL may be bound to.
#:
#: Only ``GET``: the serving route declares only ``GET``, so a signature bound to
#: any other verb could never be presented. ``HEAD`` is deliberately absent --
#: FastAPI's ``APIRoute`` does not derive it from ``GET`` the way a plain Starlette
#: ``Route`` does, so accepting it here would mean handing out URLs that answer
#: 405. Anything outside this set is refused at signing time rather than producing
#: a signature that can never be used.
SIGNED_DOWNLOAD_METHODS = frozenset({"GET"})


@dataclass(frozen=True, slots=True)
class SignedDownloadUrl:
    """Data shape for a signed download URL.

    Carries the token and its expiry alongside the URL so a caller that has
    already resolved the URL can still verify it without re-parsing.
    """

    url: str
    expires_at: int
    token: str


class TokenRejectionReason(str, Enum):
    """Why a presented token was not accepted.

    Distinct values so the boundary can tell a stale link (which the client can
    fix by asking for a new one) from a tampered one (which it cannot), instead
    of reporting both as the same opaque failure.
    """

    MISSING = "missing"
    MALFORMED = "malformed"
    INVALID_RESOURCE = "invalid_resource"
    UNSUPPORTED_METHOD = "unsupported_method"
    EXPIRED = "expired"
    SIGNATURE_MISMATCH = "signature_mismatch"


@dataclass(frozen=True, slots=True)
class TokenVerification:
    """Outcome of verifying a signed download token.

    ``valid`` alone is what the old contract returned, which collapsed a missing
    token, a malformed one, an expired one and a forged one into a single
    ``False``. ``reason`` is ``None`` exactly when ``valid`` is ``True``.
    """

    valid: bool
    reason: TokenRejectionReason | None = None


@runtime_checkable
class DownloadSigner(Protocol):
    """Port responsible for generating and validating temporary download URLs.

    Implementations are responsible only for signing and verification. They
    never access storage and never perform authorization: whether a caller may
    download a given key is decided before the signer is consulted.
    """

    def create_url(self, *, storage_key: str, method: str = "GET") -> SignedDownloadUrl:
        """Generate a signed URL bound to ``method``.

        The URL addresses the signed artifact-serving route -- not the storage
        root -- so a key is carried as the route's path tail rather than being
        treated as a filesystem location.

        Returns:
            A SignedDownloadUrl containing a URL that can later be verified.

        Raises:
            ValueError:
                If ``storage_key`` is malformed or ``method`` is not a method
                signed URLs may be bound to.
        """
        ...

    def verify_token(
        self,
        *,
        storage_key: str,
        expires: int,
        token: str,
        method: str = "GET",
    ) -> TokenVerification:
        """Verify a previously generated token.

        Returns:
            A ``TokenVerification``. Must not raise on a bad token: an invalid
            token is an expected outcome, not an error.
        """
        ...