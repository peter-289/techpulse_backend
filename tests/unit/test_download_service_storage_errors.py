"""How a storage failure becomes an HTTP answer.

``DownloadService.read_file`` is the boundary between the ``Storage`` port and the
domain, and it has to keep four failures apart rather than collapsing them into
one: they have different causes, different owners, and different remedies. If
this table loses a row, the endpoint starts answering the wrong status and nothing
downstream can tell which of the four happened.

The row that is easiest to lose is the security one. An unaddressable key and a
forged token are both 403, and both arrive at an endpoint with no session, so
there is a real pull toward folding them together -- which is exactly what the
code did. They are separate errors because in one case the client's link was fine
and in the other it was not, and because an operator reading the logs needs to
tell a probing request from a stale link.
"""

from __future__ import annotations

import io

import pytest

from app.exceptions.exceptions import ExternalServiceError
from app.modules.software_management.application.services.download_service import DownloadService
from app.modules.software_management.domain.exceptions import (
    ArtifactNotFoundError,
    ArtifactStorageUnreadableError,
    ExpiredDownloadTokenError,
    InvalidDownloadTokenError,
    UnsafeStorageKeyError,
)
from app.modules.software_management.domain.ports.download_signer import (
    SIGNED_DOWNLOAD_METHODS,
    TokenRejectionReason,
    TokenVerification,
)
from app.modules.software_management.domain.ports.storage import (
    StorageFileNotFoundError,
    StorageReadError,
    StorageSecurityError,
    StorageUnavailableError,
)

KEY = "software/123/versions/1.0.0/abcd/file.pdf"


class _Storage:
    """Raises whatever it was built with, standing in for one storage failure."""

    def __init__(self, error: Exception | None = None, *, payload: bytes = b"data") -> None:
        self._error = error
        self._payload = payload
        self.requested: list[str] = []

    def open(self, *, storage_key: str) -> io.BytesIO:
        self.requested.append(storage_key)
        if self._error is not None:
            raise self._error
        return io.BytesIO(self._payload)


class _Signer:
    def __init__(self, result: TokenVerification | None = None) -> None:
        self._result = result or TokenVerification(valid=True)

    def create_url(self, *, storage_key: str, method: str = "GET"):
        raise NotImplementedError

    def verify_token(self, **kwargs) -> TokenVerification:
        return self._result


def _service(storage: _Storage, signer: _Signer | None = None) -> DownloadService:
    return DownloadService(uow=object(), url_signer=signer or _Signer(), storage=storage)


class TestReadingTheArtifact:
    async def test_a_readable_artifact_hands_back_a_handle(self) -> None:
        storage = _Storage(payload=b"the bytes")

        handle = await _service(storage).read_file(storage_key=KEY)

        assert handle.read() == b"the bytes"
        assert storage.requested == [KEY]

    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            (StorageFileNotFoundError("gone"), ArtifactNotFoundError),
            (StorageSecurityError("escapes the root"), UnsafeStorageKeyError),
            (StorageUnavailableError("no volume"), ExternalServiceError),
            (StorageReadError("EIO"), ArtifactStorageUnreadableError),
        ],
    )
    async def test_each_storage_failure_keeps_its_own_error(
        self, error: Exception, expected: type[Exception]
    ) -> None:
        """Four different causes, four different answers.

        Asserting on the exact class rather than a status code: the status is the
        handler's business, and it is the mapping *here* that must not quietly
        merge two of these into one.
        """
        with pytest.raises(expected):
            await _service(_Storage(error)).read_file(storage_key=KEY)

    async def test_a_missing_artifact_and_an_unreadable_one_are_not_the_same_error(self) -> None:
        """The pair most likely to be merged by accident. 404 says ask again later;
        500 says the operator has a problem. Collapsing them would make a broken
        volume look like an empty one."""
        with pytest.raises(ArtifactNotFoundError):
            await _service(_Storage(StorageFileNotFoundError("gone"))).read_file(storage_key=KEY)

        with pytest.raises(ArtifactStorageUnreadableError):
            await _service(_Storage(StorageReadError("EIO"))).read_file(storage_key=KEY)

    async def test_an_unaddressable_key_is_not_reported_as_a_bad_token(self) -> None:
        """The distinction this file exists for.

        ``InvalidDownloadTokenError`` says the client's link is bad;
        ``UnsafeStorageKeyError`` says the link was fine and the key it names is
        not addressable. Both are 403, so only the class tells them apart -- and a
        client that had a perfectly good link should not be told to go and get a
        new one.
        """
        with pytest.raises(UnsafeStorageKeyError) as unsafe:
            await _service(_Storage(StorageSecurityError("escape"))).read_file(storage_key=KEY)

        assert not isinstance(unsafe.value, InvalidDownloadTokenError)
        assert str(unsafe.value) != "Invalid download token."

    async def test_the_adapters_message_never_reaches_the_caller(self) -> None:
        """An adapter message can name the resolved filesystem path. The domain
        error carries only its own text; the original stays in ``__cause__`` for
        the log."""
        leaky = "Failed to read /app/storage/software/123/versions/1.0.0/abcd/file.pdf"

        with pytest.raises(ArtifactStorageUnreadableError) as caught:
            await _service(_Storage(StorageReadError(leaky))).read_file(storage_key=KEY)

        assert "/app/storage" not in str(caught.value)
        assert leaky in str(caught.value.__cause__)

    async def test_the_adapter_is_not_consulted_after_a_failure(self) -> None:
        storage = _Storage(StorageFileNotFoundError("gone"))

        with pytest.raises(ArtifactNotFoundError):
            await _service(storage).read_file(storage_key=KEY)

        assert storage.requested == [KEY], "read_file was retried after failing"


class TestRefusingTheToken:
    async def test_a_valid_token_is_accepted(self) -> None:
        assert await _service(_Storage()).verify_token(
            storage_key=KEY, expires=1, token="0" * 64, method="GET"
        )

    async def test_an_expired_token_is_its_own_error(self) -> None:
        signer = _Signer(
            TokenVerification(valid=False, reason=TokenRejectionReason.EXPIRED)
        )

        with pytest.raises(ExpiredDownloadTokenError):
            await _service(_Storage(), signer).verify_token(
                storage_key=KEY, expires=1, token="0" * 64, method="GET"
            )

    @pytest.mark.parametrize(
        "reason",
        [
            TokenRejectionReason.MISSING,
            TokenRejectionReason.MALFORMED,
            TokenRejectionReason.SIGNATURE_MISMATCH,
            TokenRejectionReason.INVALID_RESOURCE,
            TokenRejectionReason.UNSUPPORTED_METHOD,
        ],
    )
    async def test_every_other_refusal_is_a_bad_token(
        self, reason: TokenRejectionReason
    ) -> None:
        """Including a key that is not addressable: the signer refuses it as a
        token bound to a different resource, which it is."""
        signer = _Signer(TokenVerification(valid=False, reason=reason))

        with pytest.raises(InvalidDownloadTokenError):
            await _service(_Storage(), signer).verify_token(
                storage_key=KEY, expires=1, token="0" * 64, method="GET"
            )

    async def test_the_signers_reason_reaches_the_caller(self) -> None:
        """Without this the service could just always raise one error and every
        test above would still pass."""
        signer = _Signer(
            TokenVerification(valid=False, reason=TokenRejectionReason.EXPIRED)
        )

        with pytest.raises(ExpiredDownloadTokenError) as expired:
            await _service(_Storage(), signer).verify_token(
                storage_key=KEY, expires=1, token="0" * 64, method="GET"
            )

        assert not isinstance(expired.value, InvalidDownloadTokenError)

    async def test_no_file_is_opened_when_the_token_is_refused(self) -> None:
        """Verification happens before storage, so a refused token must not be
        able to touch the volume at all."""
        storage = _Storage()
        signer = _Signer(
            TokenVerification(valid=False, reason=TokenRejectionReason.SIGNATURE_MISMATCH)
        )

        with pytest.raises(InvalidDownloadTokenError):
            await _service(storage, signer).verify_token(
                storage_key=KEY, expires=1, token="0" * 64, method="GET"
            )

        assert storage.requested == []

    async def test_the_verified_method_is_the_one_passed_to_the_signer(self) -> None:
        """Not hardcoded: the signature is checked against the request that was
        actually made."""
        seen: dict = {}

        class _Recording(_Signer):
            def verify_token(self, **kwargs) -> TokenVerification:
                seen.update(kwargs)
                return TokenVerification(valid=True)

        assert await _service(_Storage(), _Recording()).verify_token(
            storage_key=KEY, expires=99, token="a" * 64, method="GET"
        )
        assert seen["method"] == "GET"
        assert seen["expires"] == 99
        assert seen["storage_key"] == KEY

    async def test_the_methods_that_can_be_signed_are_the_ones_the_route_serves(self) -> None:
        """Guards the constant against drifting away from the router.

        FastAPI's ``APIRoute`` serves only the methods declared on the decorator,
        so admitting a verb here would mint credentials that answer 405.
        """
        from app.main import app

        serving = [
            route
            for route in app.routes
            if "storage/download" in getattr(route, "path", "")
        ]
        assert len(serving) == 1, f"expected one serving route, got {serving}"
        declared = set(serving[0].methods) - {"OPTIONS"}

        assert declared == set(SIGNED_DOWNLOAD_METHODS), (
            "SIGNED_DOWNLOAD_METHODS and the serving route disagree"
        )
