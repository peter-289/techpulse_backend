"""The download, end to end: authorize, sign, redirect, verify, stream.

This is the test for the reported bug. A client asked
``GET .../artifacts/{artifact_id}/download``, got a 307, followed it, and got a
404 -- because the URL the 307 pointed at was built from a different description
of the serving route than the one the router declares. Each half of that failed
on its own without anything noticing:

* nothing compared a generated URL against the routing table;
* nothing followed a redirect and checked it arrived.

So this file follows redirects for real. It runs the actual routers, the actual
``SoftwareService`` and ``DownloadService``, the actual ``HmacDownloadUrlSigner``
and the actual ``LocalStorage``, wired together through the real dependency
providers. Only three things are substituted: the session (minting a real token
is not the point), Redis (the abuse guard is not the point), and the database
(the aggregate is built directly).

The storage root is a ``tmp_path``, not ``/app/storage``: where artifacts live is
the deployment's choice, and a test that depended on it would only pass on the
machine it was written on.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app.infrastructure.storage.local_storage import (
    DownloadUrlSignerSettings,
    HmacDownloadUrlSigner,
    LocalStorage,
    StorageSettings,
)
from app.main import app
from app.modules.security.abuse_protection import AbuseProtection
from app.modules.security.dependencies import get_abuse_protection, get_current_user
from app.modules.shared.dependencies import get_unit_of_work
from app.modules.software_management.dependencies import get_signer, get_storage
from app.modules.software_management.domain.ports.download_signer import (
    SIGNED_DOWNLOAD_ROUTE,
)
from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.entities.version import Version
from app.modules.software_management.domain.value_objects import SemVer
from app.modules.shared.enums import (
    ArtifactStatus,
    SoftwareVisibility,
    VersionStatus,
)

SIGNING_SECRET = "integration-test-signing-secret"

# A small artifact for everything that only cares about correctness. The bytes
# still contain no newline after the header: the artifact is
# ``b"%PDF-1.7\n" + bytes(range(256))``, which repeats 0x0a every 256 bytes, so
# line-based iteration would still shred it -- just into 1 KB pieces instead of
# 10 MB ones.
SMALL_BODY = b"%PDF-1.7\n" + bytes(range(256)) * 4

# Several times the router's chunk size, for the two tests that assert on how the
# body is chunked. Only they pay for it: ``/tmp`` is a small tmpfs on many
# machines, and a 10 MB artifact written by all twenty-odd tests here was enough
# to fill it and take unrelated tests down with it.
LARGE_BODY = b"%PDF-1.7\n" + bytes(range(256)) * 40_000


# ── the published software under test ────────────────────────────────────────


@dataclass(frozen=True)
class _Fixture:
    software: Software
    version: Version
    artifact: Artifact
    storage_key: str
    body: bytes
    path: str


def _build(tmp_path: Path, *, body: bytes) -> _Fixture:
    """A public, published software with one artifact, and that artifact on disk.

    The repository is faked; the aggregate, its invariants and the key layout are
    the real ones. The storage key is built the way the upload path builds it,
    and it is the *same* string the artifact and the file on disk both use --
    three separately-generated ids drifting apart here would produce a test that
    passes for the wrong reason.

    ``body`` is a parameter so only the tests that assert on chunking pay for a
    large artifact.
    """
    # Software.create() mints its own id, so the aggregate comes first and the key
    # is built from the ids it ended up with.
    software = Software.create(
        name="Polymorphism",
        description="A sample package",
        owner_id=uuid4(),
        visibility=SoftwareVisibility.PUBLIC,
    )
    version_id, artifact_id = uuid4(), uuid4()
    storage_key = (
        f"software/{software.id}/versions/{version_id}/{artifact_id}/Polymorphism.pdf"
    )
    now = datetime.now(timezone.utc)

    artifact = Artifact(
        id=artifact_id,
        version_id=version_id,
        storage_key=storage_key,
        sha256=hashlib.sha256(body).hexdigest(),
        size_bytes=len(body),
        mime_type="application/pdf",
        filename="Polymorphism.pdf",
        status=ArtifactStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    version = Version(
        id=version_id,
        software_id=software.id,
        number=SemVer.parse("1.0.0"),
        release_notes="first",
        status=VersionStatus.PUBLISHED,
        lock_version=0,
    )
    version.add_artifact(artifact)
    software.add_version(version)

    path = tmp_path / "storage" / storage_key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)

    return _Fixture(
        software=software,
        version=version,
        artifact=artifact,
        storage_key=storage_key,
        body=body,
        path=(
            f"/api/v1/software-management/{software.id}"
            f"/versions/1.0.0/artifacts/{artifact_id}/download"
        ),
    )


# ── the fake session and the fake database ───────────────────────────────────


class _NoopAbuseProtection(AbuseProtection):
    """Redis is not the point of any test in this file."""

    def get_client_ip(self, *, request) -> str:  # type: ignore[override]
        return "203.0.113.7"

    async def guard_download(self, *, ip: str) -> None:  # type: ignore[override]
        return None


class _SoftwareRepo:
    def __init__(self, software: Software) -> None:
        self.software = software
        self.saves = 0

    async def get(self, software_id: UUID) -> Software | None:
        return self.software if self.software.id == software_id else None

    async def save(self, software: Software) -> Software:
        self.saves += 1
        return software

    async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool:
        return False


class _Uow:
    """Just enough transaction boundary for the download path."""

    def __init__(self, software: Software) -> None:
        self.software_repo = _SoftwareRepo(software)

    def read_only(self) -> "_Uow":
        return self

    async def __aenter__(self) -> "_Uow":
        return self

    async def __aexit__(self, *exc_info) -> bool:
        return False


@pytest.fixture
def body() -> bytes:
    """The artifact's bytes.

    A fixture rather than a constant so ``TestStreaming`` can shadow it with a
    large one. The client is built from the same ``fixture``, and the fake
    repository only recognises the ids in that aggregate -- so a second, larger
    fixture would 404 rather than serve, which is a confusing way to learn that
    the two have to be the same object.
    """
    return SMALL_BODY


@pytest.fixture
def fixture(tmp_path: Path, body: bytes) -> _Fixture:
    return _build(tmp_path, body=body)


@pytest.fixture
def signer() -> HmacDownloadUrlSigner:
    return HmacDownloadUrlSigner(
        settings=DownloadUrlSignerSettings(
            backend_url="http://testserver",
            signing_secret=SIGNING_SECRET,
            default_expiry_seconds=900,
        )
    )


@pytest.fixture
def overrides(fixture: _Fixture, tmp_path: Path, signer: HmacDownloadUrlSigner) -> dict:
    """Swap the three things this flow does not exercise: the session, Redis and
    the database.

    The leaf providers are overridden rather than ``get_download_service`` /
    ``get_software_service``, so the real providers still run and construct the
    services and a change to their wiring fails here instead of passing.
    """
    storage = LocalStorage(
        settings=StorageSettings(
            backend_url="http://testserver",
            storage_root=str(tmp_path / "storage"),
            signing_secret=SIGNING_SECRET,
        )
    )

    class _CurrentUser:
        user_id = fixture.software.owner_id

    return {
        get_unit_of_work: lambda: _Uow(fixture.software),
        get_storage: lambda: storage,
        get_signer: lambda: signer,
        # A zero-argument factory, not the class: FastAPI treats a class override
        # as a dependency callable and introspects the inherited
        # ``__init__(redis_client: Optional[Redis])``, which it then tries to turn
        # into a required query parameter out of an unresolvable forward reference.
        get_abuse_protection: lambda: _NoopAbuseProtection(redis_client=None),
        get_current_user: _CurrentUser,
    }


@pytest.fixture
def client(overrides: dict):
    app.dependency_overrides.update(overrides)
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def counting_client(overrides: dict):
    """The same client, wrapped so the server's own chunking is visible."""
    app.dependency_overrides.update(overrides)
    counter = _CountingBodyMessages(app)
    try:
        yield TestClient(counter), counter
    finally:
        app.dependency_overrides.clear()


def _signed_for(fixture: _Fixture, signer: HmacDownloadUrlSigner) -> str:
    """The serving URL for this artifact, as an authorized request would get it."""
    return signer.create_url(storage_key=fixture.storage_key, method="GET").url


# ── the flow ─────────────────────────────────────────────────────────────────


class TestTheWholeFlow:
    def test_an_authorized_request_is_redirected_and_the_redirect_lands(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        """The reported failure, as an assertion.

        ``follow_redirects`` is what makes this the regression test it is: the
        307 was always valid, the destination was a 404. A test that stopped at
        the redirect would have passed against the broken code.
        """
        response = client.get(fixture.path, follow_redirects=True)

        assert response.status_code == 200, response.text
        assert response.content == fixture.body
        disposition = response.headers["content-disposition"]
        assert disposition.startswith("attachment;")
        assert "Polymorphism.pdf" in disposition

    def test_the_redirect_is_a_307_to_a_route_the_application_serves(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        response = client.get(fixture.path, follow_redirects=False)

        assert response.status_code == 307, response.text
        location = response.headers["location"]
        assert location.startswith(f"http://testserver{SIGNED_DOWNLOAD_ROUTE}/")
        assert "//software" not in location, "the redirect target has a doubled separator"
        assert "%2F" not in location, "the key's separators were escaped, so it cannot route"

    def test_the_redirect_target_is_a_registered_route(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        """The generated URL, dispatched against the routing table itself.

        Comparing against ``SIGNED_DOWNLOAD_ROUTE`` would only restate the
        constant; what has to agree is the URL and the route FastAPI dispatches.
        """
        location = client.get(fixture.path, follow_redirects=False).headers["location"]

        registered = [
            route.path
            for route in app.routes
            if "storage/download" in getattr(route, "path", "")
        ]
        assert len(registered) == 1, f"expected exactly one serving route, got {registered}"

        # The query is dropped on purpose: the endpoint requires expires and
        # token, so a path that *reaches* the endpoint answers 422. A 404 here is
        # the original bug -- a signed URL pointing at nothing.
        served = client.get(urlsplit(location).path)
        assert served.status_code == 422, served.text
        assert served.json()["detail"][0]["loc"] == ["query", "expires"]

    def test_the_signed_link_alone_authorizes_the_second_request(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner
    ) -> None:
        """The serving endpoint has no session dependency on purpose: the
        signature is the credential. It must therefore work with nothing but the
        URL, and be useless without it."""
        served = client.get(_signed_for(fixture, signer))

        assert served.status_code == 200, served.text
        assert served.content == fixture.body

    def test_the_download_is_counted_once_the_request_is_authorized(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        assert fixture.software.download_count == 0

        client.get(fixture.path, follow_redirects=True)

        assert fixture.software.download_count == 1

    def test_a_refused_download_is_not_counted(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        """Counting has to follow authorization, not precede it. An artifact id
        that is not in the aggregate is refused before any URL is signed."""
        missing = uuid4()
        path = (
            f"/api/v1/software-management/{fixture.software.id}"
            f"/versions/1.0.0/artifacts/{missing}/download"
        )

        response = client.get(path, follow_redirects=False)

        assert response.status_code == 404, response.text
        assert fixture.software.download_count == 0


# ── the serving endpoint refuses ─────────────────────────────────────────────


class TestTheServingEndpointRefuses:
    def _params(self, url: str) -> dict[str, str]:
        return parse_qs(urlsplit(url).query)

    def test_a_forged_token_is_refused(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner
    ) -> None:
        params = self._params(_signed_for(fixture, signer))

        response = client.get(
            f"{SIGNED_DOWNLOAD_ROUTE}/{fixture.storage_key}",
            params={**params, "token": "0" * 64},
        )
        assert response.status_code == 403

    def test_a_token_signed_with_another_secret_is_refused(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        attacker = HmacDownloadUrlSigner(
            settings=DownloadUrlSignerSettings(
                backend_url="http://testserver",
                signing_secret="a-different-secret",
                default_expiry_seconds=900,
            )
        )
        params = self._params(attacker.create_url(storage_key=fixture.storage_key, method="GET").url)

        response = client.get(
            f"{SIGNED_DOWNLOAD_ROUTE}/{fixture.storage_key}", params=params
        )
        assert response.status_code == 403

    def test_a_token_for_another_artifact_is_refused(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner
    ) -> None:
        """The reason the key is inside the signature. Without that, any valid
        token would fetch any file in the volume: the serving endpoint is
        unauthenticated, so the token is the only thing scoping it."""
        params = self._params(_signed_for(fixture, signer))
        target = "software/someone-elses/versions/x/y/invoice.pdf"

        response = client.get(f"{SIGNED_DOWNLOAD_ROUTE}/{target}", params=params)
        assert response.status_code == 403

    def test_a_link_that_was_valid_and_has_now_lapsed_is_gone(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner
    ) -> None:
        """A real lapsed link: 410, so the client knows to ask for a new one.

        The token is authentic -- minted through the signer's own payload
        construction, the same two calls ``create_url`` makes -- because the
        distinction this endpoint draws is between "expired" and "forged", and a
        tampered token would be the latter.
        """
        lapsed = int(time.time()) - 1
        token = signer._sign_payload(
            signer._build_payload(method="GET", storage_key=fixture.storage_key, expires_at=lapsed)
        )

        response = client.get(
            f"{SIGNED_DOWNLOAD_ROUTE}/{fixture.storage_key}",
            params={"expires": lapsed, "token": token},
        )
        assert response.status_code == 410, response.text

    def test_a_token_with_its_expiry_extended_is_refused(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner
    ) -> None:
        """The obvious attack: keep the signature, push the expiry out. The
        expiry is inside the signed payload, so lengthening it invalidates the
        token rather than granting more time."""
        params = self._params(_signed_for(fixture, signer))

        response = client.get(
            f"{SIGNED_DOWNLOAD_ROUTE}/{fixture.storage_key}",
            params={**params, "expires": int(params["expires"][0]) + 86_400},
        )
        assert response.status_code == 403

    def test_a_missing_token_is_rejected_before_anything_is_opened(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner
    ) -> None:
        params = self._params(_signed_for(fixture, signer))
        del params["token"]

        response = client.get(
            f"{SIGNED_DOWNLOAD_ROUTE}/{fixture.storage_key}", params=params
        )
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "tail",
        [
            "software/../../escape.pdf",
            "../../../../etc/passwd",
        ],
    )
    def test_a_literal_traversal_never_reaches_the_endpoint(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner, tail: str
    ) -> None:
        """Unencoded ``..`` is collapsed during URL normalization, before routing.

        Worth pinning separately from the encoded spelling below, because the two
        are stopped by different things and it matters which: this one is refused
        by the HTTP layer, so the endpoint is never entered and no token is even
        looked at. Asserting only "not 200" would hide that.
        """
        params = self._params(_signed_for(fixture, signer))

        response = client.get(f"{SIGNED_DOWNLOAD_ROUTE}/{tail}", params=params)

        assert response.status_code == 404, response.text
        assert b"root:" not in response.content

    def test_an_encoded_traversal_is_refused_by_the_signer(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner
    ) -> None:
        """Percent-encoded separators survive URL normalization, so this one *does*
        reach the endpoint -- with the serving endpoint's path parameter
        attacker-controlled on every request, since it takes no session.

        It is refused because a token is bound to one key and this key is not that
        one, so the answer is 403 for a token that does not match rather than 404
        for a file that is not there.
        """
        params = self._params(_signed_for(fixture, signer))
        encoded = "..%2f..%2f..%2fetc%2fpasswd"

        response = client.get(f"{SIGNED_DOWNLOAD_ROUTE}/{encoded}", params=params)

        assert response.status_code == 403, response.text
        assert b"root:" not in response.content

    def test_a_key_that_resolves_outside_the_storage_root_is_refused(
        self, client: TestClient, fixture: _Fixture, signer: HmacDownloadUrlSigner, tmp_path: Path
    ) -> None:
        """A key that looks entirely well formed, carries a valid signature, and
        still points outside the volume.

        This is the case the string-level checks cannot catch: the key contains no
        ``..`` and no absolute prefix, so the signer accepts it and the token is
        authentic. What makes it an escape is filesystem state -- a symlink -- which
        only the adapter can see. It is refused as its own error, separate from a
        forged token, because nothing the client did was wrong and an operator
        needs to see that these are different events.
        """
        outside = tmp_path / "outside-root"
        outside.mkdir()
        (outside / "secret.txt").write_bytes(b"not yours")
        key = "software/innocent/versions/1.0.0/abc/link.txt"
        link = tmp_path / "storage" / key
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside / "secret.txt")

        lapsed = int(time.time()) + 900
        token = signer._sign_payload(
            signer._build_payload(method="GET", storage_key=key, expires_at=lapsed)
        )

        response = client.get(
            f"{SIGNED_DOWNLOAD_ROUTE}/{key}", params={"expires": lapsed, "token": token}
        )

        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "Storage key is not addressable."
        assert b"not yours" not in response.content

    def test_a_signed_but_absent_artifact_is_a_404(
        self, client: TestClient, signer: HmacDownloadUrlSigner
    ) -> None:
        """Valid signature, nothing behind it. A missing artifact is a 404, not a
        500 -- and not a 403, which would wrongly tell the caller the link was
        bad rather than the file gone."""
        absent = "software/nobody/versions/nothing/x/y.pdf"
        params = parse_qs(
            urlsplit(signer.create_url(storage_key=absent, method="GET").url).query
        )

        response = client.get(f"{SIGNED_DOWNLOAD_ROUTE}/{absent}", params=params)
        assert response.status_code == 404, response.text


# ── streaming ────────────────────────────────────────────────────────────────


class _CountingBodyMessages:
    """Counts the ``http.response.body`` messages the server actually sends.

    httpx's ASGI transport coalesces the response before handing it back, so a
    client cannot see how the body was chunked. Wrapping the ASGI callable one
    level lower can: this sees every message the server emits. That is what makes
    the streaming property observable from outside the router.
    """

    def __init__(self, application) -> None:
        self._application = application
        self.counts: list[tuple[str, int]] = []

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._application(scope, receive, send)
            return

        sent = 0

        async def _counting_send(message) -> None:
            nonlocal sent
            if message["type"] == "http.response.body":
                sent += 1
            await send(message)

        await self._application(scope, receive, _counting_send)
        self.counts.append((scope.get("path", "?"), sent))


class TestStreaming:
    @pytest.fixture
    def body(self) -> bytes:
        """Only this class needs an artifact big enough to span several chunks."""
        return LARGE_BODY

    def test_the_whole_artifact_arrives_unmodified(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        """Round-trip correctness for a large artifact, across the redirect."""
        assert len(fixture.body) > 8 * 1024 * 1024

        with client.stream("GET", fixture.path, follow_redirects=True) as response:
            assert response.status_code == 200
            received = b"".join(response.iter_bytes())

        assert received == fixture.body

    def test_the_body_is_sent_in_few_large_pieces_not_one_per_line(
        self,
        counting_client: tuple[TestClient, _CountingBodyMessages],
        fixture: _Fixture,
    ) -> None:
        """The streaming property, observed where it actually happens.

        Given the raw file handle, ``StreamingResponse`` iterates it -- and
        iterating a binary file yields *lines*. This fixture's body is 10 MB with a
        newline every 256 bytes, so that path emits roughly 400,000 body messages
        of about ten bytes each, each one a trip through the ASGI stack. The fixed
        size read loop emits one message per megabyte.

        The bound is deliberately loose. It is not asserting an exact chunk count
        -- that is ``tests/unit/test_artifact_streaming.py``'s job, where the
        boundaries are exact -- only that the server is not emitting hundreds of
        thousands of tiny messages, which is what the regression looks like.
        """
        client, counter = counting_client
        assert len(fixture.body) > 8 * 1024 * 1024

        with client.stream("GET", fixture.path, follow_redirects=True) as response:
            assert response.status_code == 200
            received = b"".join(response.iter_bytes())

        assert received == fixture.body
        # Only the serving request streams; the 307 before it does not.
        streamed = [
            count for path, count in counter.counts if path.startswith(SIGNED_DOWNLOAD_ROUTE)
        ]
        assert len(streamed) == 1, f"expected one serving request, got {counter.counts}"
        assert streamed[0] < 64, (
            f"the server sent {streamed[0]} body messages for "
            f"{len(fixture.body)} bytes; it is chunking per line, not per block"
        )

    def test_the_response_is_not_cacheable(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        """The token lives in the query string, so a shared cache must never keep
        a copy of the response."""
        response = client.get(fixture.path, follow_redirects=True)

        assert "no-store" in response.headers["cache-control"]
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_the_handle_is_closed_when_the_client_gives_up(
        self, client: TestClient, fixture: _Fixture
    ) -> None:
        """A download abandoned mid-flight still has to release its descriptor,
        or a client that walks away repeatedly exhausts the process's."""
        from app.modules.software_management.application.services import download_service as module

        handles: list[object] = []
        real = module.DownloadService.read_file

        async def _tracking(self, *, storage_key: str):
            handle = await real(self, storage_key=storage_key)
            handles.append(handle)
            return handle

        module.DownloadService.read_file = _tracking
        try:
            with client.stream(
                "GET", fixture.path, follow_redirects=True
            ) as response:
                assert response.status_code == 200
                next(response.iter_bytes())
        finally:
            module.DownloadService.read_file = real

        assert handles, "no handle was opened; the assertion below would be vacuous"
        for handle in handles:
            assert handle.closed, "the file handle was left open after an abandoned download"
