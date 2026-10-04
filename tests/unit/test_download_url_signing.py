"""The signed-download URL: what shape it is, and what the token authenticates.

Two defects lived here, and both were invisible until a client followed a
redirect and got a 404.

**The route was described twice.** The router declared
``/api/v1/software-management/storage/download/{storage_key:path}``; the signer
learned its own target from ``STORAGE_DOWNLOAD_PATH``, which defaults to ``""``.
Nothing connected the two, so the URL the client was redirected to
(``http://host//software/...``) was not a path any route could answer. The
``//`` was the visible symptom; the disagreement was the cause.

**The storage key was encoded as one opaque segment.** ``quote(storage_key,
safe="")`` turns ``software/a/b.pdf`` into ``software%2Fa%2Fb.pdf``, but the
route reads the key as a *hierarchy* — it is a ``{storage_key:path}`` tail — so
the encoded form is a different key from the one that was signed.

The tests below pin the generated shape against every spelling of
``download_path`` and ``backend_url``, and pin the signature against every way a
token can be tampered with. They are deliberately written against the settings
value rather than the process environment, so they keep their meaning whatever a
developer's ``.env`` says.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlsplit

import pytest

from app.infrastructure.storage.local_storage import (
    DownloadUrlSignerSettings,
    HmacDownloadUrlSigner,
)
from app.modules.software_management.domain.ports.download_signer import (
    SIGNED_DOWNLOAD_METHODS,
    SIGNED_DOWNLOAD_ROUTE,
    TokenRejectionReason,
)

SECRET = "signing-secret-for-tests"
KEY = "software/2f0cdb03-b4a2-410b-b10b-ecc856cfaa41/versions/64999d7d-a276-4050-8bcc-dbb729b3a5fb/7f26ed36-3bad-4ecc-a961-cbcd60ee080d/Polymorphism.pdf"


def _signer(**overrides) -> HmacDownloadUrlSigner:
    settings = DownloadUrlSignerSettings(
        backend_url=overrides.pop("backend_url", "http://localhost:8000"),
        signing_secret=overrides.pop("signing_secret", SECRET),
        default_expiry_seconds=overrides.pop("default_expiry_seconds", 900),
        download_path=overrides.pop("download_path", SIGNED_DOWNLOAD_ROUTE),
    )
    assert not overrides, f"unexpected setting(s): {sorted(overrides)}"
    return HmacDownloadUrlSigner(settings=settings)


def _path_of(url: str) -> str:
    """The URL's path, without scheme, host or query."""
    return urlsplit(url).path


def _authentic_token_at(signer: HmacDownloadUrlSigner, *, expires_at: int) -> str:
    """A genuinely valid signature over ``expires_at``, using the signer's own
    payload construction.

    Needed because ``create_url`` takes its lifetime from settings rather than an
    argument, so a token that has *already* lapsed cannot be minted through the
    public API. Going through ``_build_payload``/``_sign_payload`` is exactly what
    makes a token authentic -- the same two calls ``create_url`` makes -- so the
    result is a real signature, not a forgery.
    """
    payload = signer._build_payload(method="GET", storage_key=KEY, expires_at=expires_at)
    return signer._sign_payload(payload=payload)


# ── the generated URL ────────────────────────────────────────────────────────


class TestUrlShape:
    @pytest.mark.parametrize(
        "download_path",
        ["/", "", "/downloads", "downloads", "downloads/", "//downloads//"],
    )
    def test_no_accidental_double_slash_after_the_scheme(self, download_path: str) -> None:
        """The reported failure: ``http://localhost:8000//software/...``.

        Reproduced from the original builder, which interpolated
        ``f"{backend_url.rstrip('/')}/{download_path.strip('/')}/{key}"``. With an
        empty ``download_path`` the middle segment collapses to nothing but still
        contributes its separator, so the URL gains an empty path segment. Most
        servers and proxies normalise ``//`` away and some do not; either way the
        client is sent somewhere the application never declared.
        """
        url = _signer(download_path=download_path).create_url(storage_key=KEY).url

        authority, _, path_and_query = url.partition("://")[2].partition("/")
        path, _, _query = path_and_query.partition("?")
        assert "//" not in path, f"double slash in path for download_path={download_path!r}: {url}"
        assert authority == "localhost:8000"

    @pytest.mark.parametrize(
        ("download_path", "expected"),
        [
            ("/", f"/{KEY}"),
            ("", f"/{KEY}"),
            ("/downloads", f"/downloads/{KEY}"),
            ("downloads", f"/downloads/{KEY}"),
            ("downloads/", f"/downloads/{KEY}"),
        ],
    )
    def test_the_path_prefix_is_preserved(self, download_path: str, expected: str) -> None:
        url = _signer(download_path=download_path).create_url(storage_key=KEY).url
        assert _path_of(url) == expected

    @pytest.mark.parametrize("backend_url", ["http://localhost:8000", "http://localhost:8000/"])
    def test_a_trailing_slash_on_the_backend_url_is_harmless(self, backend_url: str) -> None:
        url = _signer(backend_url=backend_url, download_path="/downloads").create_url(storage_key=KEY).url
        assert url.startswith("http://localhost:8000/downloads/")
        assert "//" not in _path_of(url)

    def test_the_url_addresses_a_route_that_exists(self) -> None:
        """The regression this whole file exists for.

        A signed URL is only useful if something answers it. The default
        ``download_path`` and the router's declared path are two descriptions of
        one route; the router asserts they agree at import, and this asserts the
        generated URL lands inside the application's own routing table.
        """
        from app.main import app

        url = _signer().create_url(storage_key=KEY).url
        generated = _path_of(url)

        declared = [
            route.path
            for route in app.routes
            if "storage/download" in getattr(route, "path", "")
        ]
        assert declared, "no signed-artifact route is registered"
        template = declared[0]
        assert generated == template.replace("{storage_key:path}", KEY), (
            f"the generated URL {generated!r} does not match the declared route {template!r}"
        )

    def test_the_storage_key_keeps_its_hierarchy(self) -> None:
        """The key is a ``{storage_key:path}`` tail, so ``/`` must survive.

        Percent-encoding the whole key produced a single segment the route could
        not read as the key that was signed.
        """
        url = _signer().create_url(storage_key=KEY).url
        assert "%2F" not in url
        assert _path_of(url).endswith(KEY)

    def test_each_key_segment_is_still_escaped(self) -> None:
        """Not escaping at all is the other failure: it would let a filename
        containing ``#`` or ``?`` truncate the URL, or inject a query string."""
        url = _signer().create_url(storage_key="software/a b/c#d?e/f.pdf").url
        assert "%20" in url
        assert "%23" in url
        assert "%3F" in url
        # ...and the hierarchy is still navigable.
        assert _path_of(url).endswith("/f.pdf")
        assert parse_qs(urlsplit(url).query)["expires"]

    def test_the_query_carries_the_expiry_and_the_token(self) -> None:
        signed = _signer().create_url(storage_key=KEY)
        query = parse_qs(urlsplit(signed.url).query)

        assert query["expires"] == [str(signed.expires_at)]
        assert query["token"] == [signed.token]
        assert signed.expires_at > int(time.time())

    def test_a_missing_backend_url_is_refused_rather_than_mangled(self) -> None:
        with pytest.raises(ValueError):
            _signer(backend_url="   ").create_url(storage_key=KEY)

# ── the signature ────────────────────────────────────────────────────────────


class TestSignatureVerification:
    def test_a_freshly_issued_token_verifies(self) -> None:
        signed = _signer().create_url(storage_key=KEY, method="GET")

        result = _signer().verify_token(
            storage_key=KEY, expires=signed.expires_at, token=signed.token, method="GET"
        )
        assert result.valid
        assert result.reason is None

    def test_a_substituted_resource_is_refused(self) -> None:
        """A token must not be transferable to another artifact."""
        signed = _signer().create_url(storage_key=KEY)
        other = KEY.replace("Polymorphism.pdf", "SomeoneElsesSecrets.pdf")

        result = _signer().verify_token(
            storage_key=other, expires=signed.expires_at, token=signed.token, method="GET"
        )
        assert not result.valid
        assert result.reason is TokenRejectionReason.SIGNATURE_MISMATCH

    def test_a_modified_expiry_is_refused(self) -> None:
        """Extending the window by re-signing is not possible, but moving
        ``expires`` in the query is the obvious attack and must not work."""
        signed = _signer().create_url(storage_key=KEY)

        result = _signer().verify_token(
            storage_key=KEY, expires=signed.expires_at + 86_400, token=signed.token, method="GET"
        )
        assert not result.valid
        assert result.reason is TokenRejectionReason.SIGNATURE_MISMATCH

    def test_a_different_method_is_refused(self) -> None:
        signed = _signer().create_url(storage_key=KEY, method="GET")

        result = _signer().verify_token(
            storage_key=KEY, expires=signed.expires_at, token=signed.token, method="POST"
        )
        assert not result.valid
        assert result.reason is TokenRejectionReason.UNSUPPORTED_METHOD

    def test_an_expired_token_is_refused_as_expired(self) -> None:
        """Reported as *expired* rather than as a signature failure: the remedy is
        different, and the reason is now visible to the client as a 410.

        The token has to be a real one that has genuinely lapsed. The signature is
        verified first, so that "expired" continues to mean what it says -- and a
        caller who saw 403 could not tell a lapsed link from a forged one, which
        is the difference between asking again and giving up."""
        lapsed = int(time.time()) - 1
        signer = _signer()

        result = signer.verify_token(
            storage_key=KEY,
            expires=lapsed,
            token=_authentic_token_at(signer, expires_at=lapsed),
            method="GET",
        )
        assert not result.valid
        assert result.reason is TokenRejectionReason.EXPIRED

    def test_a_token_is_refused_the_moment_it_lapses(self) -> None:
        """The boundary is inclusive of "now": a token whose expiry is this second
        has no lifetime left."""
        signer = _signer()
        expires_at = int(time.time())

        result = signer.verify_token(
            storage_key=KEY,
            expires=expires_at,
            token=_authentic_token_at(signer, expires_at=expires_at),
            method="GET",
        )
        assert not result.valid
        assert result.reason is TokenRejectionReason.EXPIRED

    def test_a_forged_token_is_not_reported_as_expired(self) -> None:
        """Expiry is checked after the signature, so a token nobody signed cannot
        borrow the one answer that tells a client to ask again -- just by naming
        an expiry in the past."""
        result = _signer().verify_token(
            storage_key=KEY, expires=int(time.time()) - 1, token="0" * 64, method="GET"
        )
        assert not result.valid
        assert result.reason is TokenRejectionReason.SIGNATURE_MISMATCH

    @pytest.mark.parametrize(
        "token",
        ["", "   ", "not-a-token", "z" * 64, "A" * 64, "0" * 63, "0" * 65],
    )
    def test_a_malformed_token_is_refused(self, token: str) -> None:
        result = _signer().verify_token(
            storage_key=KEY, expires=int(time.time()) + 900, token=token, method="GET"
        )
        assert not result.valid
        assert result.reason in {TokenRejectionReason.MISSING, TokenRejectionReason.MALFORMED}

    def test_a_token_signed_with_another_secret_is_refused(self) -> None:
        signed = _signer().create_url(storage_key=KEY)

        result = _signer(signing_secret="a-different-secret").verify_token(
            storage_key=KEY, expires=signed.expires_at, token=signed.token, method="GET"
        )
        assert not result.valid
        assert result.reason is TokenRejectionReason.SIGNATURE_MISMATCH

    @pytest.mark.parametrize(
        "resource",
        [
            "../../etc/passwd",
            "/etc/passwd",
            "..",
            "software/../../escape.pdf",
            "",
            "   ",
        ],
    )
    def test_an_unaddressable_resource_is_refused(self, resource: str) -> None:
        """The signed endpoint is unauthenticated, so its path parameter is
        attacker-controlled on every request. Refusing it here — before the token
        is even consulted — is what keeps the traversal check in ``LocalStorage``
        from being the only thing standing between a request and a file outside
        the storage root."""
        result = _signer().verify_token(
            storage_key=resource, expires=int(time.time()) + 900, token="0" * 64, method="GET"
        )
        assert not result.valid
        assert result.reason in {
            TokenRejectionReason.INVALID_RESOURCE,
            TokenRejectionReason.MALFORMED,
        }

    def test_a_non_numeric_expiry_is_refused(self) -> None:
        signed = _signer().create_url(storage_key=KEY)

        result = _signer().verify_token(
            storage_key=KEY, expires="soon", token=signed.token, method="GET"
        )
        assert not result.valid
        assert result.reason is TokenRejectionReason.MALFORMED

    def test_something_that_cannot_be_a_url_route_is_refused(self) -> None:
        """The token can only ever be presented over a route the signer declared,
        so binding it to an arbitrary verb issues a credential that is guaranteed
        to fail."""
        with pytest.raises(ValueError):
            _signer().create_url(storage_key=KEY, method="DELETE")

    def test_only_get_may_be_bound(self) -> None:
        """The serving route declares only ``GET``.

        FastAPI's ``APIRoute`` does not derive ``HEAD`` from it the way a plain
        Starlette ``Route`` does, so admitting ``HEAD`` here would hand out URLs
        that answer 405 -- a credential that can never be presented."""
        assert SIGNED_DOWNLOAD_METHODS == {"GET"}

        assert _signer().create_url(storage_key=KEY, method="GET").token

    @pytest.mark.parametrize("method", ["HEAD", "POST", "PUT", "DELETE", "PATCH"])
    def test_a_method_the_route_cannot_serve_is_refused_at_signing_time(self, method: str) -> None:
        with pytest.raises(ValueError):
            _signer().create_url(storage_key=KEY, method=method)


# ── the URL is a credential ───────────────────────────────────────────────────


async def test_a_signed_url_is_never_written_to_the_log() -> None:
    """The URL is a bearer credential: anyone holding it can fetch the file
    until it expires, and it is a query string, so it also lands in access
    logs. ``DownloadService`` logs the identifiers of what it authorized and
    never the URL, the token or the key it just handled.

    ``caplog`` is not used: ``app.core`` installs its own file handlers and the
    records do not propagate to the root logger, so a capture there would see
    nothing and every assertion below would be vacuous. A handler is attached to
    the service's own logger instead.
    """
    import logging

    from app.modules.software_management.application.services.download_service import DownloadService
    from app.modules.shared.enums import VersionStatus
    from tests.unit.test_software_service_defects import _FakeRepo, _FakeUow, _software_with_artifact

    records: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    name = "app.modules.software_management.application.services.download_service"
    logger = logging.getLogger(name)
    handler = _Capture()
    previous_level, previous_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        software, artifact = _software_with_artifact(version_status=VersionStatus.PUBLISHED)
        service = DownloadService(
            uow=_FakeUow(_FakeRepo(software)),
            url_signer=_signer(),
            storage=object(),
        )
        signed = await service.create_artifact_download_url(
            software_id=software.id,
            version_number="1.0.0",
            artifact_id=artifact.id,
            user_id=software.owner_id,
        )
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate

    logged = "\n".join(records)
    assert records, "nothing was logged; these assertion would be vacuous"
    assert signed.token in signed.url
    assert signed.token not in logged, "the download token was written to the log"
    assert signed.url not in logged, "the signed URL was written to the log"
    assert artifact.storage_key not in logged, "the storage key was written to the log"
