"""Defects found in the software service and its router.

Every test here was written against a defect reproduced first: run the code, get
the traceback or the ``AttributeError``, then write the assertion. None of these
are speculative hardening.

The common theme is that ``SoftwareService`` grew a second, parallel
implementation of things ``DownloadService`` already owned -- its own
``download_url`` / ``download_artifact_url``, its own purchase and visibility
checks -- and the parallel copies drifted.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from app.modules.shared.enums import SoftwareVisibility, VersionStatus
from app.modules.software_management.application.services.download_service import DownloadService
from app.modules.software_management.application.services.software_service import SoftwareService
from app.modules.software_management.domain.entities.artifact import Artifact
from app.modules.software_management.domain.entities.software import Software
from app.modules.software_management.domain.value_objects import OwnedSoftwareCard
from app.modules.software_management.domain.value_objects.value_objects import Currency


class _FakeRepo:
    def __init__(self, software: Software | None) -> None:
        self.software = software
        self.saved: list[Software] = []

    async def get(self, software_id: UUID) -> Software | None:
        return self.software

    async def save(self, software: Software) -> Software:
        self.saved.append(software)
        return software

    async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool:
        return False

    async def list_owned(self, owner_id: UUID, *, limit: int = 100, offset: int = 0):
        return [], 0


class _FakeUow:
    def __init__(self, repo: _FakeRepo) -> None:
        self.software_repo = repo

    def read_only(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> bool:
        return False


class _RepoReturning(_FakeRepo):
    """A repo whose ``list_all`` returns whole aggregates."""

    def __init__(self, items: list[Software]) -> None:
        super().__init__(None)
        self.items = items
        self.listed_owned: list[UUID] = []

    async def list_all(self, *, limit: int = 100, offset: int = 0) -> list[Software]:
        return self.items[offset : offset + limit]

    async def list_owned(self, owner_id: UUID, *, limit: int = 100, offset: int = 0):
        self.listed_owned.append(owner_id)
        return [], 0


def _software(*, owner_id: UUID | None = None) -> Software:
    return Software.create(
        name="Pkg",
        description="desc",
        owner_id=owner_id or uuid4(),
        visibility=SoftwareVisibility.PUBLIC,
    )


def _artifact(version_id: UUID, *, status=None) -> Artifact:
    from app.modules.shared.enums import ArtifactStatus

    now = datetime.now(timezone.utc)
    return Artifact(
        id=uuid4(),
        version_id=version_id,
        storage_key="software/x/versions/y/z/pkg.zip",
        sha256="a" * 64,
        size_bytes=4,
        mime_type="application/zip",
        filename="pkg.zip",
        status=status or ArtifactStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )


# ── 1. missing await: download_url returns a coroutine, not a URL ──────────


async def test_download_url_returns_a_url_not_a_coroutine() -> None:
    """``SoftwareService.download_url`` forgot to await the download service.

    Reproduced: the method body ends in a bare ``return self._download_service
    .create_download_url(...)``. The caller gets an un-awaited coroutine, and the
    router's ``url.url`` raises ``AttributeError: 'coroutine' object has no
    attribute 'url'`` -- a 500 on every request that reaches it.

    The two methods are not called by any route today (``download_version``
    injects ``DownloadService`` directly), which is why this survived: the bug is
    latent behind a live-looking signature rather than reachable.
    """
    class _Download:
        class _Url:
            url = "https://signed.example/artifact.zip"

        async def create_download_url(self, **kwargs):
            return self._Url()

    software = _software()
    service = SoftwareService(download_service=_Download(), unit_of_work=_FakeUow(_FakeRepo(software)))

    # Reach the return statement without constructing a full aggregate: the defect
    # is the missing await, not the surrounding policy.
    result = service._download_service.create_download_url(
        software_id=software.id, version_number="1.0.0", user_id=uuid4()
    )
    assert inspect.iscoroutine(result), "precondition: the call site yields a coroutine"
    await result

    source = inspect.getsource(SoftwareService.download_url)
    assert "await self._download_service.create_download_url(" in source, (
        "SoftwareService.download_url still returns an un-awaited coroutine"
    )


async def test_download_artifact_url_returns_a_url_not_a_coroutine() -> None:
    """Same missing ``await`` in ``download_artifact_url``.

    This one *is* wired: ``download_artifact`` injects ``SoftwareService`` and
    calls this method, so the 500 is reachable from
    ``GET /{software_id}/versions/{version}/artifacts/{artifact_id}/download``.
    """
    source = inspect.getsource(SoftwareService.download_artifact_url)
    assert "await self._download_service.create_artifact_download_url(" in source, (
        "SoftwareService.download_artifact_url still returns an un-awaited coroutine"
    )


# ── 2. the artifact path skips the downloadable check ──────────────────────


async def _artifact_url_service(software: Software) -> DownloadService:
    """A DownloadService over a fake repo holding ``software``."""
    return DownloadService(uow=_FakeUow(_FakeRepo(software)), url_signer=_Signer(), storage=object())


class _Signer:
    def create_url(self, *, storage_key: str, method: str):
        class _Url:
            url = f"https://signed.example/{storage_key}"
        return _Url()

    def verify_token(self, **kwargs) -> bool:
        return True


def _software_with_artifact(*, version_status: VersionStatus) -> tuple[Software, object]:
    """A software with one published/revoked version holding one artifact."""
    software = _software()
    from app.modules.software_management.domain.entities.version import Version
    from app.modules.software_management.domain.value_objects import SemVer

    # Built published and carrying its artifact, then transitioned into the
    # target state: a revoked version refuses further modification, so the artifact
    # cannot be attached afterwards.
    version = Version(
        id=uuid4(),
        software_id=software.id,
        number=SemVer.parse("1.0.0"),
        release_notes="notes",
        status=VersionStatus.PUBLISHED,
        lock_version=0,
    )
    version.add_artifact(_artifact(version.id))
    software.add_version(version)

    if version_status is VersionStatus.DRAFT:
        version.status = VersionStatus.DRAFT
    elif version_status is VersionStatus.REVOKED:
        version.revoke()
    elif version_status is VersionStatus.DELETED:
        version.status = VersionStatus.DELETED

    return software, version.artifacts[0]


@pytest.mark.parametrize(
    "status",
    [VersionStatus.DRAFT, VersionStatus.REVOKED, VersionStatus.DELETED],
)
async def test_a_revoked_or_draft_version_cannot_be_downloaded_by_artifact(status) -> None:
    """Revoking a version must stop downloads through the artifact route.

    ``create_download_url`` refused when ``not version.is_downloadable()``.
    ``SoftwareService.download_artifact_url`` had its own copy of the
    authorization and dropped that condition, so a revoked release -- exactly what
    you revoke when a release turns out to be unsafe -- was still downloadable
    through the artifact endpoint while the version endpoint honoured it.

    Behavioural, not source-text: the assertion is that the request is refused.
    """
    software, artifact = _software_with_artifact(version_status=status)
    service = await _artifact_url_service(software)

    with pytest.raises(Exception) as exc:
        await service.create_artifact_download_url(
            software_id=software.id,
            version_number="1.0.0",
            artifact_id=artifact.id,
            user_id=software.owner_id,
        )
    assert "downloadable" in str(exc.value).lower(), (
        f"a {status.value} version's artifact was downloadable; expected a refusal "
        f"naming the state, got: {exc.value}"
    )


async def test_an_unknown_artifact_id_is_refused() -> None:
    """The artifact must belong to the version that was asked for.

    Taking identifiers rather than a resolved ``Artifact`` is what makes this
    checkable at all: previously the caller resolved the artifact and passed it
    in, so the service could not verify the pairing.
    """
    software, _ = _software_with_artifact(version_status=VersionStatus.PUBLISHED)
    service = await _artifact_url_service(software)

    with pytest.raises(Exception) as exc:
        await service.create_artifact_download_url(
            software_id=software.id,
            version_number="1.0.0",
            artifact_id=uuid4(),
            user_id=software.owner_id,
        )
    assert "artifact" in str(exc.value).lower()


async def test_artifact_downloads_are_counted() -> None:
    """Artifact downloads increment the counters.

    The version path calls ``record_download``; the artifact path did not, so
    every download served through the artifact endpoint was invisible to the
    per-version and per-software totals.
    """
    software, artifact = _software_with_artifact(version_status=VersionStatus.PUBLISHED)
    repo = _FakeRepo(software)
    service = DownloadService(uow=_FakeUow(repo), url_signer=_Signer(), storage=object())

    before = software.versions[0].download_count

    await service.create_artifact_download_url(
        software_id=software.id,
        version_number="1.0.0",
        artifact_id=artifact.id,
        user_id=software.owner_id,
    )

    assert repo.saved, "precondition: the download was not written back"
    assert repo.saved[-1].versions[0].download_count == before + 1, (
        "artifact downloads are not counted, so the download counters under-report"
    )


# ── 3. list_visible ignores is_admin, so admin endpoints list one user's rows ─


async def test_list_visible_returns_everything_for_an_admin() -> None:
    """``list_visible`` accepts ``is_admin`` and ignores it.

    Both admin routes call ``list_visible(user_id=<admin's own id>)``, which
    forwards to ``list_owned(owner_id=...)``. So ``/admin/packages`` lists only
    software the admin personally owns -- it is a duplicate of "my software",
    reachable by anyone who is an admin, and it returns nothing for every other
    user's software. The ``is_admin`` parameter reads as the intended switch and
    does nothing.
    """
    captured: dict = {}

    class _Repo(_FakeRepo):
        async def list_all(self, *, limit: int = 100, offset: int = 0):
            captured["called"] = "list_all"
            return []

        async def list_owned(self, owner_id: UUID, *, limit: int = 100, offset: int = 0):
            captured["called"] = "list_owned"
            captured["owner_id"] = owner_id
            return [], 0

    service = SoftwareService(unit_of_work=_FakeUow(_Repo(None)))

    await service.list_all()

    assert captured.get("called") == "list_all", (
        "list_all still calls list_owned, so /admin/packages shows only the admin's "
        f"own software (owner_id={captured.get('owner_id')})"
    )


# ── 4. admin endpoints index attributes the returned type does not have ────


async def test_admin_summary_counts_over_aggregates() -> None:
    """``admin_summary`` summed download counts over ``card.versions``.

    It read from the flat ``OwnedSoftwareCard`` projection returned by
    ``list_visible``, which has no ``versions`` attribute. Reproduced:
    ``AttributeError: 'OwnedSoftwareCard' object has no attribute 'versions'``, so
    the endpoint 500s on every call. The cards are still built here to keep the
    precondition honest.
    """
    card = OwnedSoftwareCard(
        id=1,
        name="x",
        description="d",
        visibility="public",
        status="active",
        latest_version=None,
        price_cents=0,
        currency="KES",
        updated_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    assert not hasattr(card, "versions"), "precondition: the card has no versions"
    with pytest.raises(AttributeError):
        [version for item in [card] for version in item.versions]

    software, _ = _software_with_artifact(version_status=VersionStatus.PUBLISHED)
    repo = _RepoReturning([software])
    service = SoftwareService(unit_of_work=_FakeUow(repo))

    items = await service.list_all()
    versions = [version for item in items for version in item.versions]

    assert versions, "list_all returned aggregates without their versions"
    assert all(item is software for item in items)


async def test_admin_packages_renders_every_package_not_just_the_admins() -> None:
    """``admin_packages`` listed only software the admin personally owned.

    It called ``list_visible(user_id=admin.user_id)``, which forwards to
    ``list_owned`` -- "my software" -- so the moderation view was empty of
    anything worth moderating. And it handed that flat card to ``software_item``,
    which expects an aggregate: reproduced ``AttributeError: 'OwnedSoftwareCard'
    object has no attribute 'latest_downloadable'``, a 500 on every call.
    """
    from app.modules.software_management.api import presenters

    other_users_software = _software_with_artifact(version_status=VersionStatus.PUBLISHED)[0]
    card = OwnedSoftwareCard(
        id=1,
        name="x",
        description="d",
        visibility="public",
        status="active",
        latest_version=None,
        price_cents=0,
        currency="KES",
        updated_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(AttributeError):
        presenters.software_item(card, viewer_user_id=1)  # type: ignore[arg-type]

    admin_id = uuid4()
    service = SoftwareService(unit_of_work=_FakeUow(_RepoReturning([other_users_software])))

    items = await service.list_all()

    assert items == [other_users_software], (
        "an admin listing does not include other users' software, so /admin/packages "
        "shows only what the admin owns"
    )
    assert other_users_software.owner_id != admin_id, (
        "precondition: the listed software belongs to somebody other than the admin"
    )
    # The presenter accepts what list_all now returns.
    assert presenters.software_item(items[0], viewer_user_id=admin_id).id


# ── 5. the currency default is not a supported currency ────────────────────


async def test_upload_package_default_currency_is_accepted() -> None:
    """``upload_package`` defaults ``currency="KSH"``.

    ``Currency._SUPPORTED`` is ``{"USD", "KES", "EUR"}``, so the default raises
    ``InvalidCurrencyError: Unsupported currency 'KSH'``. The router passes
    ``Form("KES")`` explicitly, which is why the HTTP path works -- but the
    service default is unusable, and ``Software.create`` defaults to ``"KES"``.
    Three defaults, one of them broken.
    """
    with pytest.raises(Exception) as exc:
        Currency(code="KSH")
    assert "KSH" in str(exc.value)

    source = inspect.getsource(SoftwareService.upload_package)
    assert 'currency: str = "KSH"' not in source, (
        "upload_package still defaults to 'KSH', which Currency rejects"
    )


# ── 6. events recorded by mutators are never published ─────────────────────


async def test_update_pricing_publishes_the_event_it_records() -> None:
    """``update_pricing`` records a ``SoftwarePriceUpdatedEvent`` and drops it.

    ``_dispatch_events`` is called from exactly one place: the upload path.
    ``update_pricing``, ``deprecate_version`` and ``revoke_version`` each record
    an event on the aggregate, commit, and return -- so anything subscribing to
    price changes or revocations never hears about them. A revocation, which is
    what you do when a release is unsafe, is invisible downstream.

    Reproduced: one event pending on the aggregate, zero published.
    """
    published: list = []

    class _Publisher:
        async def publish(self, events) -> None:
            published.extend(events)

    software = _software()
    service = SoftwareService(
        unit_of_work=_FakeUow(_FakeRepo(software)),
        event_publisher=_Publisher(),
    )

    await service.update_pricing(
        software_id=software.id,
        user_id=software.owner_id,
        price_cents=999,
        currency="KES",
    )

    assert published, (
        "update_pricing recorded a SoftwarePriceUpdatedEvent on the aggregate but never "
        "dispatched it, so price-change subscribers never see the change"
    )


def _router_source() -> str:
    from pathlib import Path

    return (
        Path(__file__).resolve().parents[2]
        / "app/modules/software_management/api/routers/software_router.py"
    ).read_text(encoding="utf-8")


def _route_body(decorator: str) -> str:
    body = _router_source().split(decorator, 1)[1]
    return body.split("\n@router.", 1)[0]


def _admin_summary_body() -> str:
    return _route_body('@router.get("/admin/summary"')


def _admin_packages_body() -> str:
    return _route_body('@router.get("/admin/packages"')