# 0005. Stage uploads behind a port, and make domain events real

- **Status:** Accepted
- **Date:** 2026-09-29
- **Related:** 0001, 0003, 0004

## Context

Phase 3 brought `software_management` into line with `ARCHITECTURE.md`, the
document that had described it. Two of the gaps were not stylistic.

**Upload staging was in the use-case.** `SoftwareService.spool_file` was a
`staticmethod` that opened a `NamedTemporaryFile`, streamed the upload through
`hashlib`, and read `settings.PACKAGE_UPLOAD_MAX_SIZE_BYTES` from `app.core`.
Three violations at once: the application layer touched the filesystem, reached
into the ORM-adjacent config package, and decided policy from global state
instead of from its caller. The two upload routes called it and then called
`uploaded.temp_path.unlink(missing_ok=True)` themselves, so the API layer did
filesystem I/O too — and the cleanup only covered files the service had already
handed back.

**Domain events were fabricated and thrown away.** `_process_artifact` built a
`MalwareScanRequestedEvent`, a `MalwareScanSuccessEvent` and an
`ArtifactAddedToVersion`, and assigned each to `_`. `AggregateRoot.pull_events`
had no callers anywhere in the codebase. So the event system described in
`ARCHITECTURE.md` §11 existed only as three throwaway allocations per upload,
and `MalwareScanRequestedEvent` was constructed *after* the synchronous scan had
already finished — an event asserting a request that was already history.

Neither showed up in a test. That is the point: they were invisible, so nobody
had a reason to fix them.

## Decision

Move staging behind a port, and wire the event flow the architecture document
already describes.

- `domain/ports/artifact_stager.py` declares `ArtifactStager`, and holds
  `ArtifactUpload` and `UploadLimits` beside it. `LocalArtifactStager`
  (infrastructure) does the temp-file work.
- The upload limit arrives as a `UploadLimits` value object. `app/core/config.py`
  is read once, in `app/modules/shared/dependencies.py`, at the composition root.
- `Software.add_artifact_to_version()` attaches the artifact and records
  `ArtifactAddedToVersion` together. The service calls
  `SoftwareService._dispatch_events()` after the transaction commits, passing
  events to a `DomainEventPublisher`.
- `LoggingDomainEventPublisher` is the adapter. It logs. Nothing consumes the
  events yet, so no notification behaviour changed.
- The two `MalwareScan*` events are deleted, not wired. The scan is
  synchronous: by the time a result exists there is no request outstanding to
  announce, and a failure aborts the transaction before anything commits, so
  there is no durable fact for a `MalwareScanFailedEvent` to describe.
- `Version.record_download()` replaces the service's
  `version.download_count += 1; version._touch()`.
- `DownloadService` drops `fastapi.concurrency` for `asyncio.to_thread`, and
  drops its `except SQLAlchemyError` because the repository already translates
  that to `RepositoryUnavailableError`.
- `list_versions` returns `list[Version]`; `version_item()` presents it.
- R8 is added, banning framework and filesystem roots in `*_service.py`.

## Rationale

**Why a port rather than a helper.** The alternative was leaving the copy in the
service and only moving the size limit. That leaves the worst part: a
filesystem write inside the transaction boundary, where a failure part-way
through leaves a temp file no rollback will remove. The size limit is a value
object precisely so the port is worth having — it makes the limit part of the
call rather than ambient state.

**Why `ArtifactUpload` lives in the port module, not `domain.value_objects`.**
It is a staging detail (`temp_path` is where the bytes currently live), not a
fact about an artifact, and it is the port's own return type. It follows the
pattern already in this context: `ScanResult` sits in `malware_scanner.py` and
`SignedDownloadUrl` in `download_signer.py`. This also keeps it inside R2's
allowance — an adapter in `app/infrastructure` may import another context's
`domain.ports` but not its value objects.

**Why `DomainEventPublisher` speaks the shared `DomainEvent`, not
`SoftwareDomainEvent`.** Delivery does not need to know which context produced
an event. An adapter that named the subtype would have to import this context's
domain model just to satisfy the port, which R2 (correctly) forbids.

**Why deleting the scan events rather than emitting them properly.** The
tempting fix is to emit `MalwareScanRequestedEvent` before scanning and
`MalwareScanSuccessEvent` after. That describes an asynchronous pipeline this
system does not have. The honest event stream for the current design is: an
artifact was added to a version, and the version was added and published. If the
scan is ever made asynchronous, the two events become meaningful and are worth
reintroducing then.

**Why the events are dispatched but nothing consumes them.** `pull_events()`
existing with no callers was a defect. Wiring the dispatch makes the mechanism
real and makes the next adapter a one-line change in the composition root.
Keeping the adapter a logger means the observable HTTP behaviour is unchanged,
which is the invariant for this phase.

**Why R8 rather than widening R4.** R4 answers "does this import cross a layer
boundary I named". R8 answers "does a use-case import something that is not a
use-case's business". Widening R4 to name `fastapi` and `tempfile` would have
made a rule about project structure carry a list of installed packages, and
would have retroactively re-scoped four existing ratchet entries.

## Consequences

- R4 5 -> 3. R8 0 -> 6, all of them in `user` and `authentication` and owned by
  Phases 6 and 7. R1, R2, R3, R7 stay clean. Ratchet 13 -> 17, the rise caused
  by R8 measuring an edge no earlier rule watched.
- `software_service.spool_file` and `spool_files` are gone. The two upload
  routes depend on `ArtifactStager` directly.
- The oversized-upload response is unchanged: `StagingTooLargeError` is mapped
  to 400 in `app/exceptions/handlers.py`, which is what the domain error it
  replaced produced.
- `list_versions` returns the same `SoftwareVersionRead` payload. The route has
  no `response_model`, so presentation had to stay in the router to keep the
  response body identical.
- A duplicate set of signer contracts introduced in Phase 2 was removed. ADR
  0003 had put `SignedDownloadUrl` and `DownloadUrlSigner` in
  `domain/ports/storage.py` while a near-identical `download_signer.py` already
  existed; services imported one set and the storage adapter the other.
  `StorageSettings` and `DownloadUrlSignerSettings` were also used in
  `local_storage.py` annotations but never imported, so those annotations would
  have raised on `get_type_hints`. Both settings dataclasses moved next to the
  adapter that consumes them.
- `SoftwareAccessPolicy` remains unused, and is defined twice (in
  `domain/policies/` and again in `policies/`, byte-identical). Its
  `ensure_can_download` requires `status == PUBLISHED` where the live path uses
  `is_downloadable()` and also accepts `DEPRECATED`; it requires `is_public()`
  even for a buyer, which the live path does not; and its `owns_software`
  parameter would have to be passed `has_purchase`. Adopting any of that would
  be a behavioural change disguised as a cleanup, so it is left for the phase
  that introduces download tests to decide on evidence.
- `tests/unit/test_upload_limits.py` is no longer excluded. It had referenced
  the deleted `projects` module and the deleted `spool_file`; it now covers the
  stager, including that an over-limit upload leaves no partial file behind.
