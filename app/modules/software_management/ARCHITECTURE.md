# Software Management Module — Reference Architecture

## 1. What this document is

This is the reference architecture for the `software_management` bounded context.
It records the structure, layer boundaries, aggregate design, port contracts and
error mapping **as they are implemented today**, so that a change can be checked
against something real.

It is not a design document for a future state. It was, and that is why it was
wrong: between the last substantive edit to this file and Phase 9a it had drifted
from the code in roughly forty places across nineteen sections — wrong
directory tree, wrong protocol names, wrong method signatures, an event named
`SoftwareCreated` that does not exist, a `Storage` port described with a method it
has never had, a quality gate requiring `mypy --strict` in a project where mypy is
not installed, and a section describing as future work a search implementation
that had already shipped. Phase 1 of the DDD refactor recorded the first four
divergences and said the document should be corrected "against something real in
Phase 9a". This is that correction.

**How to read it.** Every claim describes the code. Anything that does not exist
yet is confined to sections explicitly marked *(not implemented)*, and those
sections are checked too: `tests/architecture/test_architecture_doc_matches_code.py`
fails if a name listed as not implemented has since appeared, so a target cannot
quieten into a claim.

**What this document is not.** It is not a substitute for
`docs/REVIEW.md` (the phase-by-phase record of why each refactor decision was
made) or `docs/adr/` (one immutable file per decision). Where this document says
*why* something is the way it is, those are the sources; where it says *what*, that
is here and is checked.

The invariant for every change to this context remains: **the HTTP API — paths,
methods, status codes, request and response bodies — does not change** unless the
change is called out as a contract change and justified.

---

## 2. Directory structure

```
software_management/
├── ARCHITECTURE.md
├── __init__.py                     lazy re-exports of four services + the algorithm
├── dependencies.py                 composition root for this context
│
├── api/
│   ├── __init__.py
│   ├── errors.py                   http_error(): domain error -> HTTPException
│   ├── presenters.py               software_item(), version_item(), _category()
│   └── routers/
│       ├── __init__.py
│       ├── software_router.py      14 routes, prefix /api/v1/software-management
│       └── category_router.py      6 routes, prefix /api/v1/categories
│
├── application/
│   ├── __init__.py
│   ├── ports/
│   │   ├── __init__.py
│   │   └── clock.py                Clock protocol — one method, no caller
│   └── services/
│       ├── __init__.py
│       ├── software_service.py
│       ├── category_service.py
│       ├── download_service.py
│       ├── search_service.py
│       └── search_algorithm.py
│
├── domain/
│   ├── entities/
│   │   ├── __init__.py
│   │   ├── software.py
│   │   ├── version.py
│   │   ├── artifact.py
│   │   └── category.py
│   ├── events/
│   │   ├── __init__.py
│   │   └── events.py
│   ├── value_objects/
│   │   ├── __init__.py
│   │   └── value_objects.py
│   ├── ports/
│   │   ├── artifact_stager.py
│   │   ├── download_signer.py
│   │   ├── event_publisher.py
│   │   ├── malware_scanner.py
│   │   ├── notification_sender.py
│   │   ├── storage.py
│   │   ├── unit_of_work.py
│   │   └── repositories/
│   │       ├── software_repository.py
│   │       ├── category_repository.py
│   │       └── artifact_repository.py
│   ├── policies/
│   │   └── software_access_policy.py
│   └── exceptions.py
│
├── infrastructure/
│   ├── persistence/
│   │   ├── mappers/
│   │   │   ├── __init__.py
│   │   │   └── software_mapper.py
│   │   └── repositories/
│   │       ├── sqlalchemy_software_repository.py
│   │       └── category_repo.py
│   └── time/
│       ├── __init__.py
│       └── clock.py                SystemClock
│
├── policies/
│   ├── __init__.py
│   └── software_access_policy.py   duplicate — see §14
│
└── schema/
    ├── __init__.py
    ├── software_schema.py
    └── category_schema.py
```

Four things about this tree that are easy to get wrong:

**The composition root is at the context root, not under `api/`.**
`dependencies.py` is 123 lines of FastAPI providers. ADR 0001 rejected
per-module `api/dependencies.py` in favour of one shared container, and ADR 0011
split that container by ownership instead — the concern stayed one, the file did
not. Three providers with no owning context (`get_db`, `get_redis`,
`get_unit_of_work`) stayed in `app/modules/shared/dependencies.py`.

**The ORM models are not in this context.** They are shared, at
`app/infrastructure/database/models/` (`SoftwareModel`, `SoftwareVersionModel`,
`SoftwareArtifactModel`, `CategoryModel`). There is no
`infrastructure/persistence/models/` here, and there is not meant to be: a context
that owned its tables could not share a `Base.metadata` with another one.

**The adapters for storage, signing and scanning are also shared.** They live at
`app/infrastructure/storage/local_storage.py` (`LocalStorage` and
`HmacDownloadUrlSigner` in one file), `app/infrastructure/storage/local_artifact_stager.py`,
and `app/infrastructure/external_apis/scanner_service/malware_scanner.py`. Only
`SystemClock` and the repositories are inside the context.

**`domain/` and `infrastructure/` have no `__init__.py`.** They are importable as
namespace packages, and every other subpackage has one. The practical consequence
is that `pkgutil.walk_packages(app.__path__)` walks straight past both, so any
tooling built on it silently sees half this context. A whole-codebase audit in
Phase 9a reported "clean" for exactly this reason. The guard test for this
document walks the filesystem for the same reason.

---

## 3. Layer responsibilities and dependency rules

### 3.1 Dependency direction

```
api  ──▶  application  ──▶  domain  ◀──  infrastructure
                                ▲
                                │
                         (ports only)
```

- **API** depends on Application, Schema, and FastAPI.
- **Application** depends on Domain (entities, value objects, ports, exceptions,
  policies, events).
- **Domain** depends on **nothing** from the project or external frameworks, with
  one documented exception: the shared kernel (`app.modules.shared.enums`,
  `app.modules.shared.events`, `app.modules.shared.root_aggregate`,
  `app.exceptions.exceptions`). Rule R2 permits the shared kernel specifically;
  see §3.4.
- **Infrastructure** depends on Domain (implements Domain ports) and external
  libraries (SQLAlchemy, etc.).

This is not a convention here, it is a gate. `tests/architecture/layer_rules.py`
parses the import graph of `app/` with `ast` and evaluates eight rules. All eight
pass, and the `violations` list in `tests/architecture/ratchet.json` is empty, so
none of them is allowlisted — an entry there would mean a rule that can be broken.
Run it directly:

```console
$ python -m tests.architecture.layer_rules
[ok]        R1: domain must not import fastapi/starlette/sqlalchemy/pydantic/redis/jose/httpx
[ok]        R2: a module must not import another module's domain layer (use app.modules.shared)
[ok]        R3: domain must not import infrastructure (ports belong in domain, implementations in infrastructure)
[ok]        R4: application must not import api/schema/infrastructure
[ok]        R5: an application service must not import an ORM model (it has no domain object)
[ok]        R6: an API router must not build SQLAlchemy statements
[ok]        R7: a module's API layer must not import another module's API layer
[ok]        R8: an application service must not import the web framework, the ORM, or the filesystem
```

Three supplementary tests exist because the eight rules do not classify every
file:

- `test_public_http_surface.py` pins the method, path and declared success status
  of every route, so moving one between contexts is a test failure rather than a
  client's problem.
- `test_request_path_has_no_orm_models.py` covers the identity-resolution path
  and asserts codebase-wide that no `*router*.py` imports an ORM model. The
  dependency modules sit at a context root, which R5 (keyed on `_service.py`) and
  R6 (keyed on router filenames) do not classify at all.
- `test_ports_have_no_silent_defaults.py` covers a failure mode no import rule can
  see — see §5.4.

### 3.2 API layer

Responsible for:
- FastAPI route definitions
- Request validation (Pydantic schemas, in `schema/`)
- Authentication and authorization extraction
- Pagination, filtering, sorting
- HTTP response mapping

Must never contain business logic, orchestration, or repository calls.

**One known violation, and it is not a rule violation.** `category_router.py:33`
defines its own `get_unit_of_work` and `get_category_service`, duplicating
`dependencies.py:78` and `shared/dependencies.py:53`, and constructs the concrete
`UnitOfWork` itself. Five routers do this in total — `auth_router`,
`user_router`, `resources_router`, `category_router`, `support_chat_router` — and
it is the largest remaining instance of the pattern the composition-root split was
meant to remove. Recorded in `docs/REVIEW.md`, Phase 9a, "Left alone
deliberately".

### 3.3 Application layer

Responsible for:
- Use-case orchestration
- Transaction boundaries (Unit of Work)
- Authorization policy enforcement
- Domain command execution
- Domain event dispatching
- Cross-aggregate coordination

Must never import SQLAlchemy models, FastAPI types, or filesystem APIs. This is
R4, R5 and R8, and all three pass.

Two qualifications:

**`application/ports/clock.py` is a port in the application layer, and nothing
uses it.** `Clock` is a one-method protocol (`now()`) with `SystemClock`
implementing it under `infrastructure/time/`. No service takes a clock; every
timestamp in this context comes from `datetime.now()` at the point of use, and
`tests/` imports neither. A clock is arguably a domain concept, but the boundary
rules classify `application/ports/` as application, so the placement is at least
consistent with what is enforced. What is not consistent is a port with no
injector and no consumer: it is a seam for a change nobody has made. Recorded in
`docs/REVIEW.md`, Phase 9a.

**Event dispatching happens on one write path out of five.** `SoftwareService`
dispatches after commit in `_persist_version_with_artifacts` only.
`update_pricing`, `deprecate_version`, `revoke_version` and
`DownloadService.record_download` each record events that reach no publisher. See
§11.

### 3.4 Domain layer

Responsible for:
- Business invariants
- Aggregate consistency rules
- Entity behaviour
- Value object validation
- Domain event definitions
- Policy definitions
- Port (interface) definitions for external dependencies

Zero dependencies on FastAPI, SQLAlchemy/ORM frameworks, Pydantic, HTTP libraries,
filesystem APIs or cloud SDKs — R1 and R3 enforce this.

The domain does import the shared kernel: `app.modules.shared.enums` for
`SoftwareStatus`, `SoftwareVisibility`, `AccessType`, `VersionStatus` and
`ArtifactStatus`; `app.modules.shared.events` for the `DomainEvent` base;
`app.modules.shared.root_aggregate` for `AggregateRoot`; and
`app.exceptions.exceptions` for a few base types. These are deliberate, and R2
treats `app/modules/shared/**` and `app/exceptions/**` as belonging to no bounded
context, so a context importing them is importing itself. A previous version of
this document claimed the domain imports "only `stdlib`, `uuid`, `datetime`,
`typing`", which was false and would have been a rule if it were true.

R2's refinement is narrow and worth stating: `app/infrastructure/**` and
`app/modules/shared/**` may import another context's `domain.ports` and **nothing
else** — not its entities, not its value objects. That is what allows the shared
`UnitOfWork` adapter to satisfy five contexts' ports while keeping contexts
isolated from each other. Enforced by `test_r2_permits_ports_but_never_entities`.

### 3.5 Infrastructure layer

Responsible for:
- Persistence (ORM models, repository implementations, mappers)
- Storage backends
- Cryptographic signing
- Malware scanning
- Domain event delivery

**Implemented here:** `SQLAlchemySoftwareRepository`, `CategoryRepository`,
`software_mapper.py`, `SystemClock`, `LocalStorage`, `HmacDownloadUrlSigner`,
`LocalArtifactStager`, `LocalHeuristicScanner`, `LoggingDomainEventPublisher`.

*(not implemented)* Storage backends other than the local filesystem; signing
schemes other than HMAC; scanners other than the local heuristic one; any
notification adapter. See §8.

### 3.6 Schema layer

Responsible for transport models, input validation, output serialization and
OpenAPI hints. `software_schema.py` (101 lines) and `category_schema.py` (57
lines, which uses the generic `OffsetPage[T]` from `app/modules/shared/pagination.py`).

Must never contain business logic. One of them does something adjacent: the
`CategoryResponse.from_domain` classmethod takes a domain `Category`, so the
response model knows the entity it renders. That is the correct direction of
knowledge (the schema reads the domain, never the reverse) and it keeps
`category_router` from assembling response dictionaries by hand, but it means the
transport shape and the aggregate are wired together at the class level, which is
what the previous version of this document claimed happened through `slug`
validation constraints — a claim about a field that does not exist on this schema.
The bounds that do exist are transport bounds: `name` is 1–100 characters and
`description` at most 500, on the request models only, and `CategoryService`
validates independently.

---

## 4. Aggregate boundaries

### 4.1 `Software` (aggregate root)

Extends `AggregateRoot` (`app/modules/shared/root_aggregate.py`), which supplies
`_record_event`, `has_events`, `pending_events` and `pull_events`. The entity does
not define those itself.

**Fields:** `id`, `name`, `description`, `owner_id`, `category_id`,
`status`, `visibility`, `access_type`, `price` (a `Money` value object, not an
int), `versions`, `download_count`, `_events`, `created_at`, `updated_at`,
`deleted_by`, `deleted_at`.

Note that deletion is tracked by `deleted_by`/`deleted_at` pairs, not a flag.

**Invariants actually enforced:**

- An archived or deleted software accepts no state-changing command.
  `_ensure_modifiable` raises `InvalidStateTransitionError` for `DELETED` and
  `ARCHIVED`. It does **not** require `ACTIVE` — `DRAFT` is modifiable, and has to
  be, or nothing could ever be published. (The error message says "Software must
  be ACTIVE to be modifiable", which is not what the code does. The message is
  wrong; the behaviour is right.)
- A semantic version cannot be added twice (`add_version`), and a version belonging
  to another software cannot be attached.
- `update_pricing` normalises a negative price to zero rather than rejecting it.

**Invariants claimed but not enforced:** `download_count` is documented as
"cumulative; never negative" and nothing guards it. `increment_download_count` adds
one, and the only way to reach a negative count is a bug elsewhere. The claim is
recorded here as a claim, not as a fact.

**Behaviour:**

| Method | Notes |
|---|---|
| `create(*, name, description, owner_id, category_id=None, visibility=PUBLIC, price_cents=0, currency="KES")` | Factory. Derives `access_type` from the price: `FREE` at zero, `PURCHASE_REQUIRED` above it. Records no event. |
| `rename(name)` | Records no event, though `SoftwareRenamedEvent` exists. |
| `update_description(description)` | Records no event, though `SoftwareDescriptionUpdatedEvent` exists. |
| `update_pricing(*, price_cents, currency)` | Records `SoftwarePriceUpdatedEvent`. Does **not** update `access_type`. |
| `change_visibility(visibility)` | Records `SoftwareVisibilityUpdatedEvent`. Not called by any service. |
| `change_access_policy(access_type)` | Records `SoftwareAccessPolicyUpdatedEvent`. Not called by any service — so `access_type` can only ever be set at creation. |
| `publish()` / `archive()` / `restore()` | Record `SoftwarePublishedEvent` / `SoftwareArchivedEvent` / `SoftwareRestoredEvent`. None is called by any service. |
| `mark_deleted(*, actor_id)` | Records `SoftwareDeletedEvent`. There is no `marked_at` parameter; the timestamp is `now`. Not called by any service. |
| `add_version(version)` | Records `VersionAddedEvent`. |
| `add_artifact_to_version(*, version, artifact)` | Attaches and records `ArtifactAddedToVersion`. This is the method the upload path uses. |
| `publish_version` / `deprecate_version` / `revoke_version` / `remove_version` | Each takes a `version_id`, each records an event. |
| `increment_download_count()` | Records `SoftwareDownloadedEvent`. Calls `_ensure_modifiable`, so a download against archived software raises. |
| `get_version(id)` / `get_version_by_semver(semver)` | Queries. Both raise `SoftwareNotFoundError` on a miss, not `VersionNotFoundError`. |
| `latest_downloadable()` / `latest_version()` / `published_versions()` | Queries. |

**Intent-revealing queries:** `is_owned_by(actor_id)`, `is_public()`,
`is_active()`, `is_archived()`, `is_deleted()`, `requires_payment()`,
`has_versions()`, `has_downloadable_versions()`, `is_publicly_visible()`.

`is_publicly_visible()` is a compatibility shim that combines visibility and
status. It is the one method here whose reason for existing is historical rather
than conceptual.

### 4.2 `Version` (entity inside the Software aggregate)

Not an `AggregateRoot`; it records no events of its own — every event naming a
version is recorded by `Software`, because the aggregate root owns the event
stream.

**Fields:** `id`, `software_id`, `number` (a `SemVer`), `release_notes`, `status`,
`lock_version`, `download_count`, `published_at`, `created_at`, `updated_at`, and
`_artifacts` — a **collection**, exposed read-only as the `artifacts` property.
A version can carry several artifacts, not one reference.

**Invariants:**

- Publishing requires at least one artifact and requires every artifact to be
  `ACTIVE`; otherwise `MalwareScanPendingError`. This is what makes the scanner
  load-bearing rather than advisory.
- A revoked version cannot be published.
- `publish()` on an already-published version is a no-op rather than an error.
- Only `PUBLISHED` or `DEPRECATED` versions are downloadable (`is_downloadable`).
- `_touch()` also increments `lock_version`, which is optimistic locking that
  nothing currently checks.

**Behaviour:** `add_artifact(artifact)`, `remove_artifact(artifact_id)`,
`publish()`, `deprecate()`, `revoke()`, `record_download()`, `is_published()`,
`is_downloadable()`.

### 4.3 `Artifact` (entity inside the Version aggregate)

Not an `AggregateRoot` and records no events, despite
`process_malware_scan_success(event)` and `process_malware_scan_failed(event)`
taking one: they read the event and change status, they do not record it.

**Fields:** `id`, `version_id`, `storage_key`, `sha256`, `size_bytes`,
`mime_type`, `filename`, `status`, `quarantine_reason`, `created_at`,
`updated_at`. All required; no defaults on the timestamps.

**Invariants:** an artifact cannot return to `ACTIVE` from `DELETED`;
`verify_integrity(computed_hash_sha256)` raises `ArtifactIntegrityError` on a
checksum mismatch.

**Behaviour:** `verify_integrity`, `process_malware_scan_success`,
`process_malware_scan_failed`, `soft_delete(at)`.

**`verify_integrity` and `soft_delete` have no caller in `app/`.** Only
`test_sms_lifecycle.py` exercises the malware-scan methods. This is recorded
because §4 of a document that claims these are the aggregate's behaviour should
distinguish what is reachable from what is merely present.

### 4.4 `Category` (a typed record, not an aggregate root)

This is the honest description. `Category` is a mutable slots dataclass, **not** a
frozen one and **not** an `AggregateRoot`, and it records no events. The previous
version of this document called it an aggregate root with a `soft_delete()` method
and two invariants; all three of those claims were wrong.

**Fields:** `id`, `name`, `description`, `deleted_at`, `created_at`,
`updated_at`. Deletion is a nullable timestamp, and `is_deleted()` is a method.

**Behaviour:** `create(*, name, description=None)`, `rename(name)`,
`update_description(description)`, `mark_deleted(*, marked_at=None)`, `restore()`,
`is_deleted()`. `mark_deleted` normalises the name and refuses to act on a deleted
category.

**The two invariants are enforced elsewhere**, and the placement matters more than
the placement claim did:

- *Name uniqueness (case-insensitive)* is enforced by `CategoryService` (which
  raises `DuplicateCategoryError`) and backed by a database check in
  `category_repo.py`. It cannot live in the aggregate, because uniqueness is a
  property of the set and the aggregate only ever holds one member of it.
- *A category with assigned software cannot be deleted* is enforced by
  `CategoryService.delete` via `count_software`, raising `CategoryInUseError`.

---

## 5. Repository boundaries

### 5.1 Port definitions

Ports live in `domain/ports/repositories/`. They are `Protocol`s, and they are
**`I`-prefixed**: `ISoftwareRepository`, `ICategoryRepository`,
`ArtifactRepository`. The previous version of this document called the first two
`SoftwareRepository` and `CategoryRepository`, which collided with the concrete
`CategoryRepository` and obscured the fact that three different things in this
context are called "Category repository" in three different roles.

```python
class ISoftwareRepository(Protocol):
    async def save(self, software: Software) -> None: ...
    async def get(self, software_id: UUID) -> Software | None: ...
    async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool: ...
    async def list_marketplace(self, *, limit: int = 50, offset: int = 0) -> list[SoftwareCard]: ...
    async def list_owned(self, owner_id: UUID, *, limit: int = 50, offset: int = 0) -> tuple[list[OwnedSoftwareCard], int]: ...
    async def soft_delete(self, software_id: UUID) -> None: ...
    async def search_candidates(self, query: str | None = None, *, category_id: UUID | None = None,
                                tags: list[str] | None = None, limit: int = 500) -> list[Software]: ...
```

```python
class ICategoryRepository(Protocol):
    async def get(self, category_id: UUID) -> Category | None: ...
    async def save(self, category: Category) -> Category: ...   # returns the entity
    async def exists(self, name: str) -> bool: ...
    async def find_by_name(self, name: str) -> Category | None: ...
    async def rename(self, category_id: UUID, name: str) -> None: ...
    async def soft_delete(self, category_id: UUID) -> None: ...
    async def restore(self, category_id: UUID) -> None: ...
    async def list_categories(self, *, limit: int, offset: int, include_deleted: bool) -> tuple[list[Category], int]: ...
    async def count_software(self, category_id: UUID) -> int: ...
```

```python
class ArtifactRepository(Protocol):
    async def get(self, artifact_id: UUID) -> Artifact | None: ...
    async def save(self, artifact: Artifact) -> None: ...
```

Two of these need their real state stated rather than a signature:

**`ArtifactRepository` is orphaned.** No class implements it and nothing calls it.
`SoftwareManagementUnitOfWork` deliberately omits `artifact_repo`, on the
reasoning that an artifact has no independent lifecycle — it is only ever reached
through its version. The port is a leftover from before that decision, and §10.1
of the previous document described a unit of work that had this property.

**`has_purchase` has no data source.** The purchase table was removed with the
`billing` module, so there is no purchase to record and therefore no buyer to find.
`SQLAlchemySoftwareRepository` answers `False` explicitly. This was not always so,
and the reason it matters is in §5.4.

### 5.2 Implementation rules

- Implementations live in `infrastructure/persistence/repositories/`.
  `category_repo.py` breaks the `*_repository.py` filename convention; the class
  inside it is `CategoryRepository`, which does not break the *class* convention
  because there is no `SQLAlchemyCategoryRepository` anywhere — the name in the
  previous version of this document had never existed.
- Repositories translate between domain entities and ORM models via mappers.
- Repositories raise **domain exceptions** and never let a `SQLAlchemyError`
  escape. Every statement in both repositories is wrapped. This is deliberately
  the repository's job and not the application service's: a service that caught
  `SQLAlchemyError` would be a second place to forget the mapping, and R8 forbids
  the import.
- Repositories never dispatch events, generate URLs, or contact storage.

### 5.3 Mappers

`software_mapper.py` (196 lines) is a set of module **functions**, not a class:
`software_to_entity`, `software_to_model`, and the private
`_version_to_entity` / `_version_to_model` / `_artifact_to_entity` /
`_artifact_to_model`, with `_version_status` and `_artifact_status` translating
between ORM strings and domain enums.

`Category`'s two mapper functions, `_category_to_model` and
`_category_to_entity`, are **inlined in `category_repo.py`** rather than living in
a mapper module. That contradicts §17.5's own argument for mappers, and it is
recorded as a known inconsistency rather than described as if it were the design.

The mapper's own docstring cites §5.3 of this document, which is why an inaccurate
description of it was worth correcting rather than leaving to rot.

### 5.4 A port member with no implementation is a default value, not an error

`SQLAlchemySoftwareRepository` subclasses its port explicitly:

```python
class SQLAlchemySoftwareRepository(ISoftwareRepository):
```

A `Protocol` subclass that is not itself a protocol is an ordinary class, so it
**inherits the port's method bodies**. A port member written as `...` is therefore
answered on any implementation that forgot to write it — quietly, at the first
call, with a traceback pointing at the port.

`has_purchase` was never implemented. It returned `None` for every user. `None` is
falsy, and a falsy `None` is indistinguishable from a real answer, so every
purchase check in the codebase answered "this user bought nothing" with no sign
that the question had gone unasked. Three call sites consumed it: two in
`SoftwareService` (`download_url`, `download_artifact_url`) and one in
`DownloadService.create_download_url`, plus a fourth in the router.

The answer was accidentally correct — nobody can be a buyer, because nothing can
record a purchase — which is the dangerous part. A wrong answer that nothing can
distinguish from a right one is worse than a loud failure, because it survives
until the day the second one stops being true.

Phase 9a fixed it in two halves. The port's `has_purchase` now raises rather than
defaulting, so a forgotten override is loud; and the repository states `False`
explicitly, at the adapter that owns the knowledge of why. A guard
(`tests/architecture/test_ports_have_no_silent_defaults.py`) sweeps every
explicit port subclass in `app/` and fails if one inherits a member whose port
still has an ellipsis body.

The sweep found exactly one such case across `app/`, so this is an isolated defect
and not a systemic one. `DownloadService` also had a `hasattr(repo,
"has_purchase")` guard around the call, which never once returned `False` — the
attribute was always inherited, so the guard was dead code that looked like
defensive programming. Removed.

The port already had the right shape for this before Phase 9a: `Clock.now` in the
same context raises `NotImplementedError` rather than `...`. `has_purchase` now
matches it.

---

## 6. Application service boundaries

### 6.1 `SoftwareService`

Constructor takes `unit_of_work`, `storage`, `malware_scanner`, `download_service`,
`category_service` and `event_publisher` — six ports or sibling services, and no
concrete adapter.

Coordinates: `list_visible`, `get`, `list_versions`, `upload_package`,
`upload_version`, `update_pricing`, `require_owner`, `download_url`,
`download_artifact_url`, `deprecate_version`, `revoke_version`, `has_purchase`.

**It does not orchestrate visibility, archive, restore, delete or publish.** The
aggregate has `change_visibility`, `archive`, `restore` and `mark_deleted`, and no
service calls any of them, because no route exposes them. The previous version of
this document listed all of them as responsibilities. What the aggregate offers and
what the API exposes are different sets, and only the second one is a product
decision.

It also exposes a `repository` property **with a setter** that installs a test
override. `software_router.py:336` uses it to build a `SearchService` from the
service's own repository — a service reaching into a sibling service's dependency.
Recorded in `docs/REVIEW.md` as part of the Phase 9a findings.

### 6.2 `CategoryService`

Takes only a unit of work. Methods: `create`, `rename`, `update_description`,
`delete`, `restore`, `get`, `find_by_name`, `list_categories`. Enforces name
uniqueness and the in-use check (§4.4), and logs its own operations — it is the
only service in the context that does.

### 6.3 `DownloadService`

Takes a unit of work, a `DownloadSigner` and a `Storage`.

| Method | Role |
|---|---|
| `create_download_url(*, software_id, version_number, user_id)` | Loads the software, resolves the version, requires it to be downloadable and to carry exactly one artifact, authorizes, signs, then records the download. |
| `create_artifact_download_url(*, artifact, user_id=None)` | Signs a URL for a specific artifact. Performs no authorization of its own. |
| `verify_token(*, storage_key, expires, token, method)` | Delegates to the signer and translates its verdict into a domain error: `ExpiredDownloadTokenError` (410) when the signature is authentic but lapsed, `InvalidDownloadTokenError` (403) for anything else. Performs **no** authorization — this endpoint has no session, so the token is the credential. |
| `record_download(*, software_id, version_id=None)` | Opens a write transaction, increments the software's and the version's counters, saves. |
| `read_file(*, storage_key)` | **This is where the storage→domain translation in §12.4 actually happens.** It is not in the previous version of this document, which described that mapping as infrastructure's job. Returns a `BinaryIO`; the router streams it and closes it, so the body is never held in memory. |

**Authorization is weaker than §6.3 of the previous document claimed.** The check
is `not is_public() and not is_owned_by() and not has_purchase()`, so public
software needs no authorization at all. The class that encodes the fuller rule,
`SoftwareAccessPolicy.ensure_can_download`, is never called from production code
(§14).

`record_download` does **not** pull or dispatch events, though the previous
version of this document said it did. It also calls `version.record_download()`
as well as the software-level counter.

### 6.4 The download is two routes, not one

```
GET /api/v1/software-management/{software_id}/versions/{version}/artifacts/{artifact_id}/download
    authenticated ── abuse guard ── authorize ── record ── sign ── 307
                                          │
                                          ▼
GET /api/v1/software-management/storage/download/{storage_key:path}?expires=&token=
    verify ── open through Storage ── stream ── close
```

The first is the authorized half and it requires a session. The second serves the
bytes and deliberately does **not**: the HMAC token is its credential, and it is
short-lived and bound to the key, the method and its own expiry, so it cannot be
pointed at a different artifact or replayed later. Nothing authorizes twice —
`SoftwareService` and `DownloadService` both refuse before signing, and that is a
defence in depth, not two rules.

**These are different things and the distinction has to be held to:**

| | Storage key | HTTP route |
|---|---|---|
| Is | a logical identifier, relative to the storage root | a URL path |
| Looks like | `software/{sid}/versions/{vid}/{aid}/file.pdf` | `/api/v1/software-management/storage/download/…` |
| Who resolves it | `LocalStorage`, after checking it stays under the root | FastAPI, from `SIGNED_DOWNLOAD_ROUTE` |
| Reaches the client | only as the signed path tail | yes |

The key is a `:path` tail, so its `/` separators stay unencoded and each segment
is escaped individually. `quote(storage_key, safe="")` — which is what this
context used — collapsed the key into one opaque segment, so the route matched a
different key than the one that had been signed.

The two route descriptions live in one constant, `SIGNED_DOWNLOAD_ROUTE`, asserted
against the router's own prefix at import. They were previously two independent
settings — the router's literal, and an environment variable defaulting to `""` —
and nothing could make them agree. That, not the string concatenation around
them, is why the redirect 404'd: `f"{backend_url}/{download_path.strip('/')}/{key}"`
with an empty `download_path` emitted `http://host//software/…`, and even with a
correct path it would have pointed at a route that only exists because the router
declares it.

The constant sits in `domain/ports/download_signer.py` rather than beside either
of the two things that have to agree about it. The signer must build URLs for the
route and the router must declare it, so defining it in either leaves the other
importing across a layer it should not — infrastructure from the API, or the API
from infrastructure. On the port it is read inward by both, alongside
`SIGNED_DOWNLOAD_METHODS`, which is the rest of the same contract.

---

## 7. Port definitions

Seven ports, not four.

| Port | Contract |
|---|---|
| `Storage` | `save(*, storage_key, source_path: Path)`, `open(*, storage_key) -> BinaryIO`, `delete(*, storage_key)`, `exists(*, storage_key) -> bool`. **All synchronous** by design; callers use `asyncio.to_thread`. |
| `DownloadSigner` | `create_url(*, storage_key, method="GET") -> SignedDownloadUrl`, `verify_token(*, storage_key, expires, token, method="GET") -> TokenVerification`. The expiry comes from adapter settings, not the caller. `TokenVerification` carries a `valid` flag plus a `TokenRejectionReason` (missing / malformed / invalid_resource / unsupported_method / expired / signature_mismatch); a bare `bool` previously collapsed all six into one answer. The signature is checked *before* the expiry, so `expired` means the signature is authentic and has lapsed — otherwise anyone could present an unsigned token with a past expiry and be told the one answer that means "ask again". `SIGNED_DOWNLOAD_METHODS` is `{GET}` and a test asserts it against the router's declared methods, because FastAPI's `APIRoute` does not derive `HEAD` from `GET` and admitting it would mint URLs that answer 405. |
| `MalwareScanner` | `scan_file(*, file_path: Path, filename, sha256, content_type: str \| None) -> ScanResult`. |
| `NotificationSender` | `send(*, recipient_id, event: SoftwareDomainEvent, channels: list[str])`. Declared and unused — no implementation exists. |
| `DomainEventPublisher` | `publish(events: Sequence[DomainEvent])`. The real outbound port for events; the previous document named `NotificationSender` for this role. |
| `ArtifactStager` | `stage(...) -> ArtifactUpload`, `discard(upload)`. Plus `ArtifactUpload`, `UploadedFile`, `UploadLimits`, `StagingError`, `StagingTooLargeError`. |
| `SoftwareManagementUnitOfWork` | §10.1. |

`Storage` carries its own six-class exception hierarchy
(`StorageError`, `StorageUnavailableError`, `StorageWriteError`,
`StorageReadError`, `StorageFileNotFoundError`, `StorageSecurityError`) in
`domain/ports/storage.py`. ADR 0003 consolidated these with an identical set that
`local_storage.py` had been defining separately, because the split meant callers
catching the *infrastructure* class never caught the *domain* one and a missing
file surfaced as a 500 from an unrelated frame.

`SignedDownloadUrl` is defined in `domain/ports/download_signer.py`, not in
`domain/value_objects/`, because it is the result of a port call rather than a
concept the domain reasons about. The previous document listed it as a value
object.

**Rule:** application services depend only on these protocols. `Depends()` wires
the concrete implementations, at the context root rather than at the API edge.

---

## 8. Infrastructure adapter responsibilities

### 8.1 Persistence

| Component | Role |
|---|---|
| `SQLAlchemySoftwareRepository` | Implements `ISoftwareRepository` over an async session. |
| `CategoryRepository` | Implements `ICategoryRepository`. Its name is the one place in this context where the implementation and the port differ by more than an `I` and a `SQLAlchemy` prefix. |
| `software_mapper.py` | Module functions, §5.3. There is no `SoftwareMapper` class, and there never was. |

*(not implemented)* `CategoryMapper` and `ArtifactMapper` as classes; the
functionality exists, the classes do not.

### 8.2 Storage

| Component | Role |
|---|---|
| `LocalStorage` | Filesystem-backed. Synchronous. Raises the domain's storage exceptions by identity, which `test_storage_port.py` asserts. |
| `HmacDownloadUrlSigner` | HMAC-SHA256 signed URL generation and verification. Co-located with `LocalStorage` in the same file. |

*(not implemented)* `S3Storage`, `AzureBlobStorage`, any other backend. The
extension point is `app/modules/shared/container.py`, which builds the singleton —
there is no backend switch in `get_storage()`, which is a two-line return.

Migrating to another backend requires no change to Domain or Application. That
claim holds: the port is four methods and the services never import the adapter.

### 8.3 Malware scanning

| Component | Role |
|---|---|
| `LocalHeuristicScanner` | Scans a 1 MiB sample for EICAR and X5O markers. Synchronous. |
| `get_malware_scanner()` | Reads `settings.MALWARE_SCAN_PROVIDER`; supports `"local"` and raises `RuntimeError` for anything else. |

`SoftwareService._scan_file` uses `inspect.iscoroutinefunction` to accept either a
sync or an async scanner, and falls back to an inline no-op `ScanResult` when no
scanner is injected. The fallback is a hard-coded value in the service, not a
`NoOpScanner` adapter.

*(not implemented)* `ClamAVScanner`, `VirusTotalScanner`, a `HeuristicScanner` by
that name.

### 8.4 Event delivery

| Component | Role |
|---|---|
| `LoggingDomainEventPublisher` | Logs `event_type`, `aggregate_id`, `event_id`. Never raises. |

*(not implemented)* Every notification adapter. `NotificationSender` is a port
with no implementation and no caller.

---

## 9. Dependency injection

### 9.1 Composition roots

There are two, by design (ADR 0011):

- `app/modules/software_management/dependencies.py` — this context's providers
- `app/modules/shared/dependencies.py` — `get_db`, `get_redis`, `get_unit_of_work`,
  the three with no owning context

```python
def get_storage() -> Storage:
    return storage                                    # singleton from shared/container.py

def get_signer() -> DownloadSigner:
    return signer                                     # same

event_publisher = LoggingDomainEventPublisher()

def get_event_publisher() -> DomainEventPublisher:
    return event_publisher

def get_scanner() -> MalwareScanner:
    return get_malware_scanner()

def get_category_service(unit_of_work: UnitOfWork = Depends(get_unit_of_work)) -> CategoryService: ...

def get_download_service(signer, unit_of_work, storage) -> DownloadService: ...

def get_software_service(
        download_service, storage, malware_scanner, unit_of_work,
        category_service, event_publisher) -> SoftwareService: ...

upload_limits = UploadLimits(max_size_bytes=settings.PACKAGE_UPLOAD_MAX_SIZE_BYTES)
stager = LocalArtifactStager()

def get_artifact_stager() -> ArtifactStager:
    return stager
```

Note what the previous version of this document got wrong here, since it is the
part most likely to be copied: it showed four `async` providers that switch on a
`settings.backend` string and raise `ConfigurationError` on anything unsupported.
None of those switches exists. Three of the four real providers are two-line
returns of a module-level singleton, and `get_software_service` takes six
dependencies rather than four, with `unit_of_work` and `malware_scanner` as the
keyword names and no `signer` at all — the signer reaches `SoftwareService`
indirectly, through `DownloadService`.

`UploadLimits` is built here rather than read from settings by the service that
enforces it, which is what keeps `app.core` out of the application layer (R8).

### 9.2 Rules

- Services receive dependencies by constructor injection.
- Routers obtain services through `Depends()`.
- No service locator.
- Configuration flows environment → settings → factories → services.

The concrete `UnitOfWork` is named in the providers' type hints, which is
infrastructure in a `dependencies.py` and therefore not subject to R4.

---

## 10. Transactions

### 10.1 The unit of work

`domain/ports/unit_of_work.py` declares a per-context `Protocol`:

```python
class SoftwareManagementUnitOfWork(UnitOfWorkPort, Protocol):
    @property
    def software_repo(self) -> ISoftwareRepository: ...
    @property
    def category_repo(self) -> ICategoryRepository: ...
```

Five contexts each declare their own, listing only their own repositories. One
concrete `UnitOfWork` at `app/infrastructure/database/unit_of_work.py` satisfies
all five and asserts conformance to each at import time, because a `Protocol` is
structural and a missing repository is otherwise an `AttributeError` on the first
request that needs it.

That concrete class also exposes `user_repo`, `session_repo`, `chat_message_repo`,
`resource_repo` and `audit_repo`, plus `commit()`, `rollback()` and `read_only()`.
`__enter__` and `__exit__` raise `TypeError` on purpose, to catch a synchronous
`with` on an async unit of work.

**There is no `artifact_repo`**, deliberately: an artifact has no independent
lifecycle and is reached through its version.

### 10.2 Usage

```python
async with self._uow:
    software = await self._uow.software_repo.get(software_id)
    software.update_pricing(price_cents=cents, currency=currency)
    await self._uow.software_repo.save(software)
    # commit on clean exit
```

Repositories `flush()` and `refresh()` but never commit; the unit of work does.

### 10.3 Read-only transactions

```python
async with self._uow.read_only():
    software = await self._uow.software_repo.get(software_id)
```

Used in twenty-two places, fourteen of them in this context. `read_only()` also
rolls back on exception, so a read cannot leave a transaction open.

### 10.4 Error semantics

- An exception inside `async with` triggers rollback.
- Driver errors are translated **in the repository**, not in the application
  service: `sqlalchemy_software_repository.py` raises the domain's
  `RepositoryUnavailableError` and `category_repo.py` raises
  `CategoryRepositoryUnavailableError` (503 each). The previous version of this
  document put this in the application layer, which R8 has forbidden since
  Phase 3, and named a `SoftwareRepositoryUnavailableError` that exists only as
  an import alias in `app/exceptions/handlers.py:36`.
- Domain exceptions propagate unchanged to the handlers in §12.
- **One service does it the other way.** `SearchService.search` wraps the
  repository call in `except Exception` and re-raises `RepositoryUnavailableError`,
  so it both translates a driver error the repository already translated and
  swallows every other one — a `SoftwareNotFoundError` from the repository would
  reach the client as "Search repository unavailable". It is the only place in the
  context where a service names a repository-unavailability error, and
  `DownloadService.record_download` carries a comment explaining why it does not
  do the same. Recorded in `docs/REVIEW.md`, Phase 9a.

---

## 11. Events

### 11.1 The pattern

1. An aggregate method records a domain event on itself.
2. The application service calls `pull_events()` **after** the transaction
   commits, and passes the events to `DomainEventPublisher`.
3. An adapter delivers them.

Never before the commit: a rollback would take the facts back, and dispatching
first is how a queue ends up holding events for a transaction that never
happened.

### 11.2 What is recorded, and what is delivered

`domain/events/events.py` defines 21 classes: a `SoftwareDomainEvent` base and 20
concrete events. The previous version of this document tabulated four, two of
which (`SoftwareCreated`, `ArtifactUploaded`) have never existed, and it attributed
`ArtifactAddedToVersion` to `Version.attach_artifact`, a method that records
nothing.

| Signal | Recorded by | Dispatched? |
|---|---|---|
| `VersionAddedEvent` | `Software.add_version` | upload path only |
| `ArtifactAddedToVersion` | `Software.add_artifact_to_version` | upload path only |
| `SoftwarePriceUpdatedEvent` | `Software.update_pricing` | **no** |
| `VersionDeprecatedEvent` | `Software.deprecate_version` | **no** |
| `VersionRevokedEvent` | `Software.revoke_version` | **no** |
| `SoftwareDownloadedEvent` | `Software.increment_download_count` | **no** — and `record_download` is the only thing that emits it in practice |
| `SoftwarePublishedEvent` | `Software.publish` | **no** (no service calls it) |
| `SoftwareVisibilityUpdatedEvent` | `Software.change_visibility` | **no** (no service calls it) |
| `SoftwareAccessPolicyUpdatedEvent` | `Software.change_access_policy` | **no** (no service calls it) |
| `SoftwareArchivedEvent` / `SoftwareRestoredEvent` / `SoftwareDeletedEvent` | `archive` / `restore` / `mark_deleted` | **no** (no service calls it) |
| `VersionPublishedEvent` | `Software.publish_version` | **no** (no service calls it) |
| `VersionRemovedEvent` | `Software.remove_version` | **no** (no service calls it) |
| `SoftwareRenamedEvent`, `SoftwareDescriptionUpdatedEvent`, `ArtifactRemovedFromVersion`, `MalwareScanRequestedEvent`, `MalwareScanSuccessEvent`, `MalwareScanFailedEvent` | **nothing** | defined and never recorded |

Two distinct defects are visible in that table. The first is that four reachable
write paths record events that no publisher ever sees, so
`SoftwareDownloadedEvent` — the event analytics would most want — is never
delivered. The second is that six event classes exist with no producer, two of
them for methods that deliberately record nothing.

Eight of the fourteen recorded signals come from aggregate methods no service
calls, which is the mirror of the same problem: the aggregate offers a lifecycle
the application layer never drives.

The three `MalwareScan*` events are the exception that proves the rule: the scan is
synchronous, so there is no outstanding request to announce and no durable fact for
a failure event. They become meaningful if scanning is made asynchronous, which is
where Phase 3 left them.

### 11.3 Delivery semantics

- Aggregates record; services dispatch; adapters deliver. The `event_publisher.py`
  docstring cites this section by number.
- **Delivery is at-most-once, not at-least-once.** `pull_events()` clears the list
  before the publisher is called, so a publisher that raises loses the events. The
  only adapter logs and cannot fail, so nothing is lost today — but the previous
  version of this document's claim of "idempotent where possible (at-least-once
  delivery)" describes an outbox, and there is no outbox.

---

## 12. Errors

### 12.1 Domain exceptions

`domain/exceptions.py` holds 29 classes, not the 5 the previous version listed. The
shape is not two independent hierarchies: `SoftwareDomainError` is the root, with
20 direct subclasses, and `CategoryDomainError` is one of them — a category failure
is caught by `except SoftwareDomainError`, which is why every `software_router`
handler also answers for categories. Below `CategoryDomainError` there are five
more. All 28 are catchable as `SoftwareDomainError`.

The base classes are `SoftwareDomainError`, `SoftwareNotFoundError`,
`SoftwareAccessDeniedError`, `InvalidStateTransitionError` and
`RepositoryUnavailableError` — all present, all with the documented names. Also
`VersionNotFoundError` and `ArtifactNotFoundError`, which extend
`SoftwareNotFoundError` rather than the root, so a 404 handler for the parent
covers both; `VersionNotDownloadableError`, `DownloadDeniedError`,
`SoftwareArchivedError`, `SoftwareDeletedError`, `SoftwareNotPublishedError`,
`VersionUnavailableError`, `OwnerCannotPurchaseError`, `DuplicatePurchaseError`,
`InvalidSemVerError`, `ArtifactIntegrityError`, `MalwareScanPendingError`,
`SoftwareValidationError` (a frozen dataclass, not a plain `Exception`), the three
download-delivery classes below, and the six `Category*` classes.

Three download-delivery errors sit under `SoftwareAccessDeniedError` rather than
the root, because all three refuse a request that carries no credentials of its
own: `InvalidDownloadTokenError` (missing, malformed, forged, or bound to another
resource or method), `ExpiredDownloadTokenError` (authentic but lapsed), and
`UnsafeStorageKeyError` (the token was authentic, but the key it is bound to is
not addressable — a symlink resolving outside the storage root, which no
string-level check can see). The first two are separate classes because their
remedies differ: a lapsed link is fixed by asking for a new one, a forged one is
not, and collapsing them into one 403 told a client with a stale link that it had
been refused access.

The third is a sibling rather than a fourth reason to merge, and the distinction
is narrow enough to be worth stating. It was previously raised *as*
`InvalidDownloadTokenError`, which made an unaddressable key indistinguishable
from a forged token even in the logs — and the two call for opposite responses,
since one means a client with a broken link and the other a request probing the
storage layout. It is reachable only when the signer accepts a key that the
adapter then refuses, since both validate the key's syntax; the residual case is
filesystem state, which is why the check stays in `LocalStorage._resolve_path`.
`ArtifactStorageUnreadableError` is *not* a denial: it is a server-side failure
(500) whose message is deliberately generic, because the adapter's own message
names the resolved path under `/app/storage`.

Three names in `app/exceptions/exceptions.py` collide with domain names
(`RepositoryUnavailableError`, `DuplicatePurchaseError`,
`OwnerCannotPurchaseError`), and `handlers.py` aliases around the collision:
line 36 imports the domain `RepositoryUnavailableError` *as*
`SoftwareRepositoryUnavailableError` while line 17 imports the shared-kernel class
of the same name unaliased. Both are registered for 503, so the collision is
currently harmless, and worth knowing before adding an import.

### 12.2 Application layer

- Never raises `HTTPException` or any framework error; R8 enforces it.
- Does not catch driver errors; the repository owns that (§10.4).

### 12.3 Two translation layers, and they disagree

This is the most consequential thing the previous version of this document got
wrong, because it described one layer and there are two.

**Layer 1 — the global registry, `app/exceptions/handlers.py`.** Every handler
returns a `JSONResponse`, not `raise HTTPException`; the previous version showed a
handler that re-raises. It registers 57 exception types across the whole app, not
just this context, and maps them to ten status codes — seven of them beyond the
400/403/404 this context produces on its own (401, 409, 410, 422, 429, 500, 503).

| Exception | Status |
|---|---|
| `SoftwareDomainError` (and `CategoryDomainError`, `ResourceDomainError`, `DomainError`) | 400 |
| `SoftwareAccessDeniedError`, `SoftwareOwnerCannotPurchaseError`, `SoftwareNotPublishedError`, `DownloadDeniedError`, `InvalidDownloadTokenError`, `UnsafeStorageKeyError` | 403 |
| `SoftwareNotFoundError`, `VersionNotFoundError` via base, `CategoryNotFoundError`, `StorageFileNotFoundError` | 404 |
| `InvalidStateTransitionError`, `SoftwareArchivedError`, `VersionUnavailableError`, `MalwareScanPendingError`, `DuplicateCategoryError`, `CategoryInUseError`, `CategoryDeletedError`, `SoftwareDuplicatePurchaseError`, `ConflictError` | 409 |
| `SoftwareDeletedError`, `ExpiredDownloadTokenError` | 410 |
| `InvalidSemVerError`, `ArtifactIntegrityError`, `SoftwareValidationError`, `ValidationError`, `InvalidMoneyError`, `InvalidCurrencyError` | 422 |
| `RepositoryUnavailableError` (both the domain class and the shared-kernel one), `SoftwareRepositoryUnavailableError` (an alias of the domain class), `CategoryRepositoryUnavailableError`, `StorageUnavailableError`, `ExternalServiceError` | 503 |
| `StorageError`, `StorageReadError`, `StorageWriteError`, `StagingError`, `ArtifactStorageUnreadableError` | 500 |
| `StagingTooLargeError` | 400 |
| `UnauthorizedError` | 401 |
| `PermissionError` | 403 |
| `TooManyRequestsError` | 429 |

**Layer 2 — the context's own, `api/errors.py`.** `http_error(exc)` maps
`SoftwareAccessDeniedError`→403, `SoftwareNotFoundError`→404, and **everything
else**→400. Every `software_router` handler wraps its body in
`except SoftwareDomainError: raise http_error(exc)`.

**They conflict, and the conflict is observable.** `InvalidStateTransitionError`
is a `SoftwareDomainError` subclass, so when it is raised inside a route — as it
is, by `update_pricing` on archived software — the router catches it and returns
**400**, not the 409 the registry declares. The 409 handler is reachable only for
errors raised outside a route handler's `try`. The same shadowing applies to
`SoftwareArchivedError` (409→400), `MalwareScanPendingError` (409→400),
`DownloadDeniedError` (403, which happens to agree) and `RepositoryUnavailableError`
(503→400).

The search route adds a third translation to the two: `software_router.py:339`
catches bare `Exception` and answers 503, so a search failure reports itself as
unavailable whatever actually went wrong. That status happens to be right for the
one failure the route can produce — the repository's 503, re-wrapped by
`SearchService` (§10.4) — and wrong for every other.

`api/errors.py` is the older of the two and the registry is the more complete, so
the likely intent is the reverse of the current behaviour. Correcting it changes
status codes, so it is not done inside a phase whose invariant is that the HTTP API
does not change. Recorded in `docs/REVIEW.md`, Phase 9a.

### 12.4 Driver and storage error translation

| Adapter raises | Translated to | By | Status |
|---|---|---|---|
| `SQLAlchemyError` | `RepositoryUnavailableError` | `sqlalchemy_software_repository` | 503 |
| `SQLAlchemyError` | `CategoryRepositoryUnavailableError` | `category_repo` | 503 |
| `StorageFileNotFoundError` | `ArtifactNotFoundError` | `DownloadService.read_file` | 404 |
| `StorageSecurityError` | `UnsafeStorageKeyError` | `DownloadService.read_file` | 403 |
| `StorageUnavailableError` | `ExternalServiceError` | `DownloadService.read_file` | 503 |
| `StorageReadError` | `ArtifactStorageUnreadableError` | `DownloadService.read_file` | 500 |
| `StagingTooLargeError` | (not translated) | the port raises it directly | 400 |
| non-clean `ScanResult` | bare `SoftwareDomainError` | `SoftwareService._process_artifact` | 400 |

There is no `MalwareScanError` and no `MalwareScanPendingError` translation on the
upload path, which is what the previous version's table claimed. A non-clean scan
becomes `SoftwareDomainError(scan.reason or "Malware detected.")`;
`MalwareScanPendingError` is raised by `Version.publish` instead, when a version
with a quarantined artifact is published.

---

## 13. Logging

### 13.1 Principles

- Lazy `%s` formatting, never f-strings.
- Context ids in the line: `software_id`, `version_id`, `user_id`.
- No secrets: no tokens, no signed URLs, no storage paths, no API keys, no file
  contents.

### 13.2 By layer

| Layer | Logs |
|---|---|
| **Domain** | **Nothing.** No `domain/` file imports `logging`. |
| **Application** | Use-case start and end, authorization decisions, event dispatch. In practice only `CategoryService` (7 calls) and `DownloadService` (3) do this; `SoftwareService` has exactly two, both on failure paths — a cleanup that raised and a dispatch that raised. |
| **Infrastructure** | Integration attempts, retries, failures. |
| **API** | Request metadata — except `category_router.py`, which logs eight lifecycle lines (create, rename, update, delete, restore, each requested and completed). It is the most detailed logger in the context and it is in the transport layer. |

### 13.3 Known violations of this document's own rules

Stated because a standards section that the code breaks without comment is how
the rest of this document came to be wrong.

- `sqlalchemy_software_repository.py:69` uses an f-string in a `logger.error`
  call, which §13.1 forbids. It is the only such line in the context, and
  `category_repo.py` gets the same ten statements right.
- `local_storage.py:401` and `:491` log the storage key, and
  `software_service.py:209` logs it too. §13.1 gives "no storage paths" as an
  example of what not to log; a storage key is a user-supplied filename rather
  than a path, so it is on the right side of that line — but nobody decided
  that, and a key is one log call away from becoming a path.
- `ruff` would catch the f-string and the 23 unsorted-import findings. See §18.

---

## 14. Naming, and where the code disagrees with the convention

| Concept | Convention | In this context |
|---|---|---|
| **Ports** | Interface name, no suffix | `Storage`, `DownloadSigner`, `MalwareScanner`, `NotificationSender` follow it. `DomainEventPublisher`, `ArtifactStager` and the three repository ports do not. |
| **Implementations** | Descriptive prefix | `LocalStorage`, `LocalHeuristicScanner`, `LocalArtifactStager`, `SystemClock`, `LoggingDomainEventPublisher` follow it. |
| **Repository ports** | `I`-prefix | `ISoftwareRepository`, `ICategoryRepository` follow it. `ArtifactRepository` does not. |
| **Repository implementations** | Technology prefix | `SQLAlchemySoftwareRepository` follows it. `CategoryRepository` does not. |
| **Services** | Noun + `Service` | All five, including `SearchService` and the `SearchAlgorithm` collaborator. |
| **Entities** | Noun, no suffix | `Software`, `Version`, `Artifact`, `Category`. `AggregateRoot` lives in the shared kernel. |
| **Value objects** | Noun, no suffix | `SemVer`, `Money`, `Currency`, `SoftwareCard`, `OwnedSoftwareCard` are in `domain/value_objects/`. `SignedDownloadUrl` is in `domain/ports/download_signer.py`. There is no `Checksum` type — `Artifact.sha256` is a bare `str`. |
| **Events** | Past tense + `Event` | 18 of the 20 concrete events. `ArtifactAddedToVersion` and `ArtifactRemovedFromVersion` have no suffix. |
| **Exceptions** | Noun + `Error` | All 25. |
| **Schemas** | Noun + request/response hint | `SoftwareCreate`, `SoftwareRead`, `SoftwareVersionRead`, `ArtifactResponse`, `CategoryCreate` and the rest. There is no `DownloadResponse`; the download routes return a `RedirectResponse`. |

Never suffix a domain entity with `Model`, `Schema`, `DTO` or `Entity`. Held
throughout `domain/`. The ORM models use the `Model` suffix, but they are shared
infrastructure and deliberately named after the table they map.

**`SoftwareAccessPolicy` is defined twice**, byte-identical apart from a trailing
newline: once at `domain/policies/software_access_policy.py` and once at
`policies/software_access_policy.py`. The `domain/` copy is importable; the `policies/`
copy is not reachable as a package member in a way that distinguishes it, and the
only importer of it is `tests/unit/test_software_access_policy.py` — which
`tests/conftest.py` lists in `collect_ignore`, so it does not run. The policy
therefore has no test and no caller.

Adopting it is a behaviour change, not a cleanup: `ensure_can_download` requires
`status == PUBLISHED` where the live path uses `is_downloadable()` (which also
accepts `DEPRECATED`), and requires `is_public()` even for a buyer. It also takes
a parameter named `owns_software` that a caller would have to pass
`has_purchase` into, so a purchasing-but-not-owning user would be told "Only
active owners may download". Recorded in `docs/REVIEW.md`, Phase 3 and Phase 9a.

---

## 15. Extending this context

### 15.1 A new storage backend

1. Implement `Storage` in `app/infrastructure/storage/`.
2. Add a branch where the adapter is built — `app/modules/shared/container.py`,
   which currently returns a module-level `LocalStorage` singleton.
3. No change to Domain, Application, or routers.

### 15.2 A new malware scanner

1. Implement `MalwareScanner` in
   `app/infrastructure/external_apis/scanner_service/`.
2. Add a branch to `get_malware_scanner()`, which reads
   `settings.MALWARE_SCAN_PROVIDER` and currently accepts only `"local"`.
3. No change to Domain or Application. `SoftwareService._scan_file` already
   accepts a sync or an async scanner via `inspect.iscoroutinefunction`, which is
   what makes this claim hold rather than be aspirational.

### 15.3 Notifications

1. `NotificationSender` already exists as a port. Implement it in
   `app/infrastructure/`.
2. Inject into the service that should notify.
3. The aggregates already record the events; connect them via
   `DomainEventPublisher` rather than adding a second path.

Note that the previous version of this section said to inject the sender into
`SoftwareService`'s constructor, which it does not have and which §11.2 shows is
the wrong port for the job anyway.

### 15.4 Caching

`app/infrastructure/redis/client.py` exists and is wired as `get_redis`, and
nothing in this context uses it. A `CachePort` in `domain/ports/` with a Redis
adapter is the natural shape, and cache at the repository level if the
invalidation story is simpler there.

### 15.5 Search

Already implemented, and the previous version of this section described it as
future work: `ISoftwareRepository.search_candidates` fetches candidates, and
`SearchService` + `SearchAlgorithm` rank them across name, description, popularity
and recency. The candidate fetch is capped at 500 and the ranking is in Python, so
a large corpus is where this would need a real search index.

The five signals are returned by one method, `_score_contributions`, as a mapping
of name to contribution; the score is its sum and `matched_fields` is its keys.
That is the shape Phase 9a changed — the two were derived separately before, and
disagreed, which is what the two long-failing tests in
`tests/unit/test_search_algorithm.py` were about.

`matched_fields` — the list of which signals moved a result's score — is a
debugging and analytics surface and is **not** part of any HTTP response. The
search route returns `items`, `scores`, `total`, `limit` and `offset`. That is
also why the exact-match bonus's case-sensitivity is tolerable to leave in place
for now: the token part of the name signal lowercases both sides, so `?q=MyPackage`
still scores the name match; only the whole-word `name_exact` bonus is lost. The
field that would reveal that is not on the wire, which is why the defect is pinned
by a test rather than fixed: fixing it changes `score`, and `score` is returned by
the search route. See `docs/REVIEW.md`, Phase 9a.

### 15.6 Analytics

`SoftwareDownloadedEvent` is recorded on every download and dispatched by nobody
(§11.2). An analytics adapter behind `DomainEventPublisher` is the whole change
once the dispatch is wired to the download path.

---

## 16. What shipped

This section replaces a "migration path from the current state" that described a
layout — `software/software.py`, `category/application/category_service.py`,
`software_repo.py` — which no longer exists anywhere. Every target it listed has
been reached, except that the adapters for storage, signing and scanning stayed in
the shared `app/infrastructure/` tree, which is a better answer than the one it
proposed.

The record of what was done, and why, is `docs/REVIEW.md` (phases 0–9a) and
`docs/adr/0001`–`0014`. Summarised by phase:

| Phase | Scope |
|---|---|
| 0 | Baseline commit; dependency and artefact hygiene |
| 1 | Layer boundary enforcement (R1–R8, with a shrink-only ratchet); mapper/presenter split |
| 2 | Per-context `UnitOfWork` ports; storage port and exception consolidation |
| 3 | `software_management` brought into line with its own rules; `ArtifactStager`; real domain events |
| 4 | `security` domain model; alerts decided in the domain |
| 5 | `resource` domain model |
| 6a/6b | `user` domain model; `ChatMessage` entity; AI provider port; `User` aggregate |
| 7a/7b | `UserSession` aggregate; composition root split by ownership (ADR 0011); revalidation off the ORM |
| 8 | `admin_router` moved into `security`; `LogTail` port; the ratchet drained to empty |
| 9a | This document corrected against the code; two `search_algorithm` tests re-enabled; `has_purchase` made loud |

The boundary rules, the empty ratchet, and the route-table guard are all
referenced from §3.1 and §18.

---

## 17. Why the design is what it is

### 17.1 Why a separate `DownloadService`?

Downloads are a distinct concern from management. Authorization differs (purchase
check versus owner check), metrics are naturally per-download, and URL signing has
its own lifecycle. The split keeps one authority for the download path rather than
three copies of the same two-line check — a duplication that this context still
has, in `SoftwareService.download_url`, `SoftwareService.download_artifact_url` and
`DownloadService.create_download_url`, which is the actual reason the extraction
has not finished.

### 17.2 Why ports in the domain layer?

Ports define what the domain needs, not how it is delivered. The domain stays
testable without infrastructure, adapters have a stable contract, several adapters
can coexist, and the domain never depends on framework details.

### 17.3 Why services orchestrate rather than entities?

Entities own invariants; services own workflows — opening a transaction, loading
aggregates, calling commands in the right order, dispatching events, translating
infrastructure failures. Keeping them apart is what makes the invariants testable
without a database.

### 17.4 Why are the aggregates not anemic?

`Software` exposes `publish()`, `archive()`, `increment_download_count()` and the
rest, so an invariant cannot be bypassed by assigning to a field.

The counter-example is in the same document: `Category` is a typed record with two
invariants enforced by its service, because both are properties of a set rather
than of one member of it. The right conclusion was not "make Category anemic" but
"Category is not an aggregate root, and should not pretend to be".

### 17.5 Why do mappers live in infrastructure?

They translate between the persistence model and the domain model, so they depend
on both. ADR 0002 moved them out of the shared kernel, which had made anything
importing a shared helper silently acquire a dependency on this context's
entities. `category_repo.py` inlining its two mapper functions is the remaining
inconsistency with this principle.

### 17.6 Why is CQRS optional?

`application/commands/`, `queries/` and `dto/` do not exist, and are not
planned. Read-heavy endpoints can gain read-model projections without changing the
write model, but nothing in this context needs it, and an empty package tree is
worse than no package tree.

### 17.7 Why does dispatch happen in the application service?

Aggregates record; only the application service knows when the transaction has
committed. Dispatching from the aggregate would publish facts that a later
rollback could retract.

---

## 18. Quality gates

What is enforced, and what is not. The previous version of this section listed
five gates and three of them were not enforced by anything.

| Gate | Enforced? | By |
|---|---|---|
| Domain imports no framework, ORM, driver or pydantic | **yes** | R1, R3 — AST, in CI |
| No cross-context `domain/` import except via a port reader | **yes** | R2 — AST, in CI |
| Application imports no `api`/`schema`/`infrastructure` | **yes** | R4 — AST, in CI |
| No ORM model in an application service | **yes** | R5 — AST, in CI |
| No SQLAlchemy statement in a router | **yes** | R6 — AST, in CI |
| No cross-context `api/` import | **yes** | R7 — AST, in CI |
| No framework, ORM or filesystem in a service | **yes** | R8 — AST, in CI |
| Request path imports no ORM model | **yes** | `test_request_path_has_no_orm_models.py` |
| No port member silently defaulted by inheritance | **yes** | `test_ports_have_no_silent_defaults.py` (Phase 9a) |
| Route table unchanged | **yes** | `test_public_http_surface.py` |
| This document matches the code | **yes** | `test_architecture_doc_matches_code.py` (Phase 9a) |
| **`mypy --strict`** | **no** | mypy is not installed, has no config file, is not in `requirements.txt`, and no CI job runs it. `test_ports_have_no_silent_defaults.py` and this document's guard use `# type: ignore` where a real type checker would object. |
| **`ruff` clean** | **no** | ruff is not in `requirements.txt` and there is no `pyproject.toml`, `ruff.toml` or `setup.cfg` — it was found on a developer's machine, not configured for anyone. A bare `ruff check app/modules/software_management` reports 111 findings: 65 `B008` (`Depends()` in a default argument — the FastAPI idiom), 23 `I001` (unsorted imports), 5 `UP035`, 3 `BLE001`, 3 `RUF022`, 3 `UP006`, 2 each of `TRY401`, `UP037` and `UP045`, and one each of `F541`, `PIE790` and `PYI013`. The three `BLE001` are the blind excepts in §12.3 and §15.5's search path. |
| **Async I/O everywhere** | **no, and not the design** | Repositories are async. `Storage` and `ArtifactStager` are synchronous by design, with `asyncio.to_thread` at the call sites, because blocking file I/O in a coroutine stalls every other in-flight request on the worker — the same defect Phase 6a found in the support-chat adapter. `LocalHeuristicScanner` is synchronous and the port declares it async, which is why `_scan_file` inspects it. |
| **Test coverage of domain invariants** | **partly** | The gaps found in Phase 9a: `Category`'s two invariants (`DuplicateCategoryError` and `CategoryInUseError` have no test at all), `Artifact.verify_integrity` (never exercised, in `app/` or in `tests/`), and every download path, which is tested only against hand-written fakes in `test_sms_lifecycle.py` and never against a real repository. |

CI runs three jobs: `pytest`, the layer rules, and `alembic check` for
un-migrated models. It does not run a type checker or a linter, because neither is
configured.

---

## 19. Summary

- **Stability**: domain logic changes rarely; adapters change often.
- **Testability**: the domain is testable with no framework, and is tested that
  way.
- **Extensibility**: a new storage backend or scanner is an adapter and a factory
  branch, and `SoftwareService` already tolerates both scanner shapes.
- **Honesty**: the parts of this design that are not finished — the two
  translation layers that disagree, the events nobody dispatches, the policy nobody
  calls, the routers that build their own unit of work, the gates that are not
  enforced — are named above rather than described as if they were working.

`authentication`, `security`, `resource` and `user` follow this structure.
`analytics` and `designs` do not yet, and `docs/REVIEW.md` records where each
diverges and why.
