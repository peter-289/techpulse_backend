# Software Management Module — Reference Architecture

## 1. Vision

The Software Management module is the **reference architecture** for all TechPulse modules. It applies Domain-Driven Design, Clean Architecture, and Hexagonal (Ports & Adapters) principles to ensure the marketplace core remains stable while infrastructure, integrations, and delivery mechanisms evolve independently.

This document defines the **target structure, layer boundaries, aggregate design, port contracts, and migration path** from the current codebase to the reference architecture.

---

## 2. Target Directory Structure

```
software_management/
├── api/
│   ├── routers/
│   │   ├── software_router.py
│   │   ├── category_router.py
│   │   └── download_router.py
│   ├── dependencies.py
│   ├── errors.py
│   └── __init__.py
│
├── application/
│   ├── services/
│   │   ├── software_service.py
│   │   ├── category_service.py
│   │   └── download_service.py
│   ├── commands/
│   ├── queries/
│   ├── dto/
│   ├── mappers.py
│   └── __init__.py
│
├── domain/
│   ├── entities/
│   │   ├── software.py
│   │   ├── version.py
│   │   ├── artifact.py
│   │   └── category.py
│   ├── value_objects/
│   ├── events/
│   ├── policies/
│   ├── ports/
│   │   ├── repositories/
│   │   │   ├── software_repository.py
│   │   │   ├── category_repository.py
│   │   │   └── artifact_repository.py
│   │   ├── storage.py
│   │   ├── download_signer.py
│   │   ├── malware_scanner.py
│   │   └── notification_sender.py
│   ├── exceptions.py
│   └── __init__.py
│
├── infrastructure/
│   ├── persistence/
│   │   ├── models/
│   │   ├── repositories/
│   │   └── mappers/
│   ├── storage/
│   │   ├── local_storage.py
│   │   └── s3_storage.py
│   ├── signing/
│   │   └── hmac_download_signer.py
│   ├── scanners/
│   │   └── clamav_scanner.py
│   └── notifications/
│
├── schema/
│   ├── software_schema.py
│   ├── category_schema.py
│   └── download_schema.py
│
├── ARCHITECTURE.md
└── __init__.py
```

---

## 3. Layer Responsibilities & Dependency Rules

### 3.1 Dependency Direction

Always inward. No reverse dependencies.

```
api  ──▶  application  ──▶  domain  ◀──  infrastructure
                                ▲
                                │
                         (ports only)
```

- **API** depends on Application, Schema, and FastAPI.
- **Application** depends on Domain (entities, value objects, ports, exceptions, policies, events).
- **Domain** depends on **nothing** from the project or external frameworks.
- **Infrastructure** depends on Domain (implements Domain ports) and external libraries (SQLAlchemy, boto3, etc.).

### 3.2 API Layer

Responsible for:
- FastAPI route definitions
- Request validation (Pydantic schemas)
- Authentication / authorization extraction
- Dependency injection assembly
- Pagination, filtering, sorting
- HTTP response mapping (including OpenAPI metadata)

Must never contain business logic, orchestration, or repository calls.

### 3.3 Application Layer

Responsible for:
- Use-case orchestration
- Transaction boundaries (Unit of Work)
- Authorization policy enforcement
- Domain command execution
- Domain event dispatching
- Cross-aggregate coordination (e.g., Software + Billing + Notifications)

Must never import SQLAlchemy models, FastAPI types, or filesystem APIs.

### 3.4 Domain Layer

Responsible for:
- Business invariants
- Aggregate consistency rules
- Entity behavior (never anemic models)
- Value object validation
- Domain event definitions
- Policy definitions
- Port (interface) definitions for external dependencies

Zero dependencies on:
- FastAPI
- SQLAlchemy / ORM frameworks
- Pydantic
- HTTP libraries
- Filesystem APIs
- Cloud SDKs

### 3.5 Infrastructure Layer

Responsible for:
- Persistence (SQLAlchemy models, repository implementations, mappers)
- Storage backends (local filesystem, S3, Azure Blob)
- Cryptographic signing
- Malware scanning integrations
- Notification delivery (email, push, webhooks)

Contains no business rules. All orchestration lives in Application services.

### 3.6 Schema Layer

Responsible for:
- Transport models (Pydantic)
- Input validation
- Output serialization
- OpenAPI documentation hints

Must never contain business logic.

---

## 4. Aggregate Boundaries

### 4.1 Software (Aggregate Root)

Owns:
- Identity (`id`)
- Metadata (`name`, `description`, `owner_id`, `category_id`)
- State (`status`, `visibility`, `access_type`)
- Pricing (`price`)
- Versions collection (invariant: no duplicate semantic versions)
- Download counter (`download_count`)
- Domain events list

**Invariants:**
- Software must be `ACTIVE` to be modifiable.
- A version cannot be added if its `SemVer` already exists.
- `download_count` is cumulative; never negative.
- Archived/Deleted software cannot accept new versions or publish.

**Behavior (methods exposed on aggregate):**
- `create(...)` — factory
- `rename(name)`
- `update_description(description)`
- `change_visibility(visibility)`
- `change_access_policy(access_type)`
- `update_pricing(price_cents, currency)`
- `publish()`
- `archive()`
- `mark_deleted(actor_id, marked_at)`
- `restore()`
- `add_version(version)`
- `get_version(version_id)` — query
- `get_version_by_semver(semver)` — query
- `publish_version(version_id)`
- `deprecate_version(version_id)`
- `revoke_version(version_id)`
- `remove_version(version_id)`
- `increment_download_count()`
- `latest_downloadable()`
- `published_versions()`
- `pull_events()`

**Intent-revealing queries:**
- `is_owned_by(actor_id)`
- `is_public()`
- `is_active()`
- `is_archived()`
- `is_deleted()`
- `requires_payment()`
- `has_versions()`
- `has_downloadable_versions()`

### 4.2 Version (Entity inside Software aggregate)

Owns:
- `id`, `software_id`, `number` (SemVer)
- `release_notes`, `status`, `lock_version`
- `download_count`
- `published_at`, `created_at`, `updated_at`
- `artifact` reference

**Invariants:**
- A published version must have an artifact in `ACTIVE` status.
- A revoked version cannot be published.
- Only `PUBLISHED` or `DEPRECATED` versions are downloadable.

**Behavior:**
- `attach_artifact(artifact)`
- `publish()`
- `deprecate()`
- `revoke()`
- `is_downloadable()`
- `_touch()`

### 4.3 Artifact (Entity inside Version / Software aggregate)

Owns:
- `id`, `version_id`, `storage_key`
- `sha256`, `size_bytes`, `mime_type`, `filename`
- `status`, `quarantine_reason`
- Timestamps

**Invariants:**
- Artifact status cannot be `ACTIVE` after `DELETED`.
- Integrity checksum must match upload hash.

**Behavior:**
- `verify_integrity(computed_hash_sha256)`
- `process_malware_scan_success(event)`
- `process_malware_scan_failed(event)`
- `soft_delete(at)`

### 4.4 Category (Aggregate Root)

Owns:
- `id`, `name`, `description`
- `is_deleted` flag

**Behavior:**
- `create(name, description)`
- `rename(name)`
- `update_description(description)`
- `soft_delete()`
- `restore()`
- `is_deleted()`

**Invariants:**
- Category name is unique (case-insensitive).
- Categories with assigned software cannot be deleted.

---

## 5. Repository Boundaries

### 5.1 Port Definitions (Domain Layer)

Repository interfaces live in `domain/ports/repositories/`.

```python
class SoftwareRepository(Protocol):
    async def get(self, software_id: UUID) -> Software | None: ...
    async def save(self, software: Software) -> None: ...
    async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool: ...
    async def list_marketplace(self, *, limit, offset) -> list[SoftwareCard]: ...
    async def list_owned(self, owner_id: UUID, *, limit, offset) -> tuple[list[OwnedSoftwareCard], int]: ...
    async def soft_delete(self, software_id: UUID) -> None: ...
    async def search_candidates(self, query, *, category_id, tags, limit) -> list[Software]: ...
```

```python
class CategoryRepository(Protocol):
    async def get(self, category_id: UUID) -> Category | None: ...
    async def save(self, category: Category) -> None: ...
    async def exists(self, name: str) -> bool: ...
    async def find_by_name(self, name: str) -> Category | None: ...
    async def rename(self, category_id: UUID, name: str) -> None: ...
    async def soft_delete(self, category_id: UUID) -> None: ...
    async def restore(self, category_id: UUID) -> None: ...
    async def list_categories(self, *, limit, offset, include_deleted) -> tuple[list[Category], int]: ...
    async def count_software(self, category_id: UUID) -> int: ...
```

```python
class ArtifactRepository(Protocol):
    async def get(self, artifact_id: UUID) -> Artifact | None: ...
    async def save(self, artifact: Artifact) -> None: ...
```

### 5.2 Implementation Rules

- Implementations live in `infrastructure/persistence/repositories/`.
- Concrete classes implement the port protocol.
- Concrete classes translate between domain entities and ORM models via **mappers**.
- Repositories raise **domain exceptions** (e.g., `SoftwareNotFoundError`, `RepositoryUnavailableError`). They never raise SQLAlchemy exceptions or HTTPException.
- Repositories never dispatch events, send notifications, or generate URLs.

### 5.3 Mappers

Mappers live in `infrastructure/persistence/mappers/` (or `application/mappers.py` if shared across modules).

Responsibilities:
- Convert ORM models → Domain entities
- Convert Domain entities → ORM models
- Preserve aggregate invariants during conversion
- Handle `download_count`, timestamps, enums safely

---

## 6. Application Service Boundaries

### 6.1 SoftwareService

Coordinates the full Software lifecycle:
- Upload / create software with initial version
- Upload additional versions
- Manage pricing and visibility
- Deprecate / revoke versions
- Generate download URLs (orchestrates authorization + signing)
- Delete, archive, restore

**Does NOT:**
- Perform filesystem I/O
- Stream HTTP responses
- Map to HTTP responses
- Access SQLAlchemy directly

### 6.2 CategoryService

Coordinates category CRUD:
- Create, rename, update description
- Soft delete, restore
- List with pagination
- Enforce uniqueness and assignment checks

### 6.3 DownloadService

Dedicated authority for downloads:
- `create_download_url(software_id, version_number, user_id)` → `SignedDownloadUrl`
  - Authorization (public / owner / purchased)
  - Version validation (exists, downloadable, has artifact)
  - Signed URL generation
- `record_download(software_id, version_id?)` → None
  - UoW transaction
  - Increment `download_count`
  - Persist aggregate
  - Pull events

**Key design choice:** DownloadService is separated from SoftwareService to:
- Keep download logic focused on a single responsibility.
- Allow independent scaling, caching, and metrics.
- Future-proof for per-download analytics, rate limiting, and webhook delivery.

---

## 7. Port Definitions (Hexagonal Architecture)

All external dependencies are abstracted as **ports** in `domain/ports/`.

### 7.1 Storage

```python
class Storage(Protocol):
    async def create_download_url(self, storage_key: str, expires_in: int) -> str: ...
    def exists(self, *, storage_key: str) -> bool: ...
```

### 7.2 DownloadSigner

```python
class DownloadSigner(Protocol):
    def create_url(self, *, storage_key: str, expires_in: int) -> str: ...
    def verify_token(self, *, storage_key: str, expires: int, token: str, method: str) -> bool: ...
```

### 7.3 MalwareScanner

```python
class MalwareScanner(Protocol):
    async def scan_file(self, *, file_path: Path, filename: str, sha256: str, content_type: str) -> ScanResult: ...
```

### 7.4 NotificationSender

```python
class NotificationSender(Protocol):
    async def send(self, *, recipient_id: UUID, event: DomainEvent, channels: list[str]) -> None: ...
```

**Rule:** Application services depend only on these protocols. FastAPI `Depends()` wires concrete implementations at the API boundary.

---

## 8. Infrastructure Adapter Responsibilities

### 8.1 Persistence

| Component | Responsibility |
|-----------|---------------|
| `SQLAlchemySoftwareRepository` | Implements `SoftwareRepository` using SQLAlchemy async sessions |
| `SQLAlchemyCategoryRepository` | Implements `CategoryRepository` |
| `SoftwareMapper` | Maps `SoftwareModel` ↔ `Software` aggregate |
| `CategoryMapper` | Maps `CategoryModel` ↔ `Category` aggregate |
| `ArtifactMapper` | Maps `SoftwareArtifactModel` ↔ `Artifact` entity |

### 8.2 Storage

| Component | Responsibility |
|-----------|---------------|
| `LocalStorage` | Filesystem-backed `Storage` implementation |
| `S3Storage` | AWS S3-backed `Storage` implementation |
| Migrating between them requires **zero changes** to Domain or Application |

### 8.3 Signing

| Component | Responsibility |
|-----------|---------------|
| `HmacDownloadSigner` | HMAC-SHA256 signed URL generation and verification |
| `JwtDownloadSigner` | Future JWT-based signed payloads (if needed) |

### 8.4 Scanning

| Component | Responsibility |
|-----------|---------------|
| `ClamAVScanner` | Local ClamAV integration |
| `VirusTotalScanner` | Future cloud-based scanning |
| `HeuristicScanner` | Future ML-based heuristic scanning |

Adapters implement the `MalwareScanner` protocol. Application service `SoftwareService.upload_package` calls the scanner without knowing which one is wired.

### 8.5 Notifications

| Component | Responsibility |
|-----------|---------------|
| `EmailNotificationSender` | Email delivery |
| `WebhookNotificationSender` | HTTP webhook delivery |
| `PushNotificationSender` | Mobile push delivery |

---

## 9. Dependency Injection Strategy

### 9.1 Composition Root

FastAPI `dependencies.py` is the composition root. It assembles concrete implementations and exposes them via `Depends()`.

```python
async def get_storage() -> Storage:
    settings = get_storage_settings()
    if settings.backend == "local":
        return LocalStorage(settings=settings)
    if settings.backend == "s3":
        return S3Storage(settings=settings)
    raise ConfigurationError("Unsupported storage backend.")

async def get_signer() -> DownloadSigner:
    settings = get_signer_settings()
    return HmacDownloadSigner(settings=settings)

async def get_scanner() -> MalwareScanner:
    if settings.scanner_backend == "clamav":
        return ClamAVScanner(settings=settings.scanner)
    if settings.scanner_backend == "heuristic":
        return HeuristicScanner()
    return NoOpScanner()

async def get_software_service(
    uow: UnitOfWork = Depends(get_uow),
    storage: Storage = Depends(get_storage),
    signer: DownloadSigner = Depends(get_signer),
    scanner: MalwareScanner = Depends(get_scanner),
) -> SoftwareService:
    return SoftwareService(
        uow=uow,
        storage=storage,
        signer=signer,
        scanner=scanner,
    )
```

### 9.2 Rules

- Application services receive dependencies via **constructor injection**.
- FastAPI routers depend on application services via `Depends()`.
- No `ServiceLocator` anti-pattern.
- Configuration flows from environment → settings → factories → services.

---

## 10. Transaction Management Strategy

### 10.1 Unit of Work

The `UnitOfWork` manages async database transactions.

```python
class UnitOfWork:
    def __init__(self, session: AsyncSession): ...
    @property
    def software_repo(self) -> SoftwareRepository: ...
    @property
    def category_repo(self) -> CategoryRepository: ...
    @property
    def artifact_repo(self) -> ArtifactRepository: ...

    async def __aenter__(self) -> "UnitOfWork": ...
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None: ...
```

### 10.2 Usage Pattern

Application services control transaction boundaries.

```python
async def upload_package(self, ...):
    async with self._uow:
        software = Software.create(...)
        version = Version(...)
        software.add_version(version)
        await self._uow.software_repo.save(software)
        # Commit happens automatically on clean exit
```

### 10.3 Read-Only Transactions

For queries that only read data:

```python
async with self._uow.read_only():
    software = await self._uow.software_repo.get(software_id)
```

### 10.4 Error Semantics

- Exceptions inside `async with self._uow:` trigger automatic rollback.
- Infrastructure exceptions (`SQLAlchemyError`) are caught in the Application service and translated to domain exceptions (`RepositoryUnavailableError`).
- Domain exceptions propagate unchanged to the API exception handlers.

---

## 11. Event Flow

### 11.1 Production

1. Aggregate method appends a domain event to `_events`.
2. Application service calls `aggregate.pull_events()` after persistence.
3. Application service passes events to an **outbound port** (`NotificationSender`, `EventBus`).
4. Infrastructure adapter handles delivery (email, push, webhook, message queue).

```python
# inside Application service
events = software.pull_events()
for event in events:
    await self._notification_sender.send(event=event, recipient_id=software.owner_id)
```

### 11.2 Event Types

| Event | Emitted By | Carries |
|-------|-----------|---------|
| `SoftwareCreated` | `Software.create()` | `software_id`, `owner_id` |
| `VersionPublished` | `Software.publish_version()` | `software_id`, `version_id` |
| `ArtifactUploaded` | `Version.attach_artifact()` | `version_id`, `artifact_id`, `storage_key` |
| `SoftwareDownloaded` | `Software.increment_download_count()` | `software_id` |

### 11.3 Rules

- Aggregates **emit** events. They never publish, queue, or deliver them.
- Application services **dispatch** events.
- Infrastructure adapters **deliver** events.
- Event dispatching is idempotent where possible (at-least-once delivery).

---

## 12. Error Handling Strategy

### 12.1 Domain Layer

Raises domain exceptions defined in `domain/exceptions.py`.

```python
class SoftwareDomainError(Exception): ...
class SoftwareNotFoundError(SoftwareDomainError): ...
class SoftwareAccessDeniedError(SoftwareDomainError): ...
class InvalidStateTransitionError(SoftwareDomainError): ...
class RepositoryUnavailableError(SoftwareDomainError): ...
```

### 12.2 Application Layer

- Catches infrastructure exceptions (e.g., `SQLAlchemyError`) and translates them to domain exceptions (`RepositoryUnavailableError`).
- Allows domain exceptions to propagate unchanged.
- Never raises `HTTPException` or framework-specific errors.

### 12.3 API Layer

- Maps domain exceptions to HTTP responses via FastAPI exception handlers.
- Never catches and swallows exceptions silently.
- Logs context (never secrets) before re-raising or responding.

```python
@app.exception_handler(SoftwareNotFoundError)
async def software_not_found_handler(request: Request, exc: SoftwareNotFoundError):
    raise HTTPException(status_code=404, detail=str(exc))
```

### 12.4 Translation Map

| Infrastructure Exception | Domain Exception |
|-------------------------|------------------|
| `SQLAlchemyError` | `RepositoryUnavailableError` |
| `StorageFileNotFoundError` | `ArtifactNotFoundError` |
| `StorageSecurityError` | `SoftwareAccessDeniedError` |
| `MalwareScanError` | `MalwareScanPendingError` |

---

## 13. Logging Strategy

### 13.1 Principles

- **Structured logging**: use key=value pairs or JSON.
- **Lazy formatting**: use `%s` style with argument tuples, never f-strings with secrets.
- **Context propagation**: include `software_id`, `version_id`, `user_id` in logs.
- **No secrets**: never log tokens, signed URLs, storage paths, API keys, or raw file contents.

### 13.2 Layer Logging Rules

| Layer | Logs |
|-------|------|
| **Domain** | **Nothing.** Aggregates are silent. |
| **Application** | Use case start/end, authorization decisions, event dispatch |
| **Infrastructure** | External integration attempts, retries, failures |
| **API** | Request/response metadata (excluding bodies with secrets) |

### 13.3 Examples

```python
# Application service
logger.info(
    "download_url_generated software=%s version=%s user=%s",
    software_id, version_number, user_id,
)

# Infrastructure
logger.info("storage_uploaded storage_key=%s size=%d", key, size)
```

### 13.4 Anti-Patterns

```python
# WRONG
logger.info(f"URL={signed_url}")  # leaks secret token
logger.info(f"Path={storage_path}")  # leaks internal path
```

---

## 14. Naming Conventions

| Concept | Convention | Example |
|---------|-----------|---------|
| **Ports** | Interface name, no suffix | `Storage`, `DownloadSigner`, `MalwareScanner` |
| **Implementations** | Descriptive prefix | `LocalStorage`, `S3Storage`, `HmacDownloadSigner`, `ClamAVScanner` |
| **Repositories** | Aggregate + `Repository` | `SoftwareRepository`, `CategoryRepository` |
| **Implementations** | Technology prefix | `SQLAlchemySoftwareRepository`, `SQLAlchemyCategoryRepository` |
| **Services** | Noun + `Service` | `SoftwareService`, `CategoryService`, `DownloadService` |
| **Entities** | Noun, no suffix | `Software`, `Version`, `Artifact`, `Category` |
| **Value Objects** | Noun, no suffix | `SemVer`, `Money`, `Checksum`, `SignedDownloadUrl` |
| **Events** | Past tense + `Event` | `SoftwareCreated`, `VersionPublished`, `SoftwareDownloaded` |
| **Policies** | Noun + `Policy` | `SoftwareAccessPolicy`, `PublishingPolicy` |
| **Exceptions** | Noun + `Error` | `SoftwareNotFoundError`, `SoftwareAccessDeniedError` |
| **Schemas** | Noun + request/response hint | `SoftwareCreate`, `SoftwareRead`, `DownloadResponse` |

**Never suffix entities with:** `Model`, `Schema`, `DTO`, `Entity`.

---

## 15. Extensibility Mechanisms

### 15.1 Adding a New Storage Backend

1. Implement `domain/ports/storage.Storage` in `infrastructure/storage/azure_blob_storage.py`.
2. Add a factory branch in `api/dependencies.py`.
3. **Zero changes** to Domain, Application, or API routers.

### 15.2 Adding a New Malware Scanner

1. Implement `MalwareScanner` protocol in `infrastructure/scanners/sophos_scanner.py`.
2. Add configuration in settings.
3. **Zero changes** to Domain or Application.

### 15.3 Adding Notifications

1. Add `NotificationSender` port to `domain/ports/`.
2. Implement adapters in `infrastructure/notifications/`.
3. Inject into `SoftwareService` constructor.
4. Aggregate emits events; service dispatches to sender.

### 15.4 Adding Caching

1. Add `CachePort` protocol to `domain/ports/`.
2. Implement `RedisCache` in infrastructure.
3. Application service reads/writes through port.
4. Alternatively, cache at the repository level (infrastructure concern only).

### 15.5 Adding Search / Recommendations

1. Add `SearchRepository` port.
2. Implement `ElasticsearchSearchRepository` in infrastructure.
3. Add `SearchService` in Application layer.
4. Domain remains untouched.

### 15.6 Adding Analytics

1. Domain emits `SoftwareDownloadedEvent`.
2. Application service dispatches event to analytics adapter.
3. Analytics module subscribes to events via outbound port.
4. **Zero changes** to Software aggregate.

---

## 16. Migration Path from Current State

### 16.1 Current State Assessment

| Current File | Issue | Target Location |
|--------------|-------|----------------|
| `software/software.py` | Domain entity (good) | `domain/entities/software.py` |
| `software/version.py` | Domain entity (good) | `domain/entities/version.py` |
| `software/artifact.py` | Domain entity (good) | `domain/entities/artifact.py` |
| `software/exceptions.py` | Domain exceptions (good) | `domain/exceptions.py` |
| `software/events.py` | Domain events (good) | `domain/events/` |
| `software/value_objects.py` | Value objects (good) | `domain/value_objects/` |
| `policies/software_access_policy.py` | Domain policy (good) | `domain/policies/` |
| `software_service.py` | Mixed: application + some logic | `application/services/software_service.py` |
| `category/application/category_service.py` | Application service (good) | `application/services/category_service.py` |
| `software_repo.py` | Interface + implementation mixed | `domain/ports/repositories/software_repository.py` + `infrastructure/persistence/repositories/sqlalchemy_software_repository.py` |
| `infrastructure/storage/local_storage.py` | Mixed old/new APIs | `infrastructure/storage/local_storage.py` + `domain/ports/storage.py` |
| `software_router.py` | API router (good) | `api/routers/download_router.py` + `api/routers/software_router.py` |
| `software_schema.py` | Transport models (good) | `schema/software_schema.py` |
| Category models | In `category/domain/` | Keep but move to `domain/entities/` |

### 16.2 Migration Order

**Phase 1: Define Ports (No Behavior Change)**
1. Move domain exceptions to `domain/exceptions.py`.
2. Move domain events to `domain/events/`.
3. Define port protocols in `domain/ports/`.
4. Extract `Storage`, `DownloadSigner`, `MalwareScanner` ports.

**Phase 2: Extract Application Services (Thin Wrappers)**
1. Create `application/services/download_service.py` (already exists).
2. Refactor `SoftwareService` to depend only on ports.
3. Split `SoftwareService` into smaller services if needed (e.g., `PublishingService`).

**Phase 3: Separate Repository Interface from Implementation**
1. Move `ISoftwareRepository` ABC to `domain/ports/repositories/software_repository.py`.
2. Rename `SoftwareRepository` to `SQLAlchemySoftwareRepository` in `infrastructure/persistence/repositories/`.
3. Repeat for Category.

**Phase 4: Reorganize Directories**
1. Move `domain/*` files to `software_management/domain/*`.
2. Move `infrastructure/*` files to `software_management/infrastructure/*`.
3. Move `api/*` files to `software_management/api/*`.
4. Update import paths incrementally.

**Phase 5: Enforce Boundaries**
1. Add import-linting rules (e.g., `ruff` with custom rules or `import-linter`).
2. Validate that Domain layer has zero framework imports.
3. Validate that Application layer has zero ORM imports.

**Phase 6: Add Missing Elements**
1. Add `application/dto/` for command/query data shapes if CQRS is desired.
2. Add `application/queries/` for read model projections.
3. Add `application/commands/` if switching to command pattern.
4. Add `domain/value_objects/` subpackage.
5. Add `domain/policies/` subpackage.

---

## 17. Decision Justifications

### 17.1 Why Separate DownloadService?

Downloads are a distinct bounded context concern:
- Authorization logic differs from management (purchase check vs owner check).
- Metrics and analytics are naturally tied to downloads.
- URL signing has its own lifecycle (expiry, rotation, verification).
- Future requirements (rate limiting, CDN, geo-restriction) apply only to downloads.
- Separation of concerns enables independent testing and deployment of download logic.

### 17.2 Why Ports in the Domain Layer?

Ports define **what the domain needs**, not **how it is delivered**. Placing them in the Domain layer ensures:
- The domain model is fully testable without infrastructure.
- Infrastructure adapters implement stable, versioned contracts.
- Multiple adapters can coexist (e.g., local + S3 storage).
- The domain never depends on framework details.

### 17.3 Why Application Services Orchestrate, Not Entities?

Entities own **invariants** (state rules). They do not own **workflows** (sequence of steps). Application services coordinate:
- Opening a transaction.
- Loading multiple aggregates.
- Calling aggregate methods in the correct order.
- Dispatching events.
- Handling translation of infrastructure failures.

This keeps entities focused and testable.

### 17.4 Why Aggregates Are Not Anemic?

Anemic domain models (entities with only getters/setters) push business logic into services, breaking encapsulation. TechPulse aggregates expose **behavioral methods** (`publish()`, `archive()`, `increment_download_count()`). This ensures invariants cannot be bypassed.

### 17.5 Why Mappers Live in Infrastructure?

Mappers translate between **persistence models** (ORM) and **domain models**. They depend on both the infrastructure ORM and the domain entities. Placing them in infrastructure keeps the domain pure. The Application layer uses them indirectly via repositories.

### 17.6 Why CQRS Is Optional

The structure supports CQRS (`commands/`, `queries/`, `dto/`) without requiring it. For read-heavy endpoints (listing software, search), read-optimized queries can be added later without changing the write model.

### 17.7 Why Event Dispatching Happens in Application Services

Aggregates emit events but do not know about external systems. Application services are the correct place to:
- Pull events from aggregates after persistence.
- Route events to notification adapters, message queues, or webhooks.
- Ensure events are only dispatched after successful commits.

This maintains the aggregate's purity and prevents side effects during state transitions.

---

## 18. Quality Gates

To maintain the architecture, enforce:

1. **Import Linting**: Domain layer imports only from `stdlib`, `uuid`, `datetime`, `typing`.
2. **Mypy Strict**: All layers pass strict type checking.
3. **Async I/O**: All repository, storage, and scanner methods are async.
4. **No Framework Leakage**: `SQLAlchemyError`, `HTTPException`, and `Pydantic` models never appear in Domain or Application layers.
5. **Test Coverage**: Unit tests for domain invariants, integration tests for infrastructure adapters.

---

## 19. Summary

This architecture ensures:
- **Stability**: Domain logic changes rarely; infrastructure changes often.
- **Testability**: Pure domain entities are trivially unit-testable.
- **Extensibility**: New storage, scanners, and notification channels require only new adapters.
- **Maintainability**: Clear boundaries prevent accidental coupling.
- **Performance**: Read/write separation and caching fit naturally.

Every other TechPulse module (Billing, Auth, Resources, Analytics, AI Integration) should follow this exact structure and set of conventions.
