# Software Management System (SMS)

High-performance async Software Management System module for package upload, publish, download, and delete operations.

## Overview

SMS is implemented as a clean-architecture module under `software_management/` with strict dependency direction:

- `domain` -> framework-free business model and invariants.
- `application` -> use cases + interfaces + DTO contracts.
- `infrastructure` -> async SQLAlchemy persistence + async storage + adapters.
- `presentation` -> FastAPI router and boundary validation.
- `bootstrap.py` -> manual dependency composition.

## Folder Structure

```text
software_management/
  domain/
    aggregates.py
    entities.py
    events.py
    repositories.py
    value_objects.py
  application/
    dtos.py
    errors.py
    interfaces.py
    use_cases.py
  infrastructure/
    access_control.py
    db.py
    models.py
    repository.py
    storage.py
    virus_scanner.py
  presentation/
    router.py
    schemas.py
  bootstrap.py
```

## Runtime Integration

SMS is integrated in the main app lifecycle:

- Built at startup composition time in `app/main.py`.
- Schema validated through `await sms_module.initialize()` (migrations must be applied first).
- Router mounted through `app.include_router(sms_module.router)`.
- Async engine disposed via `await sms_module.close()` on shutdown.

## API Endpoints

Base path: `/api/v1/software-management`

1. `POST /upload`
- Multipart upload endpoint.
- Streams file in chunks; does not load full file in memory.
- Inputs:
  - Form: `software_name`, `software_description`, `version`, `publish_now`, optional `software_id`
  - File: `file`
  - Header: optional `If-Match-Row-Version` (optimistic locking)
- Returns: `software_id`, `version_id`, `artifact_id`, `version`, `file_hash`, `size_bytes`, `software_row_version`, `published`

2. `POST /{software_id}/versions/{version}/publish`
- Publishes an existing version.
- Header: optional `If-Match-Row-Version`
- Returns publish metadata and updated row version.

3. `GET /{software_id}/versions/{version}/download`
- Streams artifact bytes.
- Response headers include `Content-Length`, `ETag`, and `Content-Disposition`.

4. `DELETE /{software_id}`
- Deletes software and associated versions/artifacts.
- Header: optional `If-Match-Row-Version`
- Returns deletion counts.

## Data Model

Tables:

- `sms_softwares`
  - PK: `id` (UUID)
  - Unique: `(owner_id, name)`
  - Indexed: `owner_id`, `created_at`
  - Optimistic lock: `row_version`

- `sms_versions`
  - PK: `id` (UUID)
  - FK: `software_id -> sms_softwares.id` (cascade delete)
  - FK: `artifact_id -> sms_artifacts.id` (cascade delete)
  - Unique: `(software_id, version)`
  - Indexed: `software_id`, `(software_id, version)`, `created_at`

- `sms_artifacts`
  - PK: `id` (UUID)
  - Unique: `storage_key`
  - Indexed: `file_hash`, `created_at`

## Concurrency Model

- Upload/Publish/Delete write paths use DB transactions.
- Version uniqueness is guaranteed by DB unique constraints.
- Optimistic concurrency is enforced with `If-Match-Row-Version`.
- `SELECT ... FOR UPDATE` is used for owner/software/version write contention points.

## Storage Behavior

- Local async storage implementation using `aiofiles`.
- Upload and download are chunked streaming.
- No full-file buffering in memory.
- SHA-256 hash is computed during upload.

## Security and Access Control

- Access control is enforced via `AccessControlAdapter`.
- Current actor is provided by app auth dependency (`get_current_user`).
- Virus scanning adapter exists and is async-stream capable.

## Configuration

Used from existing app settings:

- `DATABASE_URL`
- `UPLOAD_ROOT`
- `PACKAGE_UPLOAD_CHUNK_SIZE_BYTES`
- `PACKAGE_UPLOAD_MAX_SIZE_BYTES`
- `PACKAGE_UPLOAD_RATE_LIMIT`
- `PACKAGE_UPLOAD_RATE_WINDOW_SECONDS`
- `PACKAGE_DOWNLOAD_RATE_LIMIT`
- `PACKAGE_DOWNLOAD_RATE_WINDOW_SECONDS`
- `DB_POOL_SIZE`
- `DB_MAX_OVERFLOW`
- `DB_POOL_TIMEOUT`
- `DB_POOL_RECYCLE`

SMS storage root defaults to:

- `<UPLOAD_ROOT>/software_management`

## Production Readiness Checklist

Current status: **Partially ready**. Core architecture and async streaming are in place, but complete production hardening still needs these:

1. Add Alembic migrations for `sms_*` tables.
- Done. SMS tables are created by Alembic migration `20260304_0007_sms_cutover_tables.py`.
- Runtime now validates schema presence and expects migrations to be applied.

2. Add explicit upload size limits and request throttling.
- Done. Max artifact size is enforced at API boundary and storage layer.
- Done. Upload/download endpoints now enforce request rate limits.

3. Upgrade virus scanner adapter to real scanner backend.
- Current adapter is stub-like and should be replaced with ClamAV/SaaS integration.

4. Add observability.
- Structured logs per request (latency, bytes, actor, software/version ids).
- Metrics (success/failure counters, p95 latency, throughput, queue depth).
- Tracing for DB/storage spans.

5. Add resilience and integrity policies.
- Orphan cleanup job for storage/database mismatch.
- Idempotency strategy for retried uploads.
- Retry/backoff strategy for storage delete failures.

6. Add test coverage.
- Unit tests for domain/application.
- Integration tests for concurrent upload/publish races.
- API tests for streaming and auth/permission errors.

7. Deploy with PostgreSQL + asyncpg in production.
- SQLite support is for local/development only.

## Local Validation Commands

```powershell
python -m compileall software_management
```

```powershell
uvicorn app.main:app --reload
```

## Notes

- `uvloop` is installed via `asyncio.set_event_loop_policy(...)` when available.
- The SMS module is isolated and can be extracted into a standalone package with minimal changes.
