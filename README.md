# Tech Pulse Backend

FastAPI backend for the Tech Pulse platform.

This service is organized as a modular application under `app/` with shared
infrastructure in `app/infrastructure/` and feature-specific code under
`app/modules/`.

## Project Structure

```text
app/
  core/                  # Settings, lifecycle, logging
  exceptions/            # Error types and exception handlers
  infrastructure/        # DB, email, Redis, storage, scripts, external APIs
  modules/               # Feature modules
    analytics/
    authentication/
    billing/
    projects/
    resource/
    security/
    software_management/
    shared/
    user/
  main.py                # FastAPI app entrypoint

alembic/                 # Database migrations
tests/                   # Unit and integration tests
logs/                    # Runtime logs
reports/                 # Generated reports
storage/                 # Local upload storage
```

## Feature Areas

- Authentication and session management
- User account and admin management
- Support chat and AI-assisted support flows
- Project upload and download APIs
- Resource management APIs
- Software/package management with upload and download flows
- Billing domain and payment/purchase APIs
- Analytics event ingestion
- Security, audit logging, and abuse protection

## Key Modules

- `app/core/`
  - Application settings
  - Lifespan hooks
  - Logging setup
- `app/exceptions/`
  - Domain and API exception handling
- `app/infrastructure/`
  - SQLAlchemy database models and session setup
  - Redis client helpers
  - Email delivery helpers and templates
  - Storage adapters
  - Malware scanning and other external integrations
  - Startup scripts such as migration helpers and superuser seeding
- `app/modules/authentication/`
  - Login, refresh, logout, and password flows
- `app/modules/user/`
  - User CRUD, support chat, admin routes, and user services
- `app/modules/projects/`
  - Project repository, schema, and router
- `app/modules/resource/`
  - Resource repository, schema, service, and router
- `app/modules/software_management/`
  - API routers, application services, domain entities, policies, ports, and persistence
- `app/modules/billing/`
  - API layer, application services, domain models, and repository adapters
- `app/modules/analytics/`
  - Analytics event API
- `app/modules/security/`
  - Password hashing, token handling, audit middleware, and abuse protection
- `app/modules/shared/`
  - Shared DTOs, enums, mappers, pagination, and dependency helpers

## Prerequisites

- Python 3.11+
- `pip`
- PostgreSQL or SQLite
- Redis is recommended for rate limiting and replay protection, but the app can
  fall back to in-memory protection in some scenarios

## Environment

Copy the example environment file and edit it for your setup:

```powershell
Copy-Item .env.example .env
```

Important settings include:

- `DATABASE_URL` and `ALEMBIC_DATABASE_URL`
- `SECRET_KEY`
- `EMAIL_VERIFY_SECRET` and `PASSWORD_RESET_SECRET`
- `FRONTEND_URL` and `BACKEND_URL`
- `ACCESS_COOKIE_NAME` and `REFRESH_COOKIE_NAME`
- `SMTP_*` values if email delivery is enabled
- `REDIS_HOST`, `REDIS_PASSWORD`, and `REDIS_DB`
- `STARTUP_RUN_MIGRATIONS`
- `SUPERUSER_*` values for startup admin seeding
- `PAYMENT_*` and `MALWARE_SCAN_*` values if those integrations are used

See [`.env.example`](./.env.example) for the full list of supported variables.

## Local Development

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run migrations:

```powershell
alembic upgrade head
```

Start the API:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Health and docs:

- `GET /health`
- Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`

## Tests

Run the test suite with:

```powershell
python -m pytest
```

Suggested test organization:

- `tests/unit/` for business logic
- `tests/integration/` for API, database, or external dependency coverage

## Database Migrations

Create a new migration:

```powershell
alembic revision --autogenerate -m "describe_change"
```

Inspect migration status:

```powershell
alembic current
alembic heads
```

The helper script at `app/infrastructure/scripts/migrate.sh` also wraps common
Alembic operations such as `status`, `upgrade`, `downgrade`, `revision`, and
`history`.

## Runtime Notes

- The API entrypoint is `app/main.py`.
- CORS is configured for local frontend origins in the current app settings.
- The service exposes `/` and `/health` at the root, and includes routers for
  authentication, users, support chat, projects, resources, analytics, software
  management, billing, and admin/security workflows.
- Static frontend assets are mounted in production if a build directory is
  present.
