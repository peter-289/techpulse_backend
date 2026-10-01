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

There is one `.env`, at the repository root, grouped by which container
consumes each variable. Important settings include:

- `DATABASE_URL_ASYNC` (the application engine) and `DATABASE_URL_SYNC` (Alembic)
- `SECRET_KEY`
- `EMAIL_VERIFY_SECRET` and `PASSWORD_RESET_SECRET`
- `FRONTEND_URL` and `BACKEND_URL`
- `ENVIRONMENT` — `production` turns off `/docs` and the loopback CORS origins
- `TRUST_PROXY_HEADERS` — see [ADR 0015](./docs/adr/0015-proxy-header-trust-is-decided-in-one-place.md)
- `ACCESS_COOKIE_NAME` and `REFRESH_COOKIE_NAME`
- `SMTP_*` values if email delivery is enabled
- `REDIS_HOST`, `REDIS_PASSWORD`, and `REDIS_DB`
- `SUPERUSER_*` values for admin seeding
- `PAYMENT_*` and `MALWARE_SCAN_*` values if those integrations are used

There is deliberately no `STARTUP_RUN_MIGRATIONS`: schema changes run as their
own one-shot step, not from the application's start-up.

See [`.env.example`](./.env.example) for the full list, and
[`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md) for deployment.

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

`/docs`, `/redoc` and `/openapi.json` are served only when
`ENVIRONMENT != production`, unless `SERVE_API_DOCS` overrides it.

## Running the stack with Docker

```bash
cp .env.example .env    # then edit it
docker compose up -d --build
```

Services come up in order — `db` becomes healthy, `migrate` applies the schema
once and exits, and `api` waits for that to succeed before serving:

```bash
docker compose ps -a                                  # check migrate exited 0
docker compose logs migrate                           # read its output
docker compose up -d api                              # only if you changed app code
docker compose --profile dev up -d                    # adds mailhog + pgadmin
```

Mailhog and pgAdmin are local-development conveniences behind the `dev`
profile; `docker compose up` does not start them. Production mail will point
`SMTP_*` at a third-party provider.

Schema changes are **not** part of the application's start-up. `migrate` is a
separate one-shot service, so restarting or rolling out `api` cannot apply a
migration as a side effect, and a failed migration stops the deploy before any
web process starts. Apply them deliberately:

```bash
docker compose run --rm migrate
```

One migration is irreversible and will refuse to run without acknowledgement —
see [TECHPULSE_ALLOW_DESTRUCTIVE_MIGRATIONS](./docs/DEPLOYMENT.md).

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

# Notes
- This project was mainly for learning purposes only, not anything serious😀🫡