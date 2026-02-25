# Tech Pulse Backend

Backend API for the Tech Pulse platform, built with FastAPI + SQLAlchemy + Alembic.

## What This Service Does
- User registration and authentication (JWT + HttpOnly access/refresh cookies)
- Email verification and password reset flows
- Role-based access control (`ADMIN`, `USER`)
- AI-powered support chat endpoint
- Project file upload/download APIs
- Software package upload/download APIs (single-shot and resumable chunk uploads)
- Resource management APIs
- Audit logging, security alerts, and admin observability endpoints
- Analytics event ingestion for cookie consent and client activity

## Tech Stack
- Python 3.11
- FastAPI / Starlette
- SQLAlchemy + Alembic
- PostgreSQL or SQLite
- Redis (optional but recommended for stronger abuse protection and one-time token replay defense)

## Project Layout
```text
app/
  api/v1/               # Route handlers
  core/                 # Config, security, middleware, logging
  database/             # Engine/session setup and DB initialization
  infrastructure/       # Storage backends and scanner/checksum utilities
  models/               # SQLAlchemy models
  repositories/         # Data access layer
  schemas/              # Pydantic request/response schemas
  services/             # Business logic
alembic/                # Database migrations
logs/                   # Runtime logs (rotating app log)
storage/                # Local uploaded files
```

## Prerequisites
- Python 3.11+
- `pip`
- Database:
  - PostgreSQL (recommended), or
  - SQLite (works with default fallback config)
- Redis (recommended; app falls back to in-memory abuse protection if unavailable)

## Environment Configuration
Copy and edit the example:

```powershell
Copy-Item .env.example .env
```

Important variables:
- `DATABASE_URL` (example: `postgresql+psycopg2://postgres:postgres@localhost:5432/techpulse`)
- `SECRET_KEY` (must be at least 32 chars)
- `EMAIL_VERIFY_SECRET` (must be at least 32 chars)
- `PASSWORD_RESET_SECRET` (recommended explicit 32+ chars; otherwise derived in code)
- `FRONTEND_URL` (comma-separated allowed origins)
- `BACKEND_URL` / `BASE_URL`
- `SMTP_*` values if email sending is required
- `SUPERUSER_*` values for startup admin seeding

## Local Run
Install dependencies:

```powershell
pip install -r requirements.txt
```

Run migrations:

```powershell
alembic upgrade head
```

Start API:

```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Docs and health:
- Swagger UI: `http://127.0.0.1:8000/docs`
- Health check: `GET /health`

## Docker Run
Build:

```powershell
docker build -t techpulse-backend .
```

Run:

```powershell
docker run --env-file .env -p 8000:8000 techpulse-backend
```

Container startup command runs migrations first, then starts Uvicorn.

## API Route Map
Base prefix for versioned APIs: `/api/v1`

- Auth (`/auth`)
  - `POST /login`
  - `POST /refresh`
  - `POST /logout`
  - `GET /verify`
  - `GET /verify-page`
  - `POST /password-reset/requests`
  - `POST /password-reset/confirm`
  - `GET /password-reset/page`
- Users
  - `POST /users`
  - `GET /users/me`
  - `GET /users` (admin)
  - `GET /users/{user_id}` (admin)
- Support Chat (`/support-chat`)
  - `POST /messages`
  - `GET /messages`
- Projects (`/projects`)
  - `POST /`
  - `GET /`
  - `GET /{project_id}`
  - `GET /{project_id}/download`
  - `DELETE /{project_id}`
- Resources (`/resources`)
  - `GET /`
  - `GET /{slug}`
  - `POST /` (admin)
  - `DELETE /{slug}` (admin)
- Software Packages (`/software-packages`)
  - `POST /` (single request upload)
  - `POST /uploads/init`
  - `PATCH /uploads/{upload_id}`
  - `POST /uploads/{upload_id}/complete`
  - `DELETE /uploads/{upload_id}`
  - `DELETE /{package_id}`
  - `GET /`
  - `GET /{package_id}/versions`
  - `GET /{package_id}/versions/{version_id}/download`
  - `GET /admin/summary` (admin)
  - `GET /admin/packages` (admin)
- Admin (`/admin`)
  - `GET /logs`
  - `GET /alerts`
  - `PATCH /alerts/{alert_id}/ack`
  - `GET /audit-events`
  - `GET /cookie-activity`
- Analytics (`/analytics`)
  - `POST /events`

## Security Notes
- Authentication accepts Bearer token and/or access cookie.
- Refresh flow uses refresh cookie and session rotation.
- Rate limits are applied to login, refresh, and password reset endpoints.
- Security secrets are validated on startup; weak secrets fail startup.
- Audit middleware records request metadata and powers admin observability APIs.

## Logging and Storage
- Logs are configured via rotating file handler (`LOG_FILE_PATH`, default under `logs/`).
- Upload storage root defaults to `storage/`.
- Package storage backend supports:
  - `local` (filesystem)
  - `object` (object storage adapter)

## Migration Workflow
Create migration:

```powershell
alembic revision --autogenerate -m "describe_change"
```

Apply migration:

```powershell
alembic upgrade head
```
