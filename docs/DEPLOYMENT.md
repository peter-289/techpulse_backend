# Deployment readiness

What stands between this repository and a running production deployment, and
what has been done about it. Written 2026-10-01.

**Verdict: the deployment shape is now sound.** The backend is a composable
image, migrations are a deploy step rather than a start-up side effect, and one
root `.env` declares every variable the stack consumes. Nine defects from the
first pass are fixed.

**Still open, and they are not cosmetic** — see [Still open](#still-open).
The largest is that **this has never been built or run**: `docker` is not
installed on the machine this was prepared on, so no image was built, no
container started, and `docker compose config` never ran. The compose file is
validated statically by `tests/unit/test_compose_wiring.py`, which is not the
same thing.

**Read alongside:** `docs/adr/` (why), `docs/REVIEW.md` (the DDD refactor this
codebase came out of).

---

## Deployment shape

### Services

```
db (healthy) ──> migrate (runs once, exits 0) ──> api (serves)
redis (healthy) ─────────────────────────────> api
```

| Service | Profile | Purpose |
|---|---|---|
| `db` | default | PostgreSQL 16, `pg_isready` healthcheck |
| `migrate` | default | `alembic upgrade head`, one-shot, `restart: "no"` |
| `api` | default | the backend, non-root, waits on `migrate` |
| `redis` | default | password-protected, healthcheck |
| `mailhog` | `dev` | local mail sink; production uses a third-party `SMTP_*` |
| `pgadmin` | `dev` | local DB UI; password read from the environment |

```bash
cp .env.example .env     # then edit it
docker compose up -d --build
docker compose --profile dev up -d      # additionally mailhog + pgadmin
```

### Why migrations are a separate service

`docker-entrypoint.sh` used to run `alembic upgrade head` before starting the
server, so every container start applied pending migrations. That made a deploy
a migration, migrated once per replica, migrated on restart, took the web
process down when a migration failed, and left no clean rollback point. Full
argument in [ADR 0016](adr/0016-schema-changes-run-outside-the-application-lifecycle.md).

Now: `migrate` overrides the entrypoint, runs to completion and exits; `api`
waits on `service_completed_successfully`; `migrate` waits on `db`'s healthcheck.
To apply a change deliberately:

```bash
docker compose run --rm migrate
```

The dead `STARTUP_RUN_MIGRATIONS` field — declared in `config.py`, present in
`.env.example` and the README, read by nothing — is deleted.

### Configuration: one file at the root

`.env.example` is the single source of truth, grouped by consumer: backend
application, PostgreSQL, Redis, email, host port bindings, migrations, and
local-dev-only. `.env` is git-ignored and excluded from the build context, so
real values reach neither the repository nor the image.

`api` and `migrate` receive it wholesale via `env_file`, because the
application's settings load from the process environment and the file declares
~40 variables. `db` is configured by explicit keys instead, so database
credentials and `SECRET_KEY` do not land in the PostgreSQL container. Compose
interpolates the whole file regardless of which services are active, so a
variable belonging to a dev-profile service must still be declared — that is why
the `dev` section is in the root file rather than a separate one.

### Two details that silently break the container

**Named volumes must be pre-created in the image.** Docker seeds a fresh named
volume from whatever the image has at that path, *including ownership*. With
`/app/storage` and `/app/logs` absent from the image, the volumes come up empty
and root-owned, and a non-root process cannot write to them — the container dies
in `logging_setup.py` at import, before uvicorn starts. The `Dockerfile` now
`mkdir -p`s both before the `chown`, and a test asserts every mounted `/app`
path appears in the `Dockerfile`.

**Uploads and logs are mounted.** `api_storage:/app/storage` and
`api_logs:/app/logs`. Without them, end-user artifacts and log files live in
the container layer and are lost when it is replaced. The `api` service also
points `UPLOAD_ROOT` and `LOG_DIR` at those paths.

---

## Fixed

### 1. The documented setup path could not start the app

`.env.example` named its variable `DATABASE_URL`; `config.py` reads
`DATABASE_URL_ASYNC` (asyncpg, the application engine) and `DATABASE_URL_SYNC`
(psycopg2, Alembic per `env.py:61,79`). Neither matched, and
`SettingsConfigDict(extra="ignore")` dropped it silently — a crash at import:

```
RuntimeError: DATABASE_URL is not set.        # db_setup.py:7
```

Both are now declared, and `db_setup.py:7` names the variable it wants.

### 2. IP rate limits depended on a switch that did nothing

`abuse_protection.get_client_ip` correctly gated its `X-Forwarded-For` reads
behind `TRUST_PROXY_HEADERS`, but uvicorn installs `ProxyHeadersMiddleware` **by
default** and rewrites the scope's `client` from a client-supplied header
whenever the peer is in `FORWARDED_ALLOW_IPS` (default `127.0.0.1`). The
fallback `return request.client.host` therefore did not return the socket peer.
Separately, `app/main.py` passed `proxy_headers=True` to the app factory — FastAPI
has no such parameter, so it fell into `**extra` and was discarded, reading as
a deliberate security setting while configuring nothing.

The entrypoint now derives uvicorn's flag from `TRUST_PROXY_HEADERS`, so the
two layers cannot disagree, and refuses `FORWARDED_ALLOW_IPS=*` at start-up.
See [ADR 0015](adr/0015-proxy-header-trust-is-decided-in-one-place.md) and
`tests/unit/test_entrypoint_proxy_trust.py`.

*Scope, stated honestly:* the rewrite only happens for a trusted peer, so
traffic arriving directly from outside the container is not affected by
default. This is a fix for two switches that could silently disagree, not a
live bypass in every deployment.

### 3. `alembic upgrade head` silently destroyed three tables

Revision `8dea867ad60e` dropped `projects`, `sms_purchases` and `sms_payments`
with no archive step; its `downgrade()` recreates the schema, not the rows. It
was in the chain that every container start applied (item 2's entrypoint).

`upgrade()` now refuses to run unless `TECHPULSE_ALLOW_DESTRUCTIVE_MIGRATIONS`
is set, naming the tables, stating that `downgrade()` cannot restore the rows,
and offering `alembic stamp` to keep the tables instead. Failing loudly was
chosen over skipping: skipping leaves tables no model declares, which
`alembic check` reports as drift. `ci.yml` sets the variable so CI still
exercises the real upgrade path.

*Scope:* this protects only databases that have not applied the revision. Any
that already ran it lost those rows before this change.

### 4. There was no way to run the backend

`docker-compose.yml` defined `db`, `redis`, `mailhog` and `pgadmin`. The
`Dockerfile` was referenced by nothing. There is now an `api` service built from
the repository root, sharing one image with `migrate` through a YAML anchor so
there is no drift between what migrated and what is serving.

### 5. Redis could not start

`redis` ran `--requirepass ${REDIS_PASSWORD}` with no such variable declared
anywhere. `REDIS_PASSWORD` is now in `.env.example`, and compose guards it with
`${REDIS_PASSWORD:?...}` so a missing value fails at parse time with a message
naming the variable rather than starting Redis with an empty password.

### 6. Uploads and logs had nowhere durable to live

Covered under [Deployment shape](#two-details-that-silently-break-the-container).

### 7. The template shipped a working admin account

`.env.example` had `SUPERUSER_SEED_ENABLED=true` with `SUPERUSER_USERNAME=admin`
and `SUPERUSER_PASSWORD=change_me`. Nothing rejected the value —
`_assert_min_secret` was never applied to it — so the documented setup path
produced an administrator reachable with a published password.

Seeding is now `false` in the template with an empty password, and
`validate_security()` refuses to start when seeding is enabled with a
placeholder password or one under 12 characters. The check runs at start-up
rather than import, so a stray value cannot take the whole test collection down.

### 8. Auth ran through a library with known advisories

`python-jose==3.3.0` carries the algorithm-confusion and JWT-bomb advisories
fixed in 3.4.0 (CVE-2024-33663, CVE-2024-33664), and it is the *only* JWT
library the auth model uses. Now pinned to `3.4.0`, with the 65 auth and rate-
limit tests re-run against it. `PyJWT==2.11.0` was installed but never imported
and is removed.

**`pyasn1` was pinned down with it.** python-jose requires `pyasn1<0.5.0`, and
`requirements.txt` pinned `pyasn1==0.6.2` from the 3.3.0 tree — so
`pip install -r requirements.txt` failed outright with both changes present.
Corrected to `0.4.8` and verified with a clean resolve. A pin change in one
dependency can silently invalidate another; this one did.

### 9. The full route surface was published in production

`/docs`, `/redoc` and `/openapi.json` were unconditional — no `docs_url`
argument and no `ENVIRONMENT` setting existed to gate them. CORS also appended
four loopback origins to an `allow_credentials=True` allowlist regardless of
environment.

`ENVIRONMENT` now selects the behaviour, and anything outside
`{development, staging, production, test}` is rejected at import:

| | `production` | otherwise |
|---|---|---|
| `/docs`, `/redoc`, `/openapi.json` | not served | served |
| loopback CORS fallbacks | not added | added |

`SERVE_API_DOCS` overrides the docs behaviour explicitly either way, which is
what lets `test_public_http_surface.py` pin those routes without depending on
the default. Production additionally **requires** `FRONTEND_URL` to name a
non-loopback origin: it seeds a credentialed allowlist, so leaving the default
`http://localhost:5173` in place would let any page on a developer's machine
make authenticated calls.

### 10. A committed credential, and dead dev dependencies

The pgAdmin password at `241f483` was in history and is **not** removed by this
work — history rewriting is not something to do unasked. The `pgadmin` service
is restored under the `dev` profile with its password sourced from
`PGADMIN_PASSWORD` in the root `.env`, so no credential is committed going
forward. **Treat the old value as exposed and rotate it.**

`pytest` and `pytest-asyncio` are still installed into the production image,
justified in `requirements.txt` by a claim that CI runs the suite from that
image. It does not — `ci.yml:20-26` installs from `requirements.txt` in a bare
interpreter and runs pytest from a checkout. Moving them to a
`requirements-dev.txt` is the honest fix but touches the CI workflow, so it is
listed below rather than done.

---

## Still open

None of these are fixed. The first is a blocker for any real deployment.

### Blockers

| # | Issue | Where |
|---|---|---|
| 1 | **Nothing has been built or run.** No `docker` on the host this was prepared on. No image built, no container started, `docker compose config` never validated. `tests/unit/test_compose_wiring.py` checks the file statically — the YAML parses, the anchors merge, every `${VAR}` is declared, the ordering invariants hold — but that is not a build | — |
| 2 | `host.docker.internal` / loopback reachability is unverified. In particular whether `BACKEND_URL` and `SMTP_HOST` resolve correctly from inside the network once the third-party mail provider is chosen | `.env.example` §4 |
| 3 | `python-jose` 3.4.0 was verified against the existing tests only. The CVE fixes are upstream's; confirm against current advisory data before relying on the pin | `requirements.txt` |
| 4 | Superuser seeding still runs in the application lifespan, so it is a per-process start-up mutation. With more than one replica, `ensure_superuser` is read-then-insert against unique `username`/`email` and the loser is swallowed at `superuser_seeder.py:56-59`. `SUPERUSER_UPDATE_PASSWORD_ON_STARTUP=true` would rewrite the admin password mid-flight | `lifespan.py:33` |
| 5 | The email-recovery loop is an in-process `asyncio.Task` with no leader election. N replicas run N sweeps every `EMAIL_RECOVERY_INTERVAL_SECONDS`, and they race on `verification_email_retry_count` | `lifespan.py:42-50` |

### Before or shortly after launch

- **Not safe to run more than one worker or replica.** `exec uvicorn` with no
  `--workers`, plus items 4 and 5 above.
- `PASSWORD_RESET_SECRET` silently falls back to `EMAIL_VERIFY_SECRET` and then
  to `SECRET_KEY` (`config.py`), so a forgotten variable collapses three
  token-signing keys into one. `validate_security` checks length only, so the
  collapse passes.
- `COOKIE_SECURE` is forced off when *either* URL is `http://`, and
  `.env.example` ships `BACKEND_URL=http://127.0.0.1:8000` — so a TLS
  deployment needs both URLs on `https://`.
- Several exception handlers return `str(exc)` to the caller;
  `handlers.py:311` forwards the AI provider's raw response body verbatim. The
  catch-all at `handlers.py:315` is clean.
- `pytest` / `pytest-asyncio` ship in the production image. Move to
  `requirements-dev.txt`.
- Dead configuration: `MALWARE_SCAN_API_URL` / `_API_KEY` and `PAYMENT_*` are
  referenced nowhere; the local scanner matches only the EICAR string; support
  chat returns a canned `FALLBACK_REPLY` when `AI_API_KEY` is unset while
  `/health` stays green.
- `config.py:48` probes `/.env` on every start (`PROJECT_ROOT` resolves to `/`
  in the image). Inert, but a stray `/.env` on the host would be picked up.

### Also worth knowing

The suite is **670 passing**. `docs/REVIEW.md` records 636 at Phase 9a; the 34
added are `test_entrypoint_proxy_trust.py` (15) and `test_compose_wiring.py`
(19).

Four test files remain in `tests/` for modules that no longer exist
(`billing`, `projects`), excluded via `collect_ignore` in `tests/conftest.py`
rather than deleted, so their intent is recoverable. They should be rewritten
or removed.

`docs/DEPLOYMENT.md` supersedes the readiness list that lived only in a commit
message; this file and the two ADRs are the durable record.