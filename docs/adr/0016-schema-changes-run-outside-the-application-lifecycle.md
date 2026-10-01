# ADR 0016: Schema changes run outside the application lifecycle

- **Status:** Accepted
- **Date:** 2026-10-01
- **Deciders:** backend maintainers
- **Supersedes:** nothing
- **Related:** ADR 0004 (layer boundaries and the ratchet), ADR 0015 (proxy-header trust is decided in one place)
- **Affects:** [`docs/DEPLOYMENT.md`](../DEPLOYMENT.md)

## Context

`docker-entrypoint.sh` used to run migrations before the web server:

```sh
alembic upgrade head
CURRENT_REVISION=$(alembic current | grep -o '[a-zA-Z0-9_]\{10,\}' | head -1)
HEAD_REVISION=$(alembic heads | grep -o '[a-zA-Z0-9_]\{10,\}' | head -1)
if [ "$CURRENT_REVISION" != "$HEAD_REVISION" ]; then ... exit 1; fi
exec uvicorn app.main:app ...
```

Every container start therefore applied whatever migrations were outstanding.
That couples a schema change to the lifetime of a web worker, and the
consequences are all in the direction of doing the wrong thing quietly:

- **A deploy is a migration.** Starting the new image applies the migration.
  There is no point at which you can decide to ship code without shipping the
  schema change that goes with it, or to hold the schema change back.
- **Every replica migrates.** `upgrade head` is not run once, it is run once
  per container. Concurrent replicas race on the `alembic_version` table.
- **A restart migrates.** `docker restart`, a crash loop, a node drain, a
  `docker compose up` to pick up an unrelated env change — each one applies
  pending migrations that nobody asked for at that moment.
- **A failed migration takes the web process down with it.** The migration runs
  in the same container as the server, so a failure surfaces as a crash-looping
  API rather than as a deploy that stopped cleanly at a known point.
- **Rolling back is not possible.** Once a migration has run, reverting the
  image reverts the code, not the schema.

The configuration carried a matching fiction: `STARTUP_RUN_MIGRATIONS` was
declared in `config.py` with the comment "Startup superuser seeding", present
in `.env.example`, and listed in the README — but never read by any code. An
operator reading the template would reasonably believe there was a supported
way to defer migrations to start-up. There was not.

One of the migrations in the chain makes this acute rather than theoretical.
`8dea867ad60e` drops three tables permanently and now refuses to run without
`TECHPULSE_ALLOW_DESTRUCTIVE_MIGRATIONS`. That guard is only meaningful if it
is consulted at a point a human chose; run automatically on every container
start, it would be a value buried in an env file deciding the fate of a
production table.

## Decision

**Migrations are a deployment step, not an application start-up step.**

- `docker-entrypoint.sh` starts the web server and nothing else. No `alembic`
  invocation remains in it.
- `docker-compose.yml` defines a `migrate` service that overrides the image
  entrypoint with `alembic upgrade head`, runs to completion, and exits.
- `api` depends on it with `condition: service_completed_successfully`, so the
  web process cannot start until the schema is current. A failed migration
  stops the deploy at a known point and leaves the previous revision in place.
- `migrate` depends on `db` with `condition: service_healthy`, because
  `pg_isready` passing is a different claim from "accepting the connection
  that `upgrade head` needs".
- `migrate` has `restart: "no"`. It is a job, not a service, and a restart
  policy would bring it back as a loop.
- `STARTUP_RUN_MIGRATIONS` is deleted from `config.py` and `.env.example`.

Applying a migration by hand is an explicit act:

```bash
docker compose run --rm migrate
```

## Rationale

*A separate one-shot service* was chosen over *running migrations in an
init container attached to the web process*, because the latter still couples
the two: the web container's start-up would block on the migration's success,
which is the coupling being removed.

*Failing the deploy* was chosen over *migrating automatically and tolerating
failure*. A deploy that cannot reach the current schema has not succeeded;
failing at a known point, with the migration's output readable via
`docker compose logs migrate`, is the behaviour an operator needs.

*`service_completed_successfully`* was chosen over `service_started`, because
`service_started` says only that a container was created.

The dead `STARTUP_RUN_MIGRATIONS` field was removed rather than implemented.
It was never read, so nothing depended on it, and leaving it would have kept
advertising a start-up migration path that no longer exists.

## Consequences

**Good**

- A schema change happens when someone runs the `migrate` service, and nowhere
  else. Restarts, crash loops and rolling deploys cannot migrate.
- One migration process per deploy rather than one per replica.
- A failed migration stops the deploy before any web process starts.
- The irreversible `8dea867ad60e` guard is consulted at a point a human chose.
- No dead configuration implying a start-up migration path.

**Bad**

- An operator who changes a model must remember to run `migrate`. This is the
  intended cost: it is the step the old arrangement performed implicitly.
- Schema and image version are now separate concerns, so a deployment has two
  things to keep ordered. That ordering is the point, but it is now explicit
  rather than automatic.
- `docker compose up` from a clean checkout applies migrations to an empty
  database, which is correct, but it means a first run does both jobs in one
  command.

**Neutral**

- `docker-entrypoint.sh` is now short enough that its whole behaviour is
  readable at a glance; the migration block moved to `docker-compose.yml`
  where the ordering it depends on is also visible.
- `migrate` builds the same image as `api` via a shared YAML anchor, so there
  is one image and no drift between what migrated and what is serving.
- Superuser seeding still runs in the application lifespan and is *not*
  covered by this decision. It remains a per-process start-up mutation, and
  the multi-replica race around it is still open — see
  [DEPLOYMENT.md](DEPLOYMENT.md).