# ADR 0009: The User aggregate, and an explicit `save`

- **Status:** Accepted
- **Date:** 2026-09-30
- **Refactor phase:** 6b
- **Related:** ADR 0001, 0002, 0004

## Context

`users` had no domain model at all. `UserService` built an ORM row, handed it to
a repository, and the repository returned *live ORM rows* to three callers
outside the user context. All three mutated what they got back and relied on
session autoflush to persist the change:

| Site | Mutation | What a detached entity would have done |
|---|---|---|
| `auth_service.py:98` | `user.password_hash = verified_hash` | rehash-on-login stops silently |
| `auth_service.py:123` | `user_acc.status = VERIFIED` | accounts never verify — lockout |
| `auth_service.py:218` | `user.password_hash = ...` | reset returns 200, old password still works |
| `verification_recovery.py:45-48` | 4 retry fields | unbounded verification-email retry |
| `superuser_seeder.py` | `role`, `status`, `password_hash` | admin seeding reports success and changes nothing |

Every one of those fails *silently*: a 200 or 201 goes back, the write is gone.
And nothing caught them. `test_auth_hardening.py` drives `AuthService` with fake
repositories, so no test ever exercised a real `UserRepo` write.

`UserService` also held five ratchet entries — R4 and R5 for the `User` model, and
three R8 entries for `fastapi`, `fastapi.concurrency`, and `sqlalchemy.exc`.

The Phase 6a review deferred this conversion explicitly, on the grounds that
returning detached entities without first making every write explicit would break
those five paths. The blocker was the missing test coverage, not the design.

## Decision

### 1. A `User` aggregate, and an explicit `save` on the port

```python
class UserRepository(Protocol):
    async def add_user(self, user: User) -> User: ...
    async def save(self, user: User) -> User: ...      # <- the load-bearing line
```

Reads return detached `User` entities. A caller that mutates one must call
`save`. Every one of the five sites above now does.

`save` is implemented with `Session.merge`, not `Session.add`. The entity is
detached, so the session has never seen it and `add` would attempt an `INSERT`
against an existing primary key. `merge` copies the entity's state onto the
tracked row. This is asserted directly: `test_works_on_an_entity_loaded_by_a_previous_session`
and `test_updates_in_place_instead_of_inserting` both count rows afterwards,
because "did this insert or update" is the whole question.

### 2. The safety net came first

`tests/integration/test_user_write_paths.py` runs against real SQLite through a
real `UnitOfWork` and reads back through a *second* session, so a passing test
means the change was committed rather than merely flushed.

It was written and proven to bite before any production line changed, by
detaching rows inside the repository's lookup methods. Post-conversion it was
re-proven by deleting the five `save()` calls: all five write-path tests fail,
the other four pass. A test that cannot fail is not a safety net.

### 3. "What does a new account start as" is a rule, not a parameter

The seeder used to construct a `User` with `status=VERIFIED, role=ADMIN` inline
while `register` said a new account starts `UNAPPROVED`/`USER`. Two places
spelling out the same rule is how they drift.

Seeding an account is a use case, so it became one: `UserService.ensure_superuser`.
R2 also forced this — the seeder is infrastructure, and R2 stops infrastructure
importing another context's entities, so a hand-rolled account was never going to
survive the aggregate. The seeder now reads configuration and decides *whether*
to seed; the user context decides *what* a seeded account looks like.

### 4. The client IP is a string, not a `Request`

`create_user` took a `fastapi.Request` purely to call
`AbuseProtection.get_client_ip(request)`. The router now reads the IP at the
transport edge and passes a `str`, which is what let the three R8 `fastapi`
imports go.

Password hashing moved from `run_in_threadpool` to `asyncio.to_thread` for the
same reason — it was never a FastAPI concern. Both are CPU-bound offload, so the
event loop is no longer blocked during Argon2.

### 5. Error translation moved to the repository

`DuplicateUserError` and `UserRepositoryUnavailableError` are raised where the
driver is, so the application no longer needs `sqlalchemy.exc` to be safe. Each is
registered against the status code its shared-kernel predecessor produced:

| Domain error | Replaces | Status |
|---|---|---|
| `UserNotFoundError` | `NotFoundError` | 404 |
| `DuplicateUserError` | `ConflictError` | 409 |
| `UserRepositoryUnavailableError` | escaping driver error | 500 |

Deliberately 500, not 503: a driver error escaped as a 500 before this phase, and
Phase 6a made the same call for the chat repository.

## Rationale

**Why not keep returning ORM rows and defer the aggregate?** It would have left
the five silent write-loss paths in place and the five ratchet entries ratcheted.
The autoflush dependency is a real defect today, not a refactoring hazard for some
future phase.

**Why explicit `save` rather than a tracked-entity or Unit-of-Work-managed
dirty-tracking session?** Autoflush made the write *possible* and its durability
invisible: nothing in the code said "this is persisted". Making it explicit costs
five call sites and makes the persistence point greppable. A session that tracked
dirty entities would keep the coupling while hiding the dependency even further.

**Why is `list_users`' `cursor` parameter gone?** It was a `created_at` upper
bound, and `list_users` had grown a second cursor, `before_id`, with different
semantics. `cursor` had no caller since the router moved to keyset pagination.
Leaving two pagination schemes on one method is how they start disagreeing. The
route was already keyset-only, so no HTTP behaviour changed.

**Why does the entity not normalize its inputs?** It never has, and
`auth_service` normalizes separately for lookup. Storing normalized values now
would silently change what existing rows mean. Recorded in `docs/REVIEW.md`.

## Consequences

**Good**

- The five silent write-loss paths are gone and are pinned by tests that are
  proven to fail without the `save()`.
- `UserService` is free of ORM models, pydantic schemas, FastAPI, threadpool
  helpers, and `sqlalchemy.exc`. Five ratchet entries removed (10 → 5).
- "What does a new account start as" is decided in one place.
- Password strength checking and Argon2 hashing no longer hold a database
  connection open; both run before the transaction opens.
- The public HTTP surface is pinned by a test
  (`tests/architecture/test_public_http_surface.py`) after being re-checked by
  hand at the end of every prior phase.

**Bad**

- A caller who forgets `save` loses their write, and the failure is still silent
  at runtime. The tests cover the five sites that exist; a sixth added later
  needs its own test, or a lint rule for entity-mutating methods.
- `auth_service` mutates an entity it receives through a port typed as
  `UserRepository`, and reaches methods the protocol does not describe. It relies
  on the concrete implementation rather than on the port. Phase 7 owns
  `auth_service` and should introduce a port that actually names this
  capability.

**Neutral**

- The entity's `gender`/`status`/`role` defaults duplicate the ORM column
  defaults on purpose, so a hand-built `User` and a hand-built `UserModel` cannot
  describe different rows.
- `verification_email_last_error` is truncated to 500 characters in the mapper.
  The column is `String(500)` and SQLite does not enforce it; on Postgres an
  over-long SMTP error would otherwise turn a bookkeeping write into a 500.
