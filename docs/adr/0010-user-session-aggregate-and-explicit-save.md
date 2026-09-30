# ADR 0010: `UserSession` is a user-context aggregate, and its writes are explicit

- **Status:** Accepted
- **Date:** 2026-09-30
- **Deciders:** refactor
- **Related:** ADR 0001, ADR 0002, ADR 0009

## Context

`UserSession` was the last user-context record with no model of its own. It was
an ORM row that `auth_service` mutated in place and persisted by accident, via
session autoflush.

The shape of the problem is the same one ADR 0009 found for `User`, and it is
worth restating because it is not a general truth about repositories — it is a
property of *when* the flush happens. The unit of work calls
`session.commit()` on exit, but a query earlier in the same transaction
autoflushes pending changes as a side effect. So a mutated row was persisted
only if some later read happened to run before the transaction ended. Adding,
removing, or reordering an unrelated read would silently change whether a
session got written. Both of the affected paths returned success either way.

`auth_service` also had two ORM-model imports and two framework imports, the
last four entries in the ratchet.

## Decision

Give sessions an aggregate, in the user context.

`UserSession` is a domain entity in `app/modules/user/domain/entities/`, and
`SessionRepository` is a port beside `UserRepository`. The repository reads
return **detached** entities, so a mutation requires an explicit
`session_repo.save(...)`. `save` uses `Session.merge` because the entity is
detached; `add` would attempt an `INSERT` against an existing primary key.

The behaviour that used to be open-coded moves onto the aggregate:

| Was | Now |
|---|---|
| `Session(refresh_token_hash=..., ...)` | `UserSession.open(user_id, refresh_token_hash, expires_at, user_agent, ip_address)` |
| `session.refresh_token_hash = new_hash` | `session.rotate(new_refresh_token_hash, rotated_at, user_agent, ip_address)` |
| `session.revoked_at = now` | `session.revoke(now)` |

`auth_service` decides *about* sessions — creating, rotating, revoking — but
never names the entity, per ADR 0001. It reaches the aggregate through
`SessionRepository.open_session(...)` and the port's methods.

`revoke_user_sessions` stays a bulk SQL `UPDATE`. It runs inside
`async with UnitOfWork(...)` so it commits explicitly, which is what the
autoflush dependency was actually providing. Password reset revokes sessions it
has not loaded and would not be written to visit individually.

## Rationale

**Sessions belong to the user context, not to authentication.** The row is
`user_id`-scoped state: it has no authentication logic of its own, and every
lifecycle operation is a decision *about* a user account. Authentication owns
the decision; the user context owns the record. This is the same split ADR 0009
used for `User`, and it is why `SessionRepository` sits next to
`UserRepository` rather than in `authentication`.

**Why an aggregate and not a plain repository?** The three mutations were
repeated field assignments at three call sites, and the rules around them are
not obvious. `rotate` must not clear `user_agent` when a cookie-less browser
refresh sends none — a blank would erase the detail that makes a session row
worth keeping. `revoke` must not move an existing `revoked_at`, because that
timestamp is when the session actually died. `rotate` must not change `id`,
because the access token stays bound to the session across a rotation, which is
the mechanism by which revoking a session invalidates its access token. These
are invariants, and they belong with the data.

**Why is `revoke` idempotent but `rotate` not?** Both may be called twice on the
same entity, and both should not move the recorded time — but they record
different things. `revoke` records a fact about the past, and the first
observation of it is the accurate one. `rotate` records the last time the token
was used, where a later value is simply more current. So `revoke` keeps the
first timestamp and `rotate` overwrites. Making them symmetric would have been
tidier and wrong for one of them.

**Why `save` and not `flush`?** `flush` would keep the implicit dependency on a
later read, which is the failure being fixed. Requiring `save` makes the write
legible at the call site: a reader can see that rotation persists and revocation
persists, which is not visible when both are attribute assignments.

**Why not narrow `AuthenticationUnitOfWork.session_repo` to the port?** R2
forbids a bounded context importing another context's `domain` at all, not even
its ports — only `app/infrastructure/**` and `app/modules/shared/**` are port
readers. So the annotation stays `object`. See "Consequences".

## Consequences

**Good**

- Rotating a session and logging out are now covered by a real-database test
  that reads back through a second session, and both are proven to fail when the
  `save()` is removed.
- The naive-datetime comparison is fixed. `expires_at` is
  `DateTime(timezone=True)`, but SQLite has no timezone type and returns a naive
  `datetime`; the old inline comparison in `_rotate_session` raised `TypeError`
  on SQLite when comparing it to an aware `now`. `_as_utc` in the entity
  normalises on read, matching the Phase 6b entities.
- A driver failure now surfaces as `SessionRepositoryUnavailableError` and a 500
  with a log line, rather than as an escaping `SQLAlchemyError`.
- `to_model` omits `created_at` so a `save()` cannot overwrite the column's
  server default with whatever a detached entity happened to hold.
- The ratchet is down to a single entry.

**Bad**

- `auth_service` calls `rotate` and `revoke` on an entity whose type it cannot
  name, so those calls are structural rather than declared. This is the same
  weakness ADR 0009 recorded for `verify` and `set_password_hash`, now
  repeated. It is a real typing gap, and see below.
- Two more places can be silently wrong if a `save` is forgotten. The existing
  sites are pinned by tests; a new one added later is not.
- The entity holds aware and naive datetimes depending on where it came from,
  because the mapper is a plain field copy and normalisation happens at
  comparison time. This follows the convention the Phase 6b entities already
  set, so it is consistent rather than novel, but it is easy to forget.
- `tests/unit/test_auth_hardening.py::test_revoke_session_is_awaitable` had to be
  rewritten. It pinned `SessionRepo.revoke_session` being a coroutine — a real
  historical bug, since it was a plain `def` while the service awaited it, so
  logout 500'd before clearing cookies. The guarantee is unchanged and now
  checked against the four methods the service actually awaits.

**Neutral**

- No route, schema, or status-code change. Session failures were 500s before and
  are 500s now.
- Public method signatures are unchanged, so the route table is byte-identical.

## The typing gap, stated honestly

`AuthenticationUnitOfWork.session_repo` is `object`, and it cannot be narrowed to
`SessionRepository` under the current rules: R2 rejects the import outright, and
R2 is a hard rule with a zero-violation ratchet, so it cannot be ratcheted
either. The concrete `UnitOfWork` in `app/infrastructure/database/unit_of_work.py`
does the wiring, and it may read other contexts' ports.

The proper fix is a **capability-shaped port**: one the authentication context
owns, declaring the operations it performs — `open`, `rotate`, `revoke` — and
satisfied structurally by the user context's `SessionRepository`. That would
name the capabilities and remove the structural calls.

It is not done here because it is a second description of one repository, which
is a decision about where session capability belongs rather than a mechanical
narrowing, and Phase 7a's scope was the aggregate and the ratchet. It is
recorded in `docs/REVIEW.md` as a Phase 9 item.

`dependencies.py` revalidation still reads the session through the ORM. It is
out of scope for this phase and remains open; see `docs/REVIEW.md`.
