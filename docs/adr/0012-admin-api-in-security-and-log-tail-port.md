# ADR 0012: The admin API belongs to the security context, and log reading is a port

- **Status:** Accepted
- **Date:** 2026-09-30
- **Deciders:** refactor
- **Related:** ADR 0001, ADR 0002, ADR 0004, ADR 0006, ADR 0011

## Context

`app/modules/user/api/router/admin_router.py` was the last ratchet entry in the
codebase, and it was the only file in the project that broke R6 by name. Five
endpoints lived in it — alert list, alert acknowledgement, audit-event list,
cookie-activity list, and the log tail — and not one of them had a test.

It was in the wrong module, and being in the wrong module was why it looked the
way it did. The tables it reads belong to the security context: `SecurityAlert`
and `AuditEvent`, both modelled in Phase 4. R2 forbids one bounded context from
naming another's domain layer, so from the user context the router had no port to
ask and the ORM models as its only way to read the security tables. It built four
`select()` statements itself, called `db.commit()` directly, and translated
nothing — so R6 recorded it and R4 could not have applied, because there was no
application service in the path to be the thing that was wrong.

The one write, alert acknowledgement, was worse than a layering complaint. It
went straight to the database: `update(SecurityAlertModel)` plus a commit, with
no aggregate, no rule, and no domain event. `SecurityAlert.acknowledge` has
refused a second acknowledgement since Phase 4 and records both the timestamp and
the operator. The endpoint that exists to call it bypassed it.

None of the three list endpoints had ever returned a row. Each ended in
`[AlertModelResponse.model_validate(a) for a in alerts]`, where `alerts` was the
result of `.all()` iterated a second time — an empty sequence, so an empty list.
The endpoints returned `200` with `{"count": 3, "items": []}`, and `count` was
correct, which is what kept it from being noticed.

The log tail was the other thing in the file that did not belong. The router
built a `Path` from `settings.LOG_FILE_PATH`, read the file with a `deque`, and
returned lines — with no redaction of any kind, from an endpoint whose entire
purpose is to make a log readable in a browser.

And `analytics_router` was still building its own `AuditService` from a concrete
`UnitOfWork`, which Phase 4 and ADR 0011 had both flagged.

## Decision

**The router moves to the context that owns the data.**
`app/modules/security/api/router/admin_router.py`. No route path, method, request
shape, status code or response field changes; the route table is byte-identical
to Phase 7b.

**Reads go through the audit repository, in the repository's own language.**
`AuditRepository` gains `get_alert`, `list_alerts` and `list_events`.
`AuditService` gains `list_alerts`, `acknowledge_alert` and `list_events`; the
first and last run on `uow.read_only()`, and the middle one runs on the write
boundary so the acknowledgement commits with the aggregate that decided it.

**Acknowledgement goes through the aggregate.** `acknowledge_alert` calls
`SecurityAlert.acknowledge`, so the endpoint now honours the rule that was
already written, and a repeat call raises `AlertAlreadyAcknowledgedError` instead
of silently restamping the first operator's name.

**Log reading is a port.** `LogTail` in
`app/modules/security/domain/ports/log_tail.py`, implemented by `FileLogTail` in
this context's `infrastructure/logs/`. The port's contract is not "returns lines"
but "returns lines that are safe to send to a browser", which is why redaction
lives in the adapter: an implementation that returned raw lines would satisfy the
signature and break the promise.

**Analytics asks the composition root for its service.** `get_audit_service`
instead of `UnitOfWork` plus `AuditService` constructed in the router.

## Rationale

**Why move the file rather than leave it and add a service.** Leaving it would
have meant the user context reading two other contexts' tables. The alternative
shape — keep the router in `user/`, inject the security service — was rejected for
a specific reason: R7 forbids one context's API layer from importing another's,
so a `user/` router calling a security service is a rule violation in its own
right. The file's location and its data access are the same decision.

**Why a port for the log rather than a helper function.** A module-level
`sanitize()` called from a router would have satisfied R8 by import graph alone
while leaving the dependency invisible: nothing would say that this endpoint
touches the filesystem, and the next reader would add a second log format beside
it. The port makes it a named, testable capability, and it is what lets
`FileLogTail` be pointed at a `tmp_path` in a test without touching settings.

**Why redaction in the adapter rather than in the port's caller.** Same argument:
one definition of "a credential" in the codebase, and the contract stated where it
is kept.

**Why `Session.merge`.** The alert already exists; the write is an update of a
loaded aggregate. `merge` matches on the primary key, which requires the mapper to
pass `id` — the detail that turned out to matter, below.

## Consequences

**Good**

- R6 has no entries. The ratchet is empty, so all eight rules are hard and the
  layer tests fail on any new violation.
- The three list endpoints return rows. This is a **client-visible behaviour
  change** and the only one: an operator asking for alerts now gets them.
- Acknowledgement is decided by the aggregate. The first acknowledgement's
  timestamp and operator are no longer at risk from a second click.
- Two tests are now capable of failing that were not: the repository tests catch
  a duplicate insert on acknowledgement, and the redaction tests catch a
  credential shape the patterns do not cover.
- `created_at` is no longer written by `alert_to_model`, matching
  `session_mapper.to_model`. It is `nullable=False` with a server default, so
  copying an entity's value over it on update was one unpopulated entity away from
  a constraint violation.

**Bad**

- The redaction patterns are a heuristic. They cover `key=value`, `key: value`,
  quoted JSON values, and `Bearer`/`Basic` headers; they do not cover a credential
  whose key is not recognisable, or a multi-word unquoted value. This is inherent
  — a regex cannot know every key name — and it is why the patterns are pinned one
  at a time so a new shape is a visible gap rather than a silent leak.
- `.gitignore` had `logs` unanchored, which matched the new
  `infrastructure/logs/` package and would have left it out of the commit while
  every import of it stayed in. Fixed by anchoring the ignore to `/logs/` and
  re-including the package.

**Neutral**

- `count` still equals the number of returned items, not the number of rows
  matching the filter. Unchanged, and now tested rather than incidental.
- All three acknowledgement outcomes still return 200, and the not-found body
  still omits `alert_id`. Unchanged.
- `alert_to_entity` converts `rule_code` and `severity` strictly, so a row holding
  a value outside the vocabulary raises rather than being displayed. The only
  writer of the table is `AuditService._raise_alerts_for`, so this means "written
  by something other than this application", and an alert whose code the domain
  cannot name is not one to show as if it were.
- **Five routers still construct a concrete `UnitOfWork`** — `auth_router`,
  `resources_router`, `category_router`, `support_chat_router`, `user_router`.
  That is composition-root work inside a router and it is now the largest
  remaining instance of the pattern this phase set out to remove. A rule banning
  it would need five ratchet entries, and growing a file whose stated contract is
  that it can only shrink is the wrong trade for the last phase of the drain.
  Phase 9.
