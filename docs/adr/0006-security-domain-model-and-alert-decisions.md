# 0006. Give the security context a domain model, and decide alerts in the domain

- **Status:** Accepted
- **Date:** 2026-09-30
- **Related:** 0001, 0002, 0004, 0005

## Context

`software_management` had a domain model after Phase 3. The security context
still had none, and it is the context that runs on every request.

**The audit trail was a table, not a concept.** `app/modules/security/audit.py`
was a repository that took SQLAlchemy constructs:

```python
async def count_events(self, predicates: list[ColumnElement[bool]]) -> int:
```

`AuditService` built the predicates, so it imported
`app.infrastructure.database.models.audit_event` and `security_alert` and wrote
`AuditEvent.event_type == event_type` inline. The port that was supposed to be
the boundary had the query shape on its own signature — the application layer was
writing SQL through a hole shaped like an interface. R5 recorded both imports as
known violations, which is how the model was known to be missing.

**The alerting rules were a branch against a global.** `_detect_and_create_alerts`
was an `if` / `elif` chain over `settings.ALERT_*`. The rules deciding when a
security system raises an alert — arguably the highest-value logic in this
context — could not be exercised without a database and a process global. There
was no test for `AuditService` at all.

**Two things had no invariant and should have had one.** The service truncated
`path` to 500 characters while the column is `varchar(255)`: a request with a
path between those lengths raised a database error and lost the audit event,
which is the one class of record that must not be droppable. And `acknowledge`
did not exist — `admin_router` set `acknowledged = True` on the ORM row directly,
so acknowledging twice was indistinguishable from acknowledging once, which is
the first question an incident review asks.

## Decision

Give the context an entity, an aggregate, a value object and a policy; make the
port speak domain terms; and inject the thresholds.

- `domain/entities/audit_event.py` — `AuditEvent`, an immutable fact. It owns
  validity: a blank type or path, or a status code outside 100–599, is rejected
  rather than stored. It does *not* own column widths; the mapper truncates.
- `domain/entities/security_alert.py` — `SecurityAlert`, an aggregate root with
  one lifecycle operation, `acknowledge`, which refuses to acknowledge twice.
- `domain/ports/alert_thresholds.py` — `AlertThresholds`, built once at the
  composition root from `settings` and injected into the service.
- `domain/policies/alert_rules.py` — the rules, as pure functions.
  `rules_for` selects; `AlertRule.exceeded_by` and `raise_alert` decide.
- `domain/ports/repositories/audit_repository.py` — four methods in words:
  `save_event`, `count_events`, `has_unacknowledged_alert`, `save_alert`.
- `infrastructure/persistence/{mappers,repositories}/audit_*.py` — the SQLAlchemy
  implementation, and the only place a `SQLAlchemyError` is caught.
- `AuditService` moves to `application/services/`, importing neither the ORM nor
  `app.core`.

## Rationale

**The port takes words, not predicates.** `count_events(event_type=..., since=...)`
instead of a caller-built expression list. The alternative — a narrower port per
query — multiplies methods without reducing leakage, because the caller still
names the columns. Naming a domain concept is a dependency on the *model*;
naming a column is a dependency on the *store*, and the store is what the
repository exists to hide.

**Selection is split from evaluation.** `rules_for` answers "could this event
trigger anything?" in a dict lookup; the count that follows is I/O, so the
service fetches it and the policy decides afterwards. The obvious alternative —
one function that takes a counting callable and is async — puts a port inside
the domain and makes every rule test require a double. The cost of the split is
a two-step call; the benefit is that the hot path pays nothing. An audited 200
must cost one dict lookup, not a `COUNT(*)`; `test_ordinary_traffic_raises_nothing_and_counts_nothing`
asserts exactly that, and fails if the count is ever hoisted out of the loop.

**`AlertThresholds` lives in `domain/ports/`, not `domain/value_objects/`.**
R2 allows the composition root to reach another context's ports and nothing else,
so a value object there is a new R2 violation. It is configuration handed to a
use case rather than a concept the domain reasons about, so the ports package is
where it belongs anyway — and it is the placement `UploadLimits` was given in
Phase 3, for the same reason, in the same commit as the rule that requires it.
The alternative was widening `_is_port` to admit `domain.value_objects` for every
context, which weakens a guard to accommodate one class of import.

**Path truncation moved to the mapper.** A fixed character limit is a property of
`varchar(255)`, not of "a request". Keeping it in the domain would have the
domain know the column width; keeping it in the service is what produced 500
against 255. The mapper now truncates, and the entity keeps the path whole.

**`SecurityAlert` records no domain events.** It could inherit `AggregateRoot`
and have a queue to fill, but this context has no `DomainEventPublisher` wired,
so every recorded event would be exactly the construct-and-drop pattern Phase 3
deleted from the upload path. The base class arrives with the publisher.

## Consequences

**Good**

- R5 drops from 7 violations to 5; both Phase 4 entries are gone and the
  ratchet shrank rather than grew.
- The alerting rules are 17 tests with no database and no global, including the
  "no rule watches this event type" cases that keep the hot path free.
- A repository failure now surfaces as `AuditRepositoryUnavailableError`,
  translated in one place. Phase 3 removed a duplicate `except SQLAlchemyError`
  for exactly this reason.
- The path-truncation mismatch is fixed, and `test_a_long_path_is_recorded_rather_than_rejected`
  fails if it comes back.

**Bad**

- `admin_router` still imports both ORM models and writes `acknowledged`
  directly, so the new `acknowledge` is not yet on the live path. Assigning it
  to Phase 8 means the aggregate's lifecycle is currently exercised only by tests.
- The analytics router still builds its own `AuditService` from a concrete
  `UnitOfWork`, and still reaches across into the security context's application
  layer. Phase 8 owns both.
- `AuditEventType` still describes only 2 of the ~5 event types actually written.
  The vocabulary is incomplete; the policy keys off the two it needs and treats
  the rest as uninteresting, which is correct but not tidy.

**Neutral**

- No API change. 54 method+path entries, route table hash identical.
- No schema change, no migration.
- `count_events` and `has_unacknowledged_alert` treat an unset actor or address
  differently on purpose: counting omits the constraint, deduplication requires
  `IS NULL`. Sharing one helper between them would have changed deduplication to
  "any anonymous actor", letting one client's alert suppress another's.
