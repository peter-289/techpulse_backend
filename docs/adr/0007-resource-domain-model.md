# ADR 0007 — The `resource` context gets a domain model, and what stays out of it

- Status: accepted
- Date: 2026-09-30
- Refactor phase: 5

## Context

`app/modules/resource` was four flat files at the root of the context:

```
resource_service.py   resource_repo.py   resource_schema.py   resources_router.py
```

The service imported `app.infrastructure.database.models.resource` — the one
R5 entry this phase was assigned. It also held a mutable class-level set:

```python
class ResourceService:
    ALLOWED_TYPES = {"api", "knowledge", "support", "updates"}
```

and five inline normalizations. The repository returned ORM rows, so the router
serialized them through `ResourceRead(from_attributes=True)` and the API contract
was pinned to the shape of a database row.

The context is 185 lines. That is worth stating plainly, because it means this
phase could not create much design; the only question was where the few rules
that exist should live.

## Decision

### 1. `ResourceType` is a `StrEnum` in the domain, not a set in the service

`domain/value_objects/resource_type.py`. The vocabulary belongs to the context
that owns the concept, so it does not go in `app/modules/shared/enums.py`
alongside the genuinely cross-cutting ones. Being a `StrEnum` means the API can
still serialize the bare string `"api"` with no conversion layer.

**Rejected: keep the set, move it to the domain.** A bare set of strings cannot
tell a reader that `"api"` and `"API"` are the same type, and every future caller
has to remember to `.strip().lower()` before comparing.

**Rejected: a free-form `str` with a validator.** The vocabulary is closed. A
validator that accepts anything not on the list is a list.

### 2. Normalization moved to `Resource.create`

`Resource.create` is the sole construction path, so "text is stored trimmed" and
"the slug is stored lowercase" are enforced in one place. `ResourceCreate`
(pydantic) still validates length bounds — that is transport validation, and it
stays at the edge.

### 3. The service takes keyword arguments, not `ResourceCreate`

Moving `resource_schema.py` into `schema/` immediately tripped R4, because the
application layer was importing a schema module that had previously been invisible
to it at the context root. The Phase 3 answer applies: the router unpacks the
payload and the use case receives `title=`, `slug=`, `resource_type=`,
`description=`, `url=`.

This is better than the arrangement it replaces, independent of the layering: a
use case that takes a pydantic model is coupled to the transport's validation
rules, and `min_length=2` on `slug` is a statement about the request, not about
what a Resource is.

### 4. `resource_type` in the domain, `type` on the wire and in the column

The domain entity calls it `resource_type` so the aggregate does not shadow the
builtin. The mapper and the presenter are the only two places that know both
spellings. Renaming the column or the API field would have been a schema and
contract change for no gain.

### 5. The aggregate is deliberately thin, and that is the finding

`Resource` has exactly one behaviour — `create` — and no mutator, because the
API exposes no edit route. There is no `delete()` either: removal is a hard
`DELETE`, which is a statement about the row rather than a change in the
resource's state, so the repository owns it.

The honest conclusion is that a resource has no invariants spanning instances, no
lifecycle and no state machine. It is closer to a typed read model than to an
aggregate root. Building mutators for a future edit route would be speculative,
so the phase deliberately stops at `create` and records the observation instead.

## Consequences

**Good**

- R5's only `resource` entry is gone; the ratchet is down to 14.
- The service no longer imports the ORM, pydantic, or shared-kernel errors.
- 41 new tests, 266 passing, and the rules that the inline string handling used
  to encode are now named and individually testable.
- The type vocabulary is discoverable from the domain rather than by reading a
  service.

**Bad**

- Two mappings (`resource_type`/`type`) now exist where there was one spelling.
  This is the cost of not shadowing a builtin, paid in exactly two files.
- `Resource` is a thin object. Calling it an aggregate overstates it, and the
  module docstring says so.

**Neutral**

- A repository failure is a 500, not a 503. See below.

## Decisions taken to preserve behaviour

**`ResourceRepositoryUnavailableError` maps to 500, not 503.** 503 is the more
truthful code for an unreachable dependency, and Phase 3's software_management
port uses it. But an escaping `SQLAlchemyError` here produced a 500, and
changing that is an observable difference. The code comment in the repository
records that 503 is the intended follow-up.

**A padded type is still rejected.** The service tested `payload.type.lower()`
against the allowed set but stored `payload.type.strip().lower()`, so `" api "`
was rejected even though stripping it yields a legal type. Validating the
normalized value would widen the accepted set. `ResourceType.from_input`
reproduces the asymmetry and names it in its docstring, and a test pins it, so
the quirk is visible instead of being rediscovered as a bug report.

**Deletion stays a hard delete.** Soft-deleting would change what
`GET /api/v1/resources` returns, which is a contract change and not a
refactoring decision.

## Notes for the next phase

The `delete` implementation is a statement-level `DELETE ... WHERE slug = ?`,
not `session.delete(row)`. The service hands the port a detached domain entity,
so the mapped row is transient, and `session.delete()` on a transient instance
raises `InvalidRequestError` — which the repository's `except SQLAlchemyError`
would have swallowed into a 500, turning every 204 into a 500 while looking like
a successful delete. `tests/unit/test_resource_repository.py` covers this and was
mutation-checked by reverting the implementation and confirming the failure.
