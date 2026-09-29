# ADR 0001: Module per bounded context, layers within

- **Status:** Accepted
- **Date:** 2026-09-29
- **Deciders:** backend maintainers
- **Related:** ADR 0002 (mappers live in infrastructure), ADR 0004 (enforce layer boundaries with a ratchet)

## Context

The codebase had grown two incompatible shapes at once.

`software_management` had been partly refactored into
`domain/ entities value_objects events policies ports/`,
`application/ services ports/`, `infrastructure/ persistence time/`,
`api/ routers/`, `schema/`. `ARCHITECTURE.md` calls it the reference
architecture and says every other module should follow it.

Everything else had not. `resource` was four flat files
(`resource_repo.py`, `resource_schema.py`, `resource_service.py`,
`resources_router.py`) with no domain at all. `security` had
`audit.py` (a repository), `audit_service.py` (an application service) and
`audit_middleware.py`, flat. `authentication` had a single `auth_service.py`
handling login, verification, sessions and password reset. `analytics` had one
router containing business logic. `user` had created the directory skeleton —
`domain/entities/`, `domain/ports/repository/`, `domain/exceptions.py` — and
left all five files empty, so the tree advertised a layer that did not exist.

That last case is worth dwelling on, because an empty `domain/` is worse than a
missing one. A reader assumes the domain is implemented and that the services
consult it. Finding five zero-byte files tells them the tree is aspirational,
but it also invites a new contributor to add a domain model beside the code
that never uses it.

Three structural problems followed from the split.

**Infrastructure depended upward.** `app/infrastructure/database/unit_of_work.py`
imported five repositories from five feature modules. Every application service
imported the concrete `UnitOfWork` from that file. So the dependency ran
inward-to-outward and back: `application -> infrastructure -> application`, and
adding a module meant editing a shared file in `infrastructure/`. This is what
produced the import cycle that `tests/unit/test_import_graph.py` was written to
catch.

**The composition root was duplicated and divergent.** `user/dependencies.py`
and `shared/dependencies.py` both defined `get_db`, `get_current_user` and
service factories. The baseline commit consolidated them, but the underlying
question — which layer owns dependency wiring — was still unanswered, and
`shared/dependencies.py` had grown to 402 lines mixing JWT verification, RBAC,
session revalidation and service factories.

**The `UnitOfWork` port did not exist.** `ARCHITECTURE.md` section 10.1
documents a `UnitOfWork` port, and `domain/ports/unit_of_work.py` exists in
`software_management`. It contains a three-line docstring and no code. The real
`UnitOfWork` is the concrete class in `infrastructure/`, which is what
application services actually depend on.

## Decision

**Each feature module is a bounded context with up to four layers inside it:**
`domain/` (entities, value objects, events, policies, ports, exceptions),
`application/` (use-case orchestration, transaction boundaries),
`infrastructure/` (adapters implementing domain ports), and `api/`
(routers) plus `schema/` (Pydantic transport models).

**Dependency direction is inward only:**

```
api  ->  application  ->  domain  <-  infrastructure
```

**A module never imports another module's `domain/`.** Cross-context
communication goes through `app/modules/shared/`, or through domain events. This
is rule R2 in ADR 0004 and it is a hard rule.

**The `UnitOfWork` is a domain port, and each module owns its own
implementation.** A module's application services depend on
`<module>/domain/ports/unit_of_work.py`, not on a shared concrete class in
`infrastructure/`. The shared `UnitOfWork` may be *reused* as a default
implementation, but it is injected, not imported upward. Wiring happens in
`app/modules/shared/container.py`, which is the one place permitted to know
about every module.

## Rationale

**Why layers inside a module rather than layers across the app.** Four
top-level layers (`app/domain`, `app/application`, ...) group by technical role
and force a single global `domain/` package. With six bounded contexts whose
concepts genuinely differ, that produces a god-package in which `User` and
`Software` and `AuditEvent` are siblings. Module-per-context keeps a concept's
entire vertical slice in one directory, so a change to "what a Resource is"
touches one subtree.

The cost is that `api/`, `domain/` etc. are repeated per module. That is
accepted: the repetition is what makes the boundary checkable, since
`tests/architecture/layer_rules.py` resolves layers by path.

**Why cross-context imports are forbidden rather than merely discouraged.**
`app/modules/shared/mappers.py` importing `software_management.domain` meant
that anything importing a shared helper acquired a dependency on the Software
aggregate. It is invisible at the call site and it is exactly the coupling that
makes a bounded context impossible to extract. Forbidding it is cheap to
enforce (R2) and expensive to violate.

`app/exceptions/handlers.py` is the one documented exception: it translates
every context's domain exceptions to HTTP, so it is the single place that must
know about all of them. Encoded in
`PERMITTED_CROSS_CONTEXT_READERS`, not in the ratchet, because it is permanent
by design rather than temporarily tolerated.

**Why the `UnitOfWork` is a port.** An application service that needs a
transaction should depend on "a transaction boundary that gives me
repositories", not on a class that happens to know about every repository in
the system. The current concrete class is a service locator wearing a
transaction's clothes: `self.uow.software_repo`, `self.uow.user_repo`,
`self.uow.resource_repo`, `self.uow.audit_repo` all on one object. Tests must
construct all of it to touch any of it.

Declaring the port does not require splitting the implementation. The
value is in the direction: services import `domain.ports`, and the container
decides whether they get the shared implementation or a per-module one.

**Why composition wiring lives in `app/modules/shared/container.py`.** DI has
to happen somewhere, and the somewhere must see both sides — ports and
adapters. Putting it in each module's own `api/dependencies.py` (the layout
`ARCHITECTURE.md` section 9.1 proposes) means the same 40 lines of
`Depends(...)` plumbing repeated six times, and the baseline commit shows what
that costs: `user/dependencies.py` and `shared/dependencies.py` had already
drifted apart. One container, split by concern, is the cheaper structure.

**Rejected: hexagonal without layers.** A flat `ports/` + `adapters/` per
module would be fewer directories. Rejected because the `domain/` directory
is what ADR 0004's rules measure, and because separating ports from the rules
they support invites putting business logic in the adapter.

**Rejected: keep the anemic services and only add ports.** This is the
"boundaries only" option. It would have made the boundaries enforceable while
leaving the model anemic, which is the failure mode the codebase is already in:
`ResourceService` would have a repository port that returns `Resource` ORM
rows, and the port would be theatre.

## Consequences

**Good**

- The dependency graph becomes a DAG checkable by path, so boundary violations
  are a test failure rather than a review comment.
- A module can be extracted, or its storage swapped, without touching any
  other module's directory.
- `app/modules/shared/dependencies.py` can be split by concern (auth
  verification, RBAC, factories) without any module needing to know which file
  a dependency came from.

**Bad**

- Six copies of `domain/`, `application/`, `infrastructure/`, `api/`. Some
  modules will have layers that are nearly empty, and an empty layer is
  ambiguous — see the `user/domain/` problem in the Context. The convention is
  that an empty layer directory is created only together with its first
  non-empty file.
- The shared `UnitOfWork` has to survive the transition as an injected
  implementation while the ports it satisfies are introduced. There is a period
  where both exist. Keeping one concrete class and adding ports around it is
  the cheapest path through that, and is what Phase 2 does.

**Neutral**

- Nothing forces a module to have all four layers. `analytics` is small enough
  that `api/`, `application/` and `schema/` may be sufficient with no
  `domain/`, provided the rules that shape it are not anemic.
