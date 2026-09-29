# ADR 0004: Enforce layer boundaries with a ratchet

- **Status:** Accepted
- **Date:** 2026-09-29
- **Deciders:** backend maintainers
- **Supersedes:** nothing
- **Related:** ADR 0001 (module-per-bounded-context), ADR 0002 (mappers live in infrastructure)

## Context

`app/modules/software_management/ARCHITECTURE.md` states the dependency
direction and the quality gates:

> **Quality Gates** — 1. Import Linting: Domain layer imports only from
> `stdlib`, `uuid`, `datetime`, `typing`. 4. No Framework Leakage:
> `SQLAlchemyError`, `HTTPException`, and `Pydantic` models never appear in
> Domain or Application layers.

None of it was enforced. `ARCHITECTURE.md` had drifted from the code it
describes: section 5.1 documents a `SoftwareRepository` protocol where the code
has an `ISoftwareRepository` ABC, section 7.1 documents
`Storage.create_download_url` where the port has `save`/`open`/`delete`/
`exists`, and section 10.1 documents a `UnitOfWork` port that
`domain/ports/unit_of_work.py` does not define (it is a three-line docstring
stub). A document that is wrong about the code is worse than no document,
because it invites reviewers to approve against a fiction.

At the start of the refactor the real state was:

| Rule | Violations |
|---|---|
| R1 domain imports a framework | 0 |
| R2 module imports another module's domain | 6 |
| R3 domain imports infrastructure | 0 |
| R4 application imports api/schema/infrastructure | 1 |
| R5 application service imports an ORM model | 7 |
| R6 API router builds SQLAlchemy statements | 1 |
| R7 module's API imports another module's API | 0 |

Three rules pass today and four do not. Writing a gate that requires all seven
to be clean from day one would have meant the gate could not land until the
entire refactor was finished, which is exactly when a guard is least useful.

## Decision

Introduce `tests/architecture/layer_rules.py`, which parses the import graph of
`app/` with `ast` and evaluates seven rules. `test_layer_boundaries.py` runs it
in CI.

Known violations are recorded in `tests/architecture/ratchet.json`. The
comparison against the ratchet is **strict equality in both directions**:

- a violation present in the code but absent from the ratchet **fails** — the
  regression guard;
- a ratchet entry whose violation no longer occurs **also fails** — the entry
  is stale and must be deleted.

Each ratcheted rule carries a `_phase` naming the refactor phase that removes
it, and a test asserts that field is present, so no entry can be added without
a commitment to remove it.

## Rationale

**Why a ratchet rather than "fix everything first".** The refactor is
incremental by decision. Each phase is independently reviewable, and a gate that
blocks merges until all four violations are gone would either be disabled on
day one or force one enormous unreviewable commit. The ratchet keeps CI green
for work that is genuinely unrelated while making the remaining debt explicit,
scored and shrinking.

**Why strict equality in both directions.** A one-directional ratchet (fail
only on new violations) is the common form and it is a trap. Stale entries are
invisible, the file grows until nobody reads it, and a reviewer can no longer
tell which entries are load-bearing. Failing on stale entries forces cleanup
in the same commit as the fix, so `ratchet.json` is always an accurate,
current statement of what is still wrong. The cost is a small amount of
churn when a violation is fixed; that is the point.

**Why `ast` in the test suite rather than `import-linter`.** `import-linter`
needs its own config file, its own invocation, and its own version pinning,
which means a CI step that does not run under the project's pytest. Keeping the
rules in the suite means `python -m pytest` is the single command that proves
the architecture holds, and each rule's docstring states the rule in prose
rather than in a config dialect.

The acknowledged cost: AST analysis sees only static `import` statements. An
`importlib.import_module` call or a runtime-injected dependency would not be
caught. Every cross-module reference in this codebase is a static import, and
`test_import_graph.py` separately guards against import cycles, so the gap is
not currently load-bearing.

**Why `handlers.py` is a documented exception to R2, not a ratchet entry.**
`app/exceptions/handlers.py` must translate every bounded context's domain
exceptions into HTTP responses, so it is the one place that is *expected* to
know about all contexts. A ratchet entry implies "temporarily tolerated, to be
removed"; this is permanent by design, so it is encoded in
`PERMITTED_CROSS_CONTEXT_READERS` with its reason, and the reason is visible
next to the rule.

## Consequences

**Good**

- A new boundary violation fails CI with the exact file and import named.
- `ratchet.json` is a live, ordered to-do list of remaining architecture debt.
  Its length is a metric: 15 entries at the start of the refactor, 0 at the end.
- The rules are executable prose, so they cannot drift from the code the way
  `ARCHITECTURE.md` did. Phase 9 rewrites that document to match reality, and
  these tests are what keep it honest.

**Bad**

- Two rules currently pass only because the code happens to be correct. They
  are not proof of correctness; they are tripwires. R1 in particular will only
  fire the first time someone imports a framework into a domain module.
- Strict equality means a fix and its ratchet cleanup must land together,
  otherwise CI is red. Intended, but it will surprise someone eventually.
- R5 and R6 are heuristics, not proofs. R5 keys on the `_service.py` suffix,
  so a service named `SoftwareOperations.py` escapes it. R6 bans a set of
  SQLAlchemy submodules, so `sqlalchemy.text()` in a router would slip past.
  Both are documented in the rule docstrings.

**Neutral**

- `ratchet.json` reaching zero entries is not a stopping condition. Deleting
  the file and the ratchet parameterisation at that point is a deliberate
  follow-up decision, not something this ADR commits to.
