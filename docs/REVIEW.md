# Refactor review notes

Phase-by-phase record of the DDD refactor, written for review. Each phase states
what moved, why, and the argument that behaviour is unchanged.

**Read alongside:** `docs/adr/` (why) and
`app/modules/software_management/ARCHITECTURE.md` (what the target is).

**Invariant for every phase:** the HTTP API — paths, methods, status codes,
request and response bodies — does not change. If a phase alters a response
shape, that is called out explicitly as a breaking change and justified.

---

## Status

| Phase | Scope | Tests | ADRs | State |
|---|---|---|---|---|
| 0 | Baseline commit; dependency and artefact hygiene | 117 pass, 2 pre-existing fail | — | merged |
| 1 | Layer boundary enforcement; mapper/presenter split | 128 pass, 2 pre-existing fail | 0001, 0002, 0004 | merged |
| 2 | `UnitOfWork` port; composition-root split | — | — | pending |
| 3 | `software_management` into line with its own rules | — | — | pending |
| 4 | `security` domain model | — | — | pending |
| 5 | `resource` domain model | — | — | pending |
| 6 | `user` domain model | — | — | pending |
| 7 | `authentication`; split `dependencies.py` | — | — | pending |
| 8 | `analytics`; `admin_router` queries | — | — | pending |
| 9 | Drain ratchet, re-enable tests, correct `ARCHITECTURE.md` | — | — | pending |

The 2 failures are pre-existing on `main` and unrelated to the refactor; see
Phase 0.

---

## Phase 0 — Baseline

### Why

The working tree had 24 modified files and 14 untracked paths: a staged
deletion of `user/dependencies.py`, nine new test modules, `pytest.ini`,
`tests/conftest.py`, a CI workflow and two untracked Alembic revisions. This
was a migration in progress with no commit boundary, so any refactor diff would
have been unreviewable — every file would show both the migration and the DDD
change at once.

Committing it first gives every subsequent phase a base where the diff contains
only DDD work.

Three hygiene problems surfaced while establishing a working baseline, and are
fixed here because they blocked the work:

### 0.1 `storage/` was tracking user-uploaded files

`storage/` holds artifacts uploaded through the software management API and
served back over
`GET /api/v1/software-management/storage/download/{storage_key}`. It is
end-user content. `.gitignore` did not cover it, so **9 files were tracked**,
including uploaded `.py` scripts and `.txt` payloads, and they would be
re-committed on every change.

`storage/` is now ignored and the paths were removed from the index with
`git rm --cached`. **The files were left on disk** — `LocalStorage` keeps
working for local development.

> The blobs remain reachable in existing history. If any of those uploads
> should be treated as disclosed, they need to be rotated out of reach
> separately (`git filter-repo` plus a force-push, or rotating the upload
> storage namespace). That is a judgement call about exposure, so it is flagged
> rather than actioned.

### 0.2 `requirements.txt` was unresolvable

`httpx` was pinned twice — `0.27.2` at line 30 and `0.28.1` at line 60 — so
`pip install -r requirements.txt` failed with `ResolutionImpossible`. The test
tooling block added the `0.28.1` pin and the old one was never removed. **CI
was failing at the install step for this reason**, which is why the untracked
CI workflow had never reported anything.

Kept `0.28.1`, which `starlette 0.38.6` supports. This is what made a local
test environment possible at all, and therefore what made behaviour
preservation checkable in every later phase.

### 0.3 Pre-existing test failures

`tests/unit/test_search_algorithm.py` has 2 failures on the baseline:

```
test_popularity_increases_score  assert 'popularity' in scored[0].matched_fields
test_recency_prefers_newer       assert 'recency' in scored[0].matched_fields
```

`SearchAlgorithm.rank` computes the recency and popularity contributions and
applies them to the score, but never records them in `matched_fields`. The
ranking is correct; only the explanatory field is empty. Unrelated to DDD and
left alone until Phase 9, so it does not get conflated with a structural
change. Every phase below therefore reports **"N pass, 2 pre-existing fail"**
and that is the expected result.

---

## Phase 1 — Layer boundary enforcement, and the mapper split

### Why first

`ARCHITECTURE.md` claimed a set of quality gates that nothing enforced, and the
document had drifted from the code it described:

| `ARCHITECTURE.md` says | Code has |
|---|---|
| §5.1 `SoftwareRepository` protocol | `ISoftwareRepository` ABC |
| §7.1 `Storage.create_download_url(storage_key, expires_in)` | `save` / `open` / `delete` / `exists` |
| §10.1 `UnitOfWork` port in `domain/ports/` | three-line docstring stub, no code |
| §5.3 mappers in `infrastructure/persistence/mappers/` | `app/modules/shared/mappers.py` |

A reviewer approving against a document that describes a different codebase is
worse than having no document. Phase 1 makes the rules executable, so the
document can be corrected against something real in Phase 9.

Writing all seven rules as hard requirements would have blocked CI until the
entire refactor finished — precisely when a guard is least useful. So they are
enforced through a **ratchet**: known violations are listed, and the list can
only shrink. Full rationale in `docs/adr/0004`.

### What was added

`tests/architecture/layer_rules.py` — parses the import graph of `app/` with
`ast` and evaluates seven rules. Run it directly for a report:

```console
$ python -m tests.architecture.layer_rules
[ok]        R1: domain must not import fastapi/starlette/sqlalchemy/pydantic/redis/jose/httpx
[ok]        R2: a module must not import another module's domain layer (use app.modules.shared)
[ok]        R3: domain must not import infrastructure (ports belong in domain, implementations in infrastructure)
[ratcheted] R4: 1 known violation(s) recorded in the ratchet -- application must not import api/schema/infrastructure
[ratcheted] R5: 7 known violation(s) recorded in the ratchet -- an application service must not import an ORM model (it has no domain object)
[ratcheted] R6: 1 known violation(s) recorded in the ratchet -- an API router must not build SQLAlchemy statements
[ok]        R7: a module's API layer must not import another module's API layer
```

| Rule | Statement | Baseline |
|---|---|---|
| R1 | domain imports no framework | 0 — hard |
| R2 | no cross-context `domain/` imports | 6 — **fixed in this phase** |
| R3 | domain imports no infrastructure | 0 — hard |
| R4 | application imports no `api`/`schema`/`infrastructure` | 1 — ratcheted |
| R5 | no service imports an ORM model | 7 — ratcheted |
| R6 | routers build no SQLAlchemy statements | 1 — ratcheted |
| R7 | no cross-context `api/` imports | 0 — hard |

`tests/architecture/test_layer_boundaries.py` runs them in CI as a separate job
so a boundary regression is reported as an architecture failure rather than
buried among test failures.

### The ratchet fails in both directions

Worth calling out because it is the part that is easy to get wrong. A
one-directional ratchet (fail only on *new* violations) is the common form and it
is a trap: stale entries are invisible, the file grows until nobody reads it,
and a reviewer can no longer tell which entries are load-bearing.

Here, an entry whose violation no longer occurs **also fails**, forcing the
cleanup to land in the same commit as the fix. Both directions were verified:

```console
# inject a new violation
$ printf '\nfrom app.infrastructure.database.models.user import User\n' >> .../software_service.py
$ python -m pytest tests/architecture -q
E  AssertionError: R5: an application service must not import an ORM model
E  A new violation was introduced and is not recorded in ratchet.json. Fix it rather than allowlisting it.
E  .../software_service.py -> app.infrastructure.database.models.user
1 failed, 10 passed

# inject a stale entry
E  AssertionError: R4: application must not import api/schema/infrastructure
E  These violations are listed in ratchet.json but no longer occur. Delete the entries.
1 failed, 10 passed
```

Each ratcheted rule also carries a `_phase` naming the refactor phase that
removes it, and a test asserts the field is present — so no entry can be added
without a commitment to remove it.

### 1.1 `app/modules/shared/mappers.py` split

Writing R2 surfaced a violation the initial survey had missed. `shared/mappers.py`
was 212 lines mixing four unrelated kinds of logic, and its location meant the
shared kernel depended on `software_management`'s domain: anything importing a
shared helper silently acquired a dependency on the `Software`, `Version` and
`Artifact` entities.

The callers already drew the correct boundary, so the split follows them:

| Old | New home | Layer |
|---|---|---|
| `*_to_entity`, `*_to_model` | `infrastructure/persistence/mappers/software_mapper.py` | infrastructure |
| `_software_item`, `_version_item` | `api/presenters.py` | api |
| `_error` | `api/errors.py` | api |
| `_actor_uuid`, `_actor_int` | deleted — unreferenced | — |
| `_category` | `api/presenters.py` | api |

The leading-underscore mappers were renamed to public names
(`software_to_entity`, `software_to_model`) because they are now imported across
a package boundary, where a leading underscore reads as "private".

`ARCHITECTURE.md` §5.3 already specified the right location; the file was simply
in the wrong place. Rationale in `docs/adr/0002`.

**This is the R4 violation's sibling.** `software_service.py:148` builds the
same `SoftwareVersionRead` shape inline that `version_item()` builds. After this
phase both exist, in different layers. Phase 3 deletes the copy in the service.

### Behaviour is unchanged

| | Before | After |
|---|---|---|
| Tests | 117 pass, 2 pre-existing fail | 128 pass, 2 pre-existing fail (+11 architecture) |
| HTTP API | — | identical |
| DB schema | — | identical; no migration |

The 11 new tests are the architecture suite. `test_import_graph.py` (which
guards against import cycles) still passes, as does `test_model_metadata.py`.

### Known limits of the new guard

Stated here rather than only in the ADR, because a reviewer should know what
the gate does not catch:

- **Static imports only.** An `importlib.import_module` call or a
  runtime-injected dependency would not be seen. Every cross-module reference
  in this codebase is a static import today, and `test_import_graph.py` covers
  cycles separately.
- **R5 keys on the `_service.py` filename suffix.** A service named
  `SoftwareOperations.py` would escape it. The rule is a heuristic for "this
  file is a use-case orchestrator"; renaming to dodge it is possible but
  visible in review.
- **R6 bans a fixed set of SQLAlchemy submodules.** `sqlalchemy.text()` in a
  router would slip past. The ban targets statement construction, which is what
  actually occurred in `admin_router.py`.
- **R1, R3 and R7 pass today only because the code happens to be correct.**
  They are tripwires, not proof. R1 in particular has never fired.
