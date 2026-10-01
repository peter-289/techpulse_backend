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
| 2 | `UnitOfWork` port; storage port consolidation | 150 pass, 2 pre-existing fail | 0001, 0003, 0004 | merged |
| 3 | `software_management` into line with its own rules | 178 pass, 2 pre-existing fail | 0001, 0004, 0005 | merged |
| 4 | `security` domain model; alerts decided in the domain | 225 pass, 2 pre-existing fail | 0001, 0002, 0004, 0006 | merged |
| 5 | `resource` domain model | 266 pass, 2 pre-existing fail | 0001, 0002, 0004, 0007 | merged |
| 6a | `user`/support-chat: ChatMessage entity, AI provider port | 308 pass, 2 pre-existing fail | 0001, 0002, 0004, 0008 | merged |
| 6b | `user`/`User` aggregate; explicit `save` on the user repository | 394 pass, 2 pre-existing fail | 0001, 0002, 0009 | merged |
| 7a | `user`/`UserSession` aggregate; explicit `save` on the session repository | 456 pass, 2 pre-existing fail | 0001, 0002, 0010 | merged |
| 7b | split `shared/dependencies.py`; revalidation off the ORM | 471 pass, 2 pre-existing fail | 0001, 0011 | merged |
| 8 | `admin_router` into `security`; `LogTail` port; ratchet drained | 567 pass, 2 pre-existing fail | 0001, 0002, 0012 | merged |
| 9a | Correct `ARCHITECTURE.md`; ports may not silently default | 636 pass | 0001, 0004, 0013, 0014 | merged |

The 2 failures recorded against phases 0–8 were pre-existing on `main` and
unrelated to the refactor (Phase 0). Both were `search_algorithm` tests that had
been failing since the baseline and are fixed in Phase 9a.

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
[ok]        R4: application must not import api/schema/infrastructure
[ok]        R5: an application service must not import an ORM model (it has no domain object)
[ratcheted] R6: 1 known violation(s) recorded in the ratchet -- an API router must not build SQLAlchemy statements
[ok]        R7: a module's API layer must not import another module's API layer
[ok]        R8: an application service must not import the web framework, the ORM, or the filesystem
```

| Rule | Statement | Baseline | Now |
|---|---|---|---|
| R1 | domain imports no framework | 0 | 0 — hard |
| R2 | no cross-context `domain/` imports | 6 | 0 — **fixed in Phase 1** |
| R3 | domain imports no infrastructure | 0 | 0 — hard |
| R4 | application imports no `api`/`schema`/`infrastructure` | 1 | 0 — **fixed in Phase 6b** |
| R5 | no service imports an ORM model | 7 | 0 — **fixed in Phase 7a** |
| R6 | routers build no SQLAlchemy statements | 0 | 0 — **fixed in Phase 8** |
| R7 | no cross-context `api/` imports | 0 | 0 — hard |
| R8 | services import no web framework, ORM, or filesystem | 0 | 0 — **fixed in Phase 7a** |

The R2 row deserves a note, because the count went *up* before it went to zero.
Introducing the per-context `UnitOfWork` ports in Phase 2 made the shared
`UnitOfWork` adapter and the composition root import five contexts' `domain.`
trees, which the original rule read as a violation. Refining the rule was the
right call rather than the code, but only because the refinement is narrow:
`app/infrastructure/**` and `app/modules/shared/**` may import another
context's `domain.ports` and nothing else. They may not import its entities or
value objects, which is what keeps the Phase 1 mapper split from eroding. See
`PORT_READERS` in `tests/architecture/layer_rules.py`.

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

---

## Phase 2 — The `UnitOfWork` and storage ports

### Why

Eight application services imported the single concrete
`app/infrastructure/database/unit_of_work.py`, and
`local_storage.py` defined its own `Storage` protocol, its own signer protocol
and its own six-class `StorageError` hierarchy next to the domain's.

The duplicate exception hierarchy was not tidiness. When `download_service` was
pointed at the domain exceptions, every `except StorageFileNotFoundError` in it
went dead: the adapter raised the *infrastructure* class, which is not a
subclass of the domain one. A missing artifact would have escaped its handler
and surfaced as a 500 from an unrelated frame.

### What moved

- `app/modules/shared/unit_of_work.py` holds the transaction contract; each
  context declares its own port listing only its own repositories. Ports are
  `Protocol`s, so one concrete adapter satisfies all five, and it asserts
  conformance to them at import time — a protocol is structural, so a missing
  repository is otherwise an `AttributeError` on the first request that needs
  it.
- The storage contract and exception hierarchy consolidate into
  `domain/ports/storage.py`.
- R2 is refined, not relaxed: `app/infrastructure/**` and
  `app/modules/shared/**` may import another context's `domain.ports` and
  nothing else.

### Result

R4 11 -> 5, ratchet 19 -> 13, route table unchanged. `tests/unit/test_storage_port.py`
asserts the adapter's exception names *are* the domain's, by identity, so the
split cannot come back silently. Full record in `docs/adr/0003`.

### Behaviour is unchanged

| | Before | After |
|---|---|---|
| Tests | 128 pass, 2 pre-existing fail | 150 pass, 2 pre-existing fail |
| HTTP API | — | identical; route table hash unchanged |
| DB schema | — | identical; no migration |

### Carried into Phase 3

ADR 0003 put `SignedDownloadUrl` and `DownloadUrlSigner` into
`domain/ports/storage.py` without noticing that `domain/ports/download_signer.py`
already existed. Services imported one pair and the storage adapter the other —
the same class-shape split the ADR had just been written to eliminate, one
directory over. `local_storage.py` also annotated `StorageSettings` and
`DownloadUrlSignerSettings` without importing them, so those annotations would
have raised on `get_type_hints`. Both were corrected in Phase 3.

---

## Phase 3 — `software_management` into line with its own rules

### Why

`ARCHITECTURE.md` §3.3 says the application layer "must never import SQLAlchemy
models, FastAPI types, or filesystem APIs". `SoftwareService` imported
`tempfile` and `app.core.config`; `DownloadService` imported
`fastapi.concurrency` and `sqlalchemy.exc`. Phase 1's gate had not caught any of
it, which turned out to be a hole in the gate rather than a clean bill.

### The gate had a hole (R8)

R4 classifies *project* layers — it sees `app.core`, `app.infrastructure` — but
`fastapi`, `sqlalchemy` and `tempfile` are installed packages that no rule
looked at. R5 banned ORM *models* only, so `sqlalchemy.exc` walked past it.

R8 bans a fixed set of framework and filesystem roots in `*_service.py` files.
Adding it **raised** the ratchet before lowering it, the same way R2 did in
Phase 1: it measures an edge the earlier rules never watched. Of the nine
violations it found, three were `software_management` and six were `user` and
`authentication` — now owned by Phases 6 and 7.

### What moved

| Was | Now | Layer |
|---|---|---|
| `SoftwareService.spool_file` (tempfile + hashlib) | `ArtifactStager` port / `LocalArtifactStager` | domain / infrastructure |
| `settings.PACKAGE_UPLOAD_MAX_SIZE_BYTES` read in the service | `UploadLimits` value object, built at the composition root | domain / shared |
| `uploaded.temp_path.unlink()` in two routers | `stager.discard()` | infrastructure |
| `list_versions` returning `SoftwareVersionRead` | returns `list[Version]`; `version_item()` presents | domain / api |
| `version.download_count += 1; version._touch()` | `Version.record_download()` | domain |
| `run_in_threadpool` | `asyncio.to_thread` | stdlib |
| `except SQLAlchemyError` in `record_download` | deleted; the repository already raises `RepositoryUnavailableError` | — |
| 3 events built and assigned to `_` | recorded by the aggregate, dispatched after commit | domain / application |
| duplicate signer contracts | one definition in `download_signer.py` | domain |

### The events

`SoftwareService` was constructing a `MalwareScanRequestedEvent`, a
`MalwareScanSuccessEvent` and an `ArtifactAddedToVersion` per upload and
assigning each to `_`. `pull_events()` had no callers in the codebase. The
`MalwareScanRequestedEvent` was built *after* the synchronous scan had already
finished, so it announced a request that was already history.

Now `Software.add_artifact_to_version()` attaches the artifact and records the
event together, and the service dispatches to a `DomainEventPublisher` after the
transaction commits — never before, since a rollback would take the facts back.
The adapter is a logger, so no notification behaviour changed; it is the seam a
queue or webhook would be added behind.

The two `MalwareScan*` events were deleted rather than wired. The scan is
synchronous, so there is no outstanding request to announce, and a failed scan
aborts the transaction before anything commits, so there is no durable fact for a
failure event to describe. They become meaningful if the scan is ever made
asynchronous.

### Two events could not be constructed

Phase 3 made the events real, which is what exposed that two of them never
could have been built. `DomainEvent.aggregate_id` is a required keyword-only
field, and `Software.publish()` did not pass it:

```
TypeError: SoftwarePublishedEvent.__init__() missing 1 required keyword-only
argument: 'aggregate_id'
```

`increment_download_count()` had the mirror problem. It passed
`occurred_at=`, and the base field was misspelled `occured_at`. Either side of
that pair had to change, so the typo was fixed in the base class rather than
propagated into a twelfth call site — the event subclasses, the audit table's
column and every other caller already spell it `occurred_at`.

Neither was caught before because `publish()` and `increment_download_count()`
had no test. Both are live: publish is the route that takes software out of
draft, and the counter is bumped on every successful download. What the failure
looked like from outside is worth stating plainly — the exception is raised
*after* the command has mutated the aggregate, so the caller sees a 500 on work
whose state change is already in memory.

`test_every_recorded_event_names_the_aggregate` now runs all thirteen
state-changing commands on `Software` and asserts each recorded event names the
aggregate and the actor. Mutation-checked: removing the `aggregate_id` fix fails
`publish`, restoring the typo fails `increment_download_count`.

`artifact_repository.py` and `category_repository.py` gained the trailing `...`
that the other port files in the context already had. A docstring is a valid
function body, so this is consistency, not behaviour.

### Behaviour is unchanged

| | Before | After |
|---|---|---|
| Tests | 150 pass, 2 pre-existing fail | 178 pass, 2 pre-existing fail |
| HTTP API | — | identical; route table hash identical at HEAD |
| `list_versions` body | — | same `SoftwareVersionRead` payload |
| Oversized upload | 400 | 400 — `StagingTooLargeError` mapped in `handlers.py` |
| DB schema | — | identical; no migration |
| `publish` / `increment_download_count` | `TypeError` | work; the event names the aggregate |

Route table verified by re-computing it from a clean `git worktree` at HEAD and
from the working tree: 54 method+path entries, same SHA-256.

The 15 new passes are the R8 rule (1), the revived `test_upload_limits.py` (6),
`test_software_aggregate_events.py` (4) and `test_software_upload_path.py` (4).

`test_software_upload_path.py` exists because `SoftwareService._process_artifact`
had no test at all. While removing `spool_file` this phase dropped a `pathlib`
import that `_sanitize_filename` still needed, and the suite stayed green —
the next real upload would have failed with `NameError`. The new tests exercise
that path; verified by deleting the import again and watching four tests fail.

### Left alone deliberately

**`SoftwareAccessPolicy` is still unused.** `ensure_can_download` requires
`version.status == PUBLISHED`, but the live path uses
`Version.is_downloadable()`, which also accepts `DEPRECATED`; it also requires
`software.is_public()` even for a buyer, which the live path does not. It
additionally takes a parameter named `owns_software` that any caller would have
to pass `has_purchase` into, so a purchasing-but-not-owning user hits "Only
active owners may download". Adopting it would be a behaviour change wearing a
cleanup's clothes, so it waits for the phase that brings download tests with it.

**The download access check is still in three places.** `SoftwareService.
download_url` and `.download_artifact_url` each repeat the same two-line
purchase/ownership/visibility test, and `DownloadService.create_download_url`
repeats a third, slightly different copy that checks visibility but not
`requires_payment()`. Collapsing them would mean picking one behaviour, which
is a decision about the API rather than about layer boundaries. Flagged, not
normalised.

**`SoftwareAccessPolicy` is also defined twice** — in
`domain/policies/software_access_policy.py` and again in
`policies/software_access_policy.py`, byte-identical apart from a trailing
newline. The same class-shape duplication ADR 0003 addressed for the storage
exceptions, but here no code imports either copy, so nothing is broken yet.
Worth folding in when the policy is adopted.

---

## Phase 4 — the `security` domain model

### Why

Phase 3 gave `software_management` a domain model. The security context still
had none, and it is the one that runs on every request: the audit trail is
written by middleware for every API call.

The port made the gap legible. `AuditRepository.count_events` took
`list[ColumnElement[bool]]`, so `AuditService` built `AuditEvent.event_type ==
event_type` inline and imported both ORM models to do it. A port with the query
shape on its signature is the application layer writing SQL through a hole
shaped like an interface — R5 had both imports recorded, which is how the missing
model was known.

The alerting rules were an `if` / `elif` chain over `settings.ALERT_*`, and
`AuditService` had no test at all. So the logic that decides when a security
system raises an alert was both the least testable code in the context and the
code with no coverage.

### What moved

| Was | Now | Layer |
|---|---|---|
| `AuditEvent` ORM row built by the service | `AuditEvent` entity with validity rules | domain |
| `SecurityAlert` ORM row | `SecurityAlert` aggregate with `acknowledge` | domain |
| `settings.ALERT_*` read inside the service | `AlertThresholds`, injected from the composition root | domain / shared |
| `if`/`elif` over event types in the service | `rules_for` + `AlertRule` in `alert_rules` | domain |
| `count_events(predicates: list[ColumnElement])` | `count_events(event_type=..., since=...)` | domain |
| `get_alert(predicates)` | `has_unacknowledged_alert(...) -> bool` | domain |
| `app/modules/security/audit.py` | `security/infrastructure/persistence/repositories/audit_repo.py` | infrastructure |
| mappers inline in the repository | `security/infrastructure/persistence/mappers/audit_mapper.py` | infrastructure |
| `audit_service.py` at the context root | `application/services/audit_service.py` | application |

### The rules are selected, then evaluated

`rules_for` answers "could this event trigger anything?" in a dict lookup.
`AlertRule.exceeded_by` and `.raise_alert` decide. The split exists because the
count between them is I/O: the service has to fetch it, so the decision cannot be
one call without putting a port inside the domain.

The alternative — one async function taking a counting callable — makes every
rule test need a double. The split costs a two-step call and buys the property
that matters: an audited 200 costs one dict lookup and no query.
`test_ordinary_traffic_raises_nothing_and_counts_nothing` asserts zero count
calls, and fails if the count is ever hoisted out of the loop.

`AlertThresholds` went into `domain/ports/` rather than `domain/value_objects/`
because R2 lets the composition root reach another context's ports and nothing
else, so the other location was a new violation on import. It is configuration
handed to a use case rather than a concept the domain reasons about, and it is
the placement `UploadLimits` got in Phase 3 for the same reason. The alternative
was widening `_is_port` for every context's value objects to accommodate one
import.

### Two behaviours that had no home

**Path truncation was a bug.** The service truncated `path` to 500 characters
while the column is `varchar(255)`. A request with a path between those lengths
raised a database error and lost the audit event — the one record that must not
be droppable. A fixed character limit belongs to the column, so the mapper
truncates and the entity keeps the path whole.

**Acknowledgement could not be expressed.** `admin_router` set
`acknowledged = True` on the ORM row, so acknowledging twice was
indistinguishable from acknowledging once. `SecurityAlert.acknowledge` refuses to
run twice. It is not on the live path yet — `admin_router` is Phase 8.

`SecurityAlert` deliberately does *not* inherit `AggregateRoot`. It could, and
would then have a queue to fill, but this context has no `DomainEventPublisher`
wired, so every recorded event would be the construct-and-drop pattern Phase 3
deleted from the upload path.

### A defect found while verifying the phase

Verifying the route table needed a clean worktree at HEAD, and HEAD would not
import:

```
ModuleNotFoundError: No module named 'app.infrastructure.storage.local_artifact_stager'
```

`.gitignore` has carried an unanchored `storage/` since `e0d2f6c`, added to keep
user uploads out of version control. A trailing-slash pattern with no leading
slash matches a directory of that name at *any* depth, so it also matched
`app/infrastructure/storage/` — a source package Phase 3 added. The stager was
never committed. It is on disk, 200-odd tests pass against it, and a fresh clone
cannot start.

Nothing caught it because every test runs against the working tree, where the
untracked file happens to be present. The ratchet reads the filesystem, not git.

Fixed separately in `4c89f15` by anchoring the pattern to `/storage/`, with both
behaviours checked rather than assumed.

### Behaviour is unchanged

| | Before | After |
|---|---|---|
| Tests | 178 pass, 2 pre-existing fail | 225 pass, 2 pre-existing fail |
| HTTP API | — | identical; 54 method+path entries, same route table hash |
| Alert descriptions | — | same strings, byte for byte |
| Thresholds | `ALERT_LOGIN_FAILURE_THRESHOLD=5`, `ALERT_ACCESS_DENIED_THRESHOLD=10`, 15-minute windows | same defaults, from the same settings |
| DB schema | — | identical; no migration |
| Repository failure | `SQLAlchemyError` inside the service | `AuditRepositoryUnavailableError` |

The 47 new passes are the rules (17), the service path (12), the entity (11) and
the aggregate (5), plus 2 architecture tests for the moved service.

`rules_for` is mutation-checked in both directions: giving every event type a
default rule fails `test_ordinary_traffic_raises_nothing_and_counts_nothing` and
the four unknown-type cases, and moving `save_alert` outside the unit of work
fails `test_the_alert_is_written_before_the_transaction_closes`.

### Left alone deliberately

**`admin_router` still reads both ORM models** and builds queries — the R6
entry, assigned to Phase 8. It is also the only caller that writes
`acknowledged` directly, so `SecurityAlert.acknowledge` is currently exercised
only by tests.

**The analytics router still reaches into security's application layer**, builds
its own `AuditService` from a concrete `UnitOfWork`, and reads the thresholds
from the composition root module directly rather than through
`get_audit_service`. It is a cross-context import of another context's
application service, which no rule checks — R7 covers api-to-api only. Phase 8
owns analytics.

**`AuditEventType` is incomplete.** It names 2 of the ~5 event types actually
written; `http.request`, `auth.login.success`, `cookie.consent.accepted` and
`client.activity` are bare strings at their call sites. The policy keys off the
two it needs and treats the rest as uninteresting, which is correct — but a
test pins those four as "no rule watches this", so completing the enum later
means revisiting that test rather than being surprised by it.

## Phase 5 — the `resource` domain model

### Why

The smallest context in the codebase, and the last one still shaped by R5. Four
files at the context root, 185 lines, and the only R5 entry the phase was
assigned:

```
app/modules/resource/resource_service.py -> app.infrastructure.database.models.resource
```

Worth saying up front: 185 lines is not enough code to justify much design. The
phase was about putting the three rules that did exist somewhere defensible, and
deleting the rest.

### What moved

| Was | Now |
|---|---|
| `resource_service.py` | `application/services/resource_service.py` |
| `resource_repo.py` | `infrastructure/persistence/repositories/resource_repo.py` |
| — | `infrastructure/persistence/mappers/resource_mapper.py` |
| — | `domain/entities/resource.py` |
| — | `domain/value_objects/resource_type.py` |
| `resource_schema.py` | `schema/resource_schema.py` |
| `resources_router.py` | `api/routers/resources_router.py` |
| — | `api/presenters.py` |
| — | `domain/ports/repositories/resource_repository.py` |
| — | `domain/exceptions.py` |

`ResourceService.ALLOWED_TYPES` — a mutable class-level set — became
`ResourceType`, a `StrEnum` in the domain. The five inline normalizations in
`create_resource` became `Resource.create`. The four shared-kernel errors became
`domain/exceptions.py`, each registered in `handlers.py` against the status code
its predecessor produced.

### Moving the schema exposed a dependency that had been hidden

Relocating `resource_schema.py` into `schema/` immediately tripped R4:

```
app/modules/resource/application/services/resource_service.py
  -> app.modules.resource.schema.resource_schema
```

The import had been invisible because the schema sat at the context root, where
R4 does not apply. It was the same latent violation Phase 1 found elsewhere: a
file in the wrong place can mask a real coupling.

Resolved the Phase 3 way — the router unpacks the payload, the use case takes
keyword arguments:

```python
await service.create_resource(
    title=payload.title, slug=payload.slug, resource_type=payload.type, ...
)
```

This is an improvement independent of the layering rule. A use case that accepts
a pydantic model is coupled to the transport's validation rules, and
`min_length=2` on `slug` is a claim about a request, not about what a Resource
is.

### The aggregate is thin, and that is the finding

`Resource` has one behaviour and no mutator, because the API exposes no edit
route. No `delete()` either: removal is a hard `DELETE`, which is a statement
about the row rather than a change in the resource's state, so the repository
owns it.

The conclusion worth recording is that a resource has no invariants spanning
instances, no lifecycle and no state machine — it is closer to a typed read
model than an aggregate root. Adding mutators for a hypothetical edit route
would be speculative, so the phase stops at `create` and says so in the module
docstring.

### A 204 that would have become a 500

The service hands the port a detached domain entity. `to_model` therefore
produces a *transient* row, and `session.delete()` on a transient instance
raises `InvalidRequestError: Instance is not persisted`. The repository's
`except SQLAlchemyError` would have caught it and raised
`ResourceRepositoryUnavailableError` — a 500 on a request that was a 204 before,
returned with a plausible log line and no row deleted.

Fixed with a statement-level delete keyed on the unique slug, which is safe
because no foreign key references `resources`:

```python
stmt = sa_delete(ResourceModel).where(ResourceModel.slug == resource.slug)
```

Mutation-checked: reverting the implementation makes
`test_delete_of_a_detached_entity_actually_removes_the_row` fail with the
`InvalidRequestError`. A DELETE that silently no-ops still returns 204, so only a
test that inspects the table catches this class of bug.

### Behaviour is unchanged

- 54 routes, SHA-256 `0b745ecc2ac85456fda4439434b96ccaa41d9dde6d6dd90aaf623d392b9e09ff`
- 404 / 409 / 422 / 500 on the same failures as before, from new exception types
- The 422 body is character-identical, including `Allowed: api, knowledge, support, updates`
- No schema change: the entity's `resource_type` is mapped to the `type` column
- `created_at` still comes from the database default
- 266 pass, 2 pre-existing `search_algorithm` failures
- Ratchet 15 → 14

### Two behaviours preserved that look like bugs

**A padded type is still rejected.** The service tested `payload.type.lower()`
but stored `payload.type.strip().lower()`, so `" api "` was rejected even though
stripping it yields a legal type. Normalizing first would widen the accepted
set — a contract change. `ResourceType.from_input` reproduces the asymmetry,
names it in its docstring, and a test pins it, so it cannot be discovered later
as a bug report.

**A repository failure is a 500, not a 503.** 503 is the more truthful code and
Phase 3's port uses it, but an escaping `SQLAlchemyError` produced a 500 here.
Changing it is observable. The comment in the repository records 503 as the
intended follow-up.

### Left alone deliberately

**The list filter is not validated.** `GET /api/v1/resources?type=nope` returns
an empty list rather than a 422, while `POST` with the same type is rejected.
The asymmetry is pre-existing and, for a read path, arguably the better
behaviour: the endpoint stays usable as a lookup even if a caller knows a type
the vocabulary has since dropped. A test now pins it as deliberate.

**Deletion is still a hard delete.** Soft-deleting would change what the list
endpoint returns, which is a contract change.

**`resource_repo` is reachable from the shared `UnitOfWork`** like every other
context's. A port restricts what a service *declares*, not what the object can
physically reach; Phase 7 or 9 is where that gets tightened if it should be.


## Phase 6a — support chat, and an event loop that was blocked for a minute at a time

### Why

Phase 6 as planned was "the `user` domain model". It was split in two, for
reasons at the end of this section, and 6a is the half that was safe to do.

`SupportChatService` held four unrelated things: the system prompt, a length
rule, the provider configuration, and the HTTP call itself. It carried four
ratchet entries.

### What moved

| Was | Now |
|---|---|
| `infrastructure/persistence/repository/support_chat_repo.py` | `.../chat_message_repo.py`, returning entities |
| — | `domain/entities/chat_message.py` |
| — | `domain/policies/support_chat_policy.py` (prompt, fallback text, length rule) |
| — | `domain/ports/support_ai.py` (`SupportAI`, `SupportAIConfig`) |
| — | `domain/ports/repository/chat_message_repository.py` |
| — | `infrastructure/persistence/mappers/chat_message_mapper.py` |
| — | `infrastructure/external_apis/ai_support/http_support_ai.py` |

### The R8 entry was pointing at something worse than a layering violation

`requests` is on the forbidden list because an application service has no business
speaking HTTP. But the concrete harm was larger:

```python
response = requests.post(url, headers=headers, json=payload, timeout=60)
```

`requests` blocks the calling thread. That call sat inside a coroutine on the
event loop, so a slow or hanging provider stalled **every other in-flight request
on that worker** for up to sixty seconds. The layer rule found the import; nothing
would ever have found the stall.

`HttpSupportAI` uses `httpx.AsyncClient` and awaits. `httpx==0.28.1` was already
a pinned dependency and was used nowhere, so this adds no package.

`test_concurrent_questions_do_not_serialize` is the regression test — three
concurrent questions with 0.2s of simulated latency must finish in well under
0.6s. Mutation-checked by reverting the adapter to a synchronous call and
confirming the failure.

### R2 rejected the obvious way to wire the prompt

Putting `system_prompt` in `SupportAIConfig` and importing it from the domain in
`dependencies.py` is the natural first cut, and R2 refuses it: the composition
root may read another context's `domain.ports` and nothing else. The prompt
belongs in `domain.policies` — it is what the support bot is allowed to say.

So the port takes it as an argument. The prompt stays with the policy, the service
supplies it, and the config carries only deployment configuration. Rejected
alternatives are in ADR 0008.

### Four error kinds became one

Connection failure, HTTP error, non-JSON body and empty completion produced four
distinct messages and were all caught to substitute a canned reply. The adapter
now raises one `SupportAIUnavailableError`; the cause survives in the log line.
The distinction was never load-bearing, because every path ended the same way.

Note the degraded-mode contract, which is unchanged and slightly odd: **a customer
cannot tell a canned reply from a model reply**, because the response schema has
no field for it. The question is still recorded, which is deliberate — losing the
transcript because a third party was down would make it depend on their uptime.
Surfacing "this was not a real answer" would change the response shape.

### Ordering was load-bearing for the length rule

`clean_question` has to run *before* the model is called, so a one-character
submission costs no round trip. That is why it is a policy function rather than a
check inside `ChatMessage.create` — the entity is built after the reply exists.
`test_a_short_question_never_reaches_the_model` pins it.

### A read that committed

`list_messages` opened a write transaction for a pure read. It now uses
`read_only()`. No response changes.

### Modelling notes

One row holds a question *and* its answer — `user_message` and
`assistant_message` are always written together and nothing ever writes half a
row. So the type models an exchange, while the column and the API field are
called a message. Renaming either is a schema and contract change, so the awkward
spelling stays and the mismatch is recorded.

Relatedly, the `role` column defaults to `"user"` but every row ever created is
`"assistant"`. Both values are modelled so the default stays reachable; only one
is used.

### Behaviour is unchanged

- 54 routes, SHA-256 `0b745ecc2ac85456fda4439434b96ccaa41d9dde6d6dd90aaf623d392b9e09ff`
- 201 with a canned reply when the provider is down, 422 for a short question
- Exchanges still listed oldest first, LIMIT applied to the newest
- No schema change
- 308 pass, 2 pre-existing `search_algorithm` failures
- Ratchet 14 → 10

### Left alone deliberately

**`rules.py` had three dead functions.** `check_by_email` and `check_by_username`
had zero call sites; `map_integrity_error` lost its only caller in Phase 6b, when
the user repository took over translating `IntegrityError`. All three are deleted
in Phase 6b, which is where the first two were assigned.

**`SupportAIUnavailableError` → 503 is registered but unreachable.** The service
catches it, exactly as it caught the `ExternalServiceError` it replaced, so the
client still gets 201. Registered for parity.

**`follow_redirects=True` is set explicitly on the client.** `httpx` defaults to
not following redirects and `requests` did follow them. Preserving the old
behaviour is cheaper than assuming no provider redirects.

## Phase 6b — the `User` aggregate, and five writes that were vanishing

### What was actually broken

The Phase 6a review deferred this conversion on the grounds that returning
detached entities before making every write explicit would break five paths. Those
five were not hypothetical. Each mutated a row the repository handed back and
relied on session autoflush, and each failed *silently* — a 200 or 201 went back
and the write was gone:

| Site | Mutation | Symptom if made implicit |
|---|---|---|
| `auth_service.py:98` | `user.password_hash = verified_hash` | Argon2 rehash-on-login stops; cost upgrades never reach users |
| `auth_service.py:123` | `user_acc.status = VERIFIED` | accounts never verify — lockout |
| `auth_service.py:218` | `user.password_hash = ...` | reset returns 200, old password still works |
| `verification_recovery.py:45-48, 76-78` | 4 retry fields | unbounded verification-email retry |
| `superuser_seeder.py` | `role`, `status`, `password_hash` | admin seeding reports success and changes nothing |

`test_auth_hardening.py` could not have caught any of them: it drives
`AuthService` with fake repositories, so no test exercised a real `UserRepo`
write.

### The safety net, and proving it bites

`tests/integration/test_user_write_paths.py` runs against real SQLite through a
real `UnitOfWork` and **reads back through a second session**. That detail is the
point: a passing test then means the change was committed, not merely flushed.

It was written before any production line changed, and proven to bite by
detaching rows inside the repository's lookups. After the conversion it was
proven again from the other direction — deleting all five `save()` calls:

```
FAILED test_rehashing_on_login_is_persisted
FAILED test_verifying_an_account_is_persisted
FAILED test_a_password_reset_is_persisted
FAILED test_marking_a_verification_email_sent_is_persisted
FAILED test_marking_a_verification_email_failed_is_persisted
5 failed, 4 passed
```

A test that cannot fail is not a safety net, so it was checked from both sides.

### `save` uses `merge`, and that is asserted

The port returns detached entities, so `save` uses `Session.merge` — `add` would
attempt an `INSERT` against an existing primary key. Two repository tests count
rows after saving (`test_updates_in_place_instead_of_inserting`,
`test_works_on_an_entity_loaded_by_a_previous_session`) because "insert or update"
is the entire question this method answers.

### The seeder was the interesting caller

R2 stops infrastructure importing another context's entities, so the seeder could
not have hand-built an account once the aggregate existed. But the reason to
change it was already there: the seeder constructed a `User` with
`status=VERIFIED, role=ADMIN` inline, while `register` said a new account starts
`UNAPPROVED`/`USER`. Two places spelling out "what does a new account start as" is
how they drift.

Seeding an account is a use case, so it became one — `UserService.ensure_superuser`.
The seeder now reads configuration and decides *whether* to seed; the user context
decides *what* a seeded account is. A username and an email belonging to different
accounts is reported as `CONFLICT` and nothing is written, because that is a
configuration error rather than something to resolve.

### Three incidental improvements

**The client IP is a string.** `create_user` took a `fastapi.Request` only to call
`AbuseProtection.get_client_ip(request)`. The router reads the IP at the transport
edge and passes a `str`. That is what removed the `fastapi` and
`fastapi.concurrency` imports — not a lint fix, a genuine separation.

**Hashing no longer holds a connection open.** Argon2 is deliberately slow, and
the old code opened a write transaction *first*, then validated the password and
hashed inside it — holding a pooled connection for 100–300ms per registration.
Both now happen before the transaction opens. `run_in_threadpool` became
`asyncio.to_thread`, which is what it always was.

**Driver errors are translated where the driver is.** `DuplicateUserError` and
`UserRepositoryUnavailableError` are raised by the repository, so the application
no longer imports `sqlalchemy.exc` to be safe. Status codes are unchanged:

| Domain error | Replaces | Status |
|---|---|---|
| `UserNotFoundError` | `NotFoundError` | 404 |
| `DuplicateUserError` | `ConflictError` | 409 |
| `UserRepositoryUnavailableError` | escaping driver error | 500 |

500 and not 503 for the last one, because that is what an escaping driver error
produced before this phase — the same call Phase 6a made for the chat repository.

### `list_users` lost a dead parameter

It had two cursors: `cursor`, a `created_at` upper bound, and `before_id`,
keyset pagination on the id. `cursor` had no caller since the router moved to
keyset. Two pagination schemes on one method is how they start disagreeing, so it
went. The route was already keyset-only, so no HTTP behaviour changed; the
existing pagination test was updated, and the implicit-`None` bug it was written
to catch is now unrepresentable rather than merely tested against.

### The route table is a test now

Every prior phase re-checked the route table by hand at the end. That is exactly
the kind of check that gets skipped once, so it is
`tests/architecture/test_public_http_surface.py`. It was verified byte-identical
against a clean `HEAD` worktree of Phase 6a, then mutation-checked by renaming
`/users/me` to `/users/profile` — the test named both the addition and the
removal.

It pins method, path, and declared success status. It cannot catch a request or
response schema change; those remain covered by the per-context tests. It is here
because a refactor that quietly moves a route between contexts is otherwise
invisible — the code moves, the tests keep passing, and only a client notices.

### Behaviour is unchanged

- Route table byte-identical to Phase 6a, verified against a clean worktree
- 404 for a missing account, 409 for a taken username or email, as before
- Registration still stores submitted values without normalizing them
- Passwords still Argon2-hashed; accounts still start `UNAPPROVED`/`USER`
- No schema change
- 394 pass, 2 pre-existing `search_algorithm` failures
- Ratchet 10 → 5

### Remaining ratchet, and who owns it

| Entry | Owner |
|---|---|
| R5 ×2, R8 ×2 — all `auth_service.py` | Phase 7 — **resolved in Phase 7a** |
| R6 ×1 — `admin_router.py` | Phase 8 |

`UserUnitOfWork.user_repo` is now typed. `session_repo` stays `object` until
Phase 7, which is the context that mutates those rows the same way.

### Left alone deliberately

**`auth_service` calls entity methods the port does not name.** It receives a
`User` through a `UserRepository`-typed property and calls `verify()`,
`set_password_hash()`, and `apply_verified_password_hash()`. The protocol
describes persistence, not those capabilities, so the service depends on the
concrete implementation rather than on the port. The alternative — a port that
names the capability — belongs to Phase 7, which owns `auth_service`.

**A forgotten `save` is still silent at runtime.** It is no longer silent in the
test suite: the five sites that exist are pinned. A sixth added later needs its
own test, or a lint rule for methods that mutate an entity in place.

**`admin_router` still reads both ORM models** and builds queries — the R6 entry
that Phase 8 owns.

**Registration still stores what was submitted.** The entity does not normalize
`full_name`, `username`, or `email`, and the authentication context normalizes
separately for lookup. The asymmetry is real but predates this refactor; storing
normalized values now would silently change what existing rows mean. The test
`test_registration_does_not_normalize_its_inputs` pins the current behaviour so a
future fix is a deliberate change.

**`verification_email_last_error` is truncated in the mapper, not the domain.** The
column is `String(500)` and SQLite does not enforce it, so on Postgres an over-long
SMTP error would turn a bookkeeping write into a 500. The domain stores the message
whole and the mapper fits it to the column, which is where the width is known.

## Phase 7a — `UserSession`, and the last autoflush in `auth_service`

Scope note: this phase was split in two on purpose. The user context's session
record and the ratchet went first; the `app/modules/shared/dependencies.py` split
was deferred to Phase 7b. Doing the aggregate first meant the ORM reads there had
a port to migrate onto rather than being rewritten twice.

### Two writes were vanishing, the same way as Phase 6b's five

`UserSession` was an ORM row that `auth_service` mutated in place and persisted
by accident. The mechanism is the same as ADR 0009's: the unit of work commits
on exit, but a later read in the same transaction autoflushes pending changes as
a side effect. So the write landed only if a read happened to follow it.

| Site | Mutation | Symptom if made implicit |
|---|---|---|
| `_rotate_session` | `refresh_token_hash = new` | the old refresh token keeps working after rotation — a rotated session is still live |
| `_rotate_session` | `last_used_at`, `user_agent`, `ip_address` | rotation is a no-op, so session audit data is never updated |
| `logout` | `revoked_at = now` | logout returns 200, clears the cookies, and the session **stays alive** |

The logout case is the one worth stating plainly: it looked like it worked. The
cookies were cleared, the client believed it was signed out, and the refresh
token behind it was still valid. The same write was pinned in
`test_auth_hardening.py` as `revoke_session` needing to be a coroutine — it had
been a plain `def` that the service awaited, so logout 500'd before reaching the
cookie-clearing code at all. Two bugs, same method, opposite symptoms, and
neither was visible from a fake-repository unit test.

### The safety net, and proving it bites twice

`tests/integration/test_session_write_paths.py` — 13 tests against real SQLite,
reading back through a second session. It was written before any production line
changed, and proven to bite by detaching rows inside
`get_by_refresh_hash`. After the conversion it was proven again from the other
direction, by deleting both `save()` calls:

```
FAILED test_rotating_a_session_persists_the_new_refresh_hash
FAILED test_rotating_persists_last_used_at
FAILED test_rotating_updates_the_user_agent_and_ip
FAILED test_the_rotated_session_keeps_its_id
FAILED test_revoking_a_session_persists_revoked_at
FAILED test_a_revoked_session_cannot_be_rotated_afterwards
FAILED test_revoking_leaves_other_sessions_alone
7 failed, 6 passed
```

The same 7-failure signature as the pre-conversion mutation, which is the useful
part: the net was measuring the behaviour before and after, and both endpoints
agree.

### The aggregate holds three invariants that were open-coded

| Was | Now |
|---|---|
| `Session(refresh_token_hash=..., ...)` | `UserSession.open(user_id, refresh_token_hash, expires_at, user_agent, ip_address)` |
| `session.refresh_token_hash = new_hash` | `session.rotate(new_refresh_token_hash, rotated_at, user_agent, ip_address)` |
| `session.revoked_at = now` | `session.revoke(now)` |

The non-obvious ones, all now pinned by 26 entity tests:

**`rotate` must not blank the agent.** A browser refresh is cookie-less and sends
no `User-Agent`. Assigning the new value unconditionally would erase the
recorded agent on every rotation, so a cookie-less session ends up with a null
user agent after its first refresh. The old code only avoided this by accident,
because rotation passed the request-derived values and the field happened to be
set. `rotate` ignores `None` and empty strings.

**`revoke` keeps the first `revoked_at`.** The bulk password-reset revocation
runs a second time whenever a reset is retried, and a second logout on an
already-revoked session is reachable by design. That timestamp is when the
session actually died; overwriting it with a later observation would be a small
falsehood about the past. `revoke_user_sessions` filters on
`revoked_at.is_(None)` for the same reason.

**`rotate` must not change `id`.** The access token stays bound to the session
id across a rotation, which is precisely the mechanism by which revoking a
session invalidates its access token. Changing the id would leave a revoked
session's access token permanently un-revokable.

`revoke` and `rotate` are deliberately asymmetric about overwriting a timestamp:
`revoke` records a past fact, so the first observation wins; `rotate` records
current usage, so the latest wins. Making them symmetric would have been tidier
and wrong for one of them.

### A TypeError that only fired on SQLite

`expires_at` is `DateTime(timezone=True)`, but SQLite has no timezone type and
returns a naive `datetime`. The old inline comparison in `_rotate_session` did
`expires_at <= now` against an aware `datetime`, which raises `TypeError`. On
Postgres it worked; on the SQLite the test suite runs against, session
revalidation would fail. `_as_utc` in the entity normalises on read, matching the
convention the Phase 6b entities already set.

The mapper stays a plain field copy rather than normalising there, which means an
entity read from the database can hold a naive `expires_at`. That is a real
consequence and it is the reason `is_expired_at` must never compare raw — the
entity tests assert the naive cases directly so the trap is documented rather
than left to be rediscovered.

### `revoke_user_sessions` stays a bulk UPDATE

Password reset revokes sessions it has not loaded, and would not be written to
visit each one. What changed is that it now runs inside
`async with UnitOfWork(...)`, so the commit is explicit rather than a side effect
of a later read. The detached-entity change does not affect it, and the test
covers it against a real database anyway.

### `save` uses `merge`, and that is asserted

Same as Phase 6b: the port returns detached entities, so `add` would attempt an
`INSERT` against an existing primary key. Two repository tests count rows after
saving, because "update or insert a duplicate" is the entire question this method
answers. `to_model` also omits `created_at`, so a `save()` cannot overwrite the
column's server default with whatever a detached entity happened to hold; that
is asserted too.

### One test had to be rewritten, and the guarantee kept

`test_revoke_session_is_awaitable` pinned `SessionRepo.revoke_session` being a
coroutine. That method no longer exists — the mutation moved onto the entity.
The *guarantee* is still real, so the test now checks all four methods
`AuthService` awaits on the session repository. A single `def` among them is the
same logout-breaking bug, and a test that names one method would have missed a
second.

### R2 blocked the obvious fix, so the port stays `object`

`AuthenticationUnitOfWork.session_repo` is `object`, and could not be narrowed to
`SessionRepository`: R2 rejects a bounded context importing another context's
`domain`, *including its ports* — only `app/infrastructure/**` and
`app/modules/shared/**` are port readers. R2 is a hard rule with a zero-violation
ratchet, so it cannot be ratcheted either. The concrete `UnitOfWork` does the
wiring, legally.

The proper fix is a capability-shaped port owned by the authentication context,
declaring `open`/`rotate`/`revoke` and satisfied structurally by
`SessionRepository`. That is a second description of one repository — a decision
about where the capability belongs, not a mechanical narrowing — so it is recorded
as a Phase 9 item instead of being done here. It is the same gap ADR 0009
recorded for `verify` and `set_password_hash`, now repeated for sessions, and
ADR 0010 states it as a known typing gap rather than a settled design.

### An unrelated import removal would have broken revalidation

Removing the ORM `User` and `UserSession` imports from `auth_service` also
removed `UserStatus`, which the service still uses to check `user.status ==
UserStatus.VERIFIED` before rotating. It is restored from
`app.modules.shared.enums`, which is the shared kernel and always permitted. The
suite caught it; the note is here because the three imports sat in one block and
looked like the same category.

### Behaviour is unchanged

- Route table byte-identical, checked by `test_public_http_surface.py`
- No schema change; session rows have the same columns
- Login, refresh, logout, and password-reset status codes unchanged
- Session storage failure was a 500 before (escaping `SQLAlchemyError`) and is a
  500 now (`SessionRepositoryUnavailableError` with a log line). Not 503: the
  escaping error was never retriable from the client's side and changing the
  status would have been a behaviour change
- 456 pass, 2 pre-existing `search_algorithm` failures
- Ratchet 5 → 1

### Remaining ratchet, and who owns it

| Entry | Owner |
|---|---|
| R6 ×1 — `admin_router.py` | Phase 8 |

`tests/architecture/test_layer_boundaries.py` fails on a ratchet entry whose
violation no longer occurs, so the four `auth_service.py` entries were deleted in
this commit rather than left to rot. Five of eight rules are now clean with no
ratchet entries at all.

### Left alone deliberately

**`dependencies.py` revalidation still reads the session through the ORM.** It is
the remaining ORM read in the request path that no domain model serves. Deferred
to Phase 7b by the scope decision, and it is the reason 7b is not a formality.

**`auth_service` calls `rotate` and `revoke` structurally**, on an entity whose
type R2 does not permit it to name. Real gap, described above.

**A forgotten `save` is still silent at runtime.** Not silent in the suite: the
five sites are pinned, and the mutation check is recorded above so the next
person can re-run it rather than trust it. A sixth site added later needs its own
test, or a lint rule for methods that mutate a returned entity in place. That
rule is the only real fix and it is not in place.

**`admin_router` still reads both ORM models** and builds queries — the last
ratchet entry, Phase 8.

## Phase 7b — the composition root, split by ownership, and the last ORM read

### What the file was

`app/modules/shared/dependencies.py` was 474 lines holding twenty-odd providers
for every context in the codebase: the database session, the Redis client, the
unit of work, access-token decoding, access-token revalidation, RBAC, the
abuse-protection singleton, the malware scanner, local storage, the download
signer, the event publisher, the artifact stager, the upload limits, the alert
thresholds, the AI provider, and four use-case factories.

The split followed the ownership its call sites already implied. Nothing had to
decide where anything went; every name had exactly one obvious answer, which is
the sign that a 474-line composition root is a symptom rather than a design.

| Provider | Home |
|---|---|
| `get_db`, `get_redis`, `get_unit_of_work` | `app/modules/shared/dependencies.py` |
| tokens, principals, `require_role`, abuse protection, audit service | `app/modules/security/dependencies.py` |
| scanner, storage, signer, event publisher, stager, software use cases | `app/modules/software_management/dependencies.py` |
| the support-chat AI provider | `app/modules/user/dependencies.py` |

The three that stayed are the three with no owning context. A per-context copy of
any of them would be a second connection pool behind the same database, so one
instance is the correct answer there rather than a convenient one.

`shared/dependencies.py` is now 53 lines and imports no context at all.

**This deviates from ADR 0001, and is recorded rather than reconciled.** ADR 0001
rejected per-module `api/dependencies.py` — the layout `ARCHITECTURE.md` §2 and
§9.1 specify — and preferred a single container, for a reason that still holds: the
same `Depends(...)` plumbing repeated per module drifts. Nothing here duplicates
anything; each provider is still defined exactly once. What changed is *where* the
concerns live, which is ADR 0001's own "split by concern" consequence applied
literally rather than within one module. ADR 0011 states the decision and the
rejected alternatives, including the closer one — a `shared/dependencies/` package,
which would keep every import path under `shared` but would also keep software
management's use-case factories outside `software_management`, leaving the
ownership error in place under a new path. ADRs are immutable once accepted, so
this is a new ADR rather than an edit to 0001.

The cost is that `ARCHITECTURE.md` §2, §9.1 and §15.1 now describe a layout the code
does not use. That document was already behind the code in four places when Phase 1
started; this adds three more, and Phase 9 corrects all of them.

### Token verification moved next to the thing that signs tokens

`decode_access_token`, `get_email_user` and `get_password_reset_user` were
verified token *readers*, and they lived in the composition root while the tokens
themselves were minted by `security/token_manager.py`. The two modules also each
defined their own `oauth2_scheme`, `credentials_exception`, `EXPECTED_ISSUER`,
`EXPECTED_PURPOSE` and `EXPECTED_RESET_PURPOSE` — byte-identical, as was
`ACCESS_TOKEN_REQUIRED_CLAIMS`, which existed only in the copy that read tokens.

Phase 2 recorded the same class-shape duplication for the storage exceptions
(ADR 0003), and Phase 3 for `SoftwareAccessPolicy`; this is the third instance,
which is what makes it a pattern rather than an accident. The readers moved to
`token_manager.py`, one definition of each constant remains, and the duplicated
copies are gone.

Two consequences worth stating:

**`auth_service` no longer imports the composition root.** It called
`get_email_user` and `get_password_reset_user` as plain functions — not FastAPI
dependencies — so this was an application service reaching into the module that
wires the application together, for two pure functions. It now imports them from
the module that owns tokens, alongside `TokenManager`, which it already imported.

**They were renamed.** `get_email_user` returns the token's claims and never
loads an account, so the name said the opposite of what it did;
`decode_email_verification_token` pairs with `decode_access_token` and
`decode_password_reset_token`. Internal names, so no contract moves.

### Revalidation was the last ORM read on the request path

```python
stmt = (
    select(UserSession, User)
    .join(User, User.id == UserSession.user_id)
    .where(UserSession.id == claims.session_id)
)
```

`revalidate_access_token` built this itself, in the composition root, and read
`revoked_at`, `expires_at`, `user.status` and `user.role` off the rows. That is
repository work, a domain decision and a transport concern in one function, and
it ran for essentially all authenticated traffic — so the code path that executed
most often was the one with no domain model behind it, and the rules it applied
were the rules no test could reach.

It now asks `SessionRepository.get_by_id` and `UserRepository.get_user_by_id`, and
decides with the aggregates: `UserSession.is_usable_at` for the session and
`User.is_verified` for the account. The check order is unchanged — session exists,
session live, `sub` matches the session's user, account verified — and every
failure raised the same `credentials_exception`, so the order is not observable.

**One query became two, on every request.** The old version joined; the new one
looks the session up and then the account. The `sub`/`sid` mismatch is checked
against the session's own `user_id` *before* the account lookup, so the one case
that would waste a query still costs one. Keeping it at one would mean a port
method returning "the account behind this session" — an authentication-shaped join
inside the user context — to save a round trip per authenticated request. The two
ports are more defensible and the cost is one local query; the alternative is
recorded in the function's docstring rather than silently chosen.

### A guard, because no existing rule would have noticed

`tests/architecture/test_request_path_has_no_orm_models.py` parses the modules
that resolve a request's identity and fails if any of them imports
`infrastructure.database.models`.

This is needed because the dependency modules sit at a context root, which none of
the eight rules classify at all: R5 keys on the `_service.py` suffix, R6 on router
filenames. This is the same hole R8 was written to close in Phase 3, one layer
further out. Re-introducing the join is invisible in review and unmeasured in
production, which is exactly the kind of regression the ratchet exists to prevent
and which the ratchet cannot see.

### A test that asserted nothing

`test_session_belonging_to_another_user_is_rejected` claimed to prove that a valid
session id cannot be paired with someone else's subject. It minted a token with
`user_a`'s subject and `session_a`'s id, decoded it, and asserted the two matched
— a statement about the token, not about revalidation. The mismatch it describes
was never exercised, so the `sub`/`sid` check in
`revalidate_access_token` could be deleted without failing anything.

It now mints a token for `user_a` against `session_b` and requires a 401.
Mutation-checked: removing the binding check fails it.

### Twelve unreachable lines

`get_current_user` ended with a `return`, followed by twelve lines that were the
pre-revalidation implementation verbatim: a second `jwt.decode`, a `role` read out
of the token payload, a `CurrentUser` built from it. They became unreachable when
`5c9a5b5` added `revalidate_access_token` and made the database the authority —
which is also what fixed the bug the module docstring in
`test_current_user_and_route_guards.py` describes: the access token used to be the
sole source of truth, so a demoted admin kept admin rights until the token
expired. The code that would have caused exactly that was still in the file,
twelve lines below the function that had superseded it. Deleted.

### Behaviour is unchanged

- Route table byte-identical to Phase 7a. 46 API entries (50 including the four
  docs routes), SHA-256 of the sorted `METHOD PATH STATUS` lines
  `954915f0bb3e1b5dbaa4730fa26fedbbdfbb0f7063b75e9c5b28c3ddb15c58f9` for the API
  subset and `f17b93910a05b74f5c59f121835adedf90dcbb6275d830607f4014903ef1c6ea`
  with the docs routes, both recomputed from a clean checkout of `667192c` and
  from the working tree. The standing guard is
  `test_route_table_is_unchanged`, which diffs added and removed entries against a
  pinned `EXPECTED_ROUTES` and names any difference
- 401 for a revoked, expired, unknown or cross-account session; 403 from
  `require_role`; unchanged
- A session storage failure is still a 500. It used to be an escaping
  `SQLAlchemyError` and is now `SessionRepositoryUnavailableError`, whose handler
  returns `{"detail": "Session storage unavailable"}` rather than the generic 500
  body. Same status; a 500 body is not a contract, and the same substitution Phase
  6b and 7a made elsewhere
- `resolve_optional_user` still returns `None` rather than raising, so audit
  attribution stays best-effort
- 471 pass, 2 pre-existing `search_algorithm` failures
- Ratchet unchanged at 1 (`R6`, `admin_router`, Phase 8) — 7b had no entries to
  remove, because the files it touched were never violations under any rule

### Left alone deliberately

**`UserRepository.get_user_by_id` is the one read that does not translate driver
errors.** Every other method in the user repository raises
`UserRepositoryUnavailableError`; this one lets `SQLAlchemyError` escape, so
revalidation has two different failure modes for the same class of problem. Adding
the translation would be a behaviour change: `auth_service.login` catches
`DomainError` and re-raises it as `UnauthorizedError`, so a database failure
during login would become a **401 instead of a 500**. Same on the status code and
a real change on what the client is told, and it is a question about what an
outage should look like from outside rather than a cleanup. Phase 9.

**The repositories stay `object` in both places they are consumed.**
`revalidate_access_token` takes `session_repo`/`user_repo` as `object` and
`AuthenticationUnitOfWork.session_repo` is still `object`, both because R2 forbids
a bounded context from naming another context's ports. The proper fix is
capability-shaped ports owned by the consuming context — which is the same item
Phase 6b recorded, Phase 7a recorded, and Phase 7b has now recorded for a third
time. Three phases of deferral is the signal that it should be scheduled, not
carried: it is Phase 9's first item.

**`token_manager.py` raises `HTTPException`.** `decode_access_token` and the two
reset/verification decoders signal failure with a 401 carrying
`WWW-Authenticate`, from a module that is not an API layer. It is pre-existing,
every caller treats a failure as "unauthenticated", and changing it to a domain
exception would mean editing every route that depends on it for no gain in
correctness. Recorded because it is the kind of thing a reviewer will ask about.

**`container.py` still builds the storage adapter and the signer.** It is
process-wide singletons that `app/infrastructure/storage/local_storage.py`
constructs with its own settings objects, and moving them would put an adapter's
configuration next to the ports rather than in the shared kernel where it already
is. The composition root imports them; it does not own them.

**`analytics_router` still reaches into the security context.** It imports
`CurrentUser`, `get_current_user`, `get_abuse_protection` and `alert_thresholds`
from `app.modules.security.dependencies`, and builds its own `AuditService` from a
concrete `UnitOfWork` rather than through `get_audit_service`. Phase 4 flagged
this; Phase 8 owns analytics.

---

## Phase 8 — the last ratchet entry, and three endpoints that had never returned a row

### What the file was

`app/modules/user/api/router/admin_router.py`. The last ratchet entry in the
codebase, the only file named in it, and the only file in the project that broke
R6 by name. Five endpoints, no tests:

| Method | Path |
|---|---|
| GET | `/api/v1/admin/alerts` |
| PATCH | `/api/v1/admin/alerts/{alert_id}/ack` |
| GET | `/api/v1/admin/audit-events` |
| GET | `/api/v1/admin/cookie-activity` |
| GET | `/api/v1/admin/logs` |

It was in the wrong module, and that was not incidental. The tables it reads are
the security context's — `SecurityAlert` and `AuditEvent`, both modelled in Phase
4 — and R2 forbids one context from naming another's domain layer. So from the
user context the router had no port to ask, the ORM models were its only route to
the data, and it built four `select()` statements and called `db.commit()` itself.
R4 could not have applied either: there was no application service in the path to
be the thing that was wrong.

### The bug the tests found, first

All three list endpoints had **never returned a row**. Each ended in

```python
alerts = result.scalars().all()
return {"count": len(alerts), "items": [AlertModelResponse.model_validate(a) for a in alerts]}
```

`.all()` returns a `Sequence`, and iterating it a second time yields nothing. So
an operator asking for open alerts got `200` with `{"count": 3, "items": []}` —
and `count` was *correct*, which is what kept it from being noticed. There was no
test, and the response shape is exactly what a broken endpoint looks like from the
outside.

`tests/unit/test_admin_api.py` was written against the old code first. Ten of its
24 tests failed; those ten were the three list endpoints. That is the number worth
remembering: the phase did not begin with a bug found by reading, it began with a
bug found by asking.

### What changed

The router moved to `app/modules/security/api/router/admin_router.py` — the
context that owns the data. R7 forbids one context's API layer from importing
another's, so keeping the file in `user/` and injecting a security service would
have traded one rule for another; the location and the data access were the same
decision.

Reads go through `AuditRepository`, in its own language: `get_alert`,
`list_alerts`, `list_events`. `AuditService` gained the matching three. The two
lists run on `uow.read_only()`; acknowledgement runs on the write boundary, so the
change and the decision commit together. `test_audit_read_path.py` records which
boundary each one opened, because "a read that accidentally commits" and "a write
that forgot to" are invisible in a test that only checks a return value.

Acknowledgement now calls `SecurityAlert.acknowledge` instead of
`update(SecurityAlertModel)`. `save_alert` uses `Session.merge`.

### The two defects the phase found in its own new code

**`merge` was inserting a second alert.** `alert_to_model` did not pass `id`, on
the reasoning that its only caller created new alerts — true until Phase 8, and
false the moment an endpoint acknowledges one. Without the primary key `merge`
sees a transient instance and *inserts*: acknowledging an alert left the original
row open and added a second, acknowledged copy beside it. The endpoint test caught
it by noticing the returned id was not the one it asked for.
`test_acknowledging_updates_the_row_instead_of_adding_a_second_one` now asserts
the consequence, which is the thing that matters: the table does not grow.

**`created_at` was being written on update.** The mapper's own docstring said the
column was left alone for the same reason `session_mapper.to_model` leaves it,
and the code did the opposite. The docstring was right: `created_at` is
`nullable=False` with a `server_default`, so copying an entity's value over it is
one unpopulated entity away from a constraint violation, and even when populated
it rewrites when the alert fired every time an operator opened it. Removed.

### Log reading, and the redaction

`LogTail` is a port in the security context; `FileLogTail` is its adapter. The
port's contract is not "returns lines" but "returns lines that are safe to send to
a browser", which is why redaction lives in the adapter — an implementation
returning raw lines would satisfy the signature and break the promise.

Writing the tests one pattern at a time, as the adapter's docstring said they
should be written, immediately paid for itself. The first version of the pattern
covered `key=value` and `key: value` and nothing else:

```
{"password": "hunter2", "user": "alice"}   ->  unchanged
{"access_token": "eyJhbGciOi.payload"}    ->  unchanged
client_secret=sk-live-1234                 ->  unchanged
```

A closing quote between the key and the colon defeats a pattern that expects
`:` there. JSON is how most logging libraries emit a structured field, and a
single test with one long log line would have passed. It is now one pattern for
the key family and one for `Authorization` headers, both quoted-value aware, and
`test_a_redacted_json_line_is_still_valid_json` holds the line to its own shape —
`{"password": "[REDACTED]"}` is still a document, which matters to whatever parses
the file next.

Three bugs in that pattern were found by mutation check rather than by reading,
and the third is the one worth recording: the `head` group closed at the first
alternation branch, so the `:` and the value had both fallen outside it. The code
ran, returned 200, and removed the separator and the value together.

### Analytics

`analytics_router` now takes `AuditService` through `Depends(get_audit_service)`
instead of building it from a concrete `UnitOfWork`. Flagged in Phase 4, recorded
in Phase 7b, closed here.

### The ratchet

`ratchet.json` holds `"violations": []` — empty. R6 was the only entry and it is
gone with the file that caused it, so all eight rules are now hard. The file
itself stays, with the entry removed in the same commit as the phase, because the
instruction *do not add an entry here* is only worth something if there is an
obvious place to add one instead.

```
[ok]        R1: domain must not import fastapi/starlette/sqlalchemy/pydantic/redis/jose/httpx
[ok]        R2: a module must not import another module's domain layer (use app.modules.shared)
[ok]        R3: domain must not import infrastructure (ports belong in domain, implementations in infrastructure)
[ok]        R4: application must not import api/schema/infrastructure
[ok]        R5: an application service must not import an ORM model (it has no domain object)
[ok]        R6: an API router must not build SQLAlchemy statements
[ok]        R7: a module's API layer must not import another module's API layer
[ok]        R8: an application service must not import the web framework, the ORM, or the filesystem
```

The rule descriptions above were paraphrased rather than copied when this was
first written, and `ARCHITECTURE.md` carried the same invented transcript. Both
were replaced with real output in Phase 9a. It is recorded here rather than quietly
fixed because it is the clearest example of the class of thing Phase 9a is about: a
plausible transcript, in a block that invites trust precisely because it looks like
a command and its output.

`test_request_path_has_no_orm_models.py` gained two guards, both green rather
than ratcheted: a parametrised one over **both** paths the admin router has
occupied, so a future `user/` router that grows a `select()` names the exact place
to look; and a codebase-wide one asserting no `*router*.py` imports an ORM model.
The second is wider than the request-path list on purpose — the reasoning is not
about frequency but that a router which can name a row can read one.

### Mutation checks

Every claim above that a test enforces was checked by breaking the code and
confirming the test failed. Twelve mutations, ten caught. The two that survived
were the id tiebreaks on `list_alerts` and `list_events`, and being unable to test
them was the finding:

- A covering-index scan over `created_at` returns equal keys in **descending
  rowid** order on SQLite, so a test asserting the returned order passed with the
  tiebreak deleted. The tiebreak is a property of the *statement*, so
  `test_a_tied_page_of_alerts_has_a_fixed_order` now asserts on the compiled SQL
  through a recording session. It is a white-box test, and the docstring says why
  it has to be.
- The production database is PostgreSQL, where a seq-scan-and-sort leaves the tie
  order unspecified. The tiebreak is what makes a refreshed triage list show the
  same page twice.

### A `.gitignore` that would have shipped a broken commit

`.gitignore` line 9 was `logs`, unanchored, so it matched *any* directory named
`logs` at any depth — including `app/modules/security/infrastructure/logs/`. The
adapter would not have been committed while `LogTail`, `get_log_tail` and the
tests importing it all were, and the failure would have been an `ImportError` on
a clean checkout rather than anything a local run would show. Anchored to
`/logs/` and the package re-included.

This is worth writing down as a class: the Phase 7b review recorded that the
route-table hash was computed over a list that excluded two entries, so the
"byte-identical" claim was checking a smaller surface than it claimed. Both are
cases of a check that passes because it is looking at the wrong thing.

### Contract

Preserved exactly. Route table byte-identical to Phase 7b, verified by diffing
against a `git worktree` at HEAD rather than against a recorded hash.

- Five paths, five methods, unchanged
- 401 unauthenticated, 403 non-admin, unchanged
- `count` is the returned page size, not the total matching rows — unchanged, and
  now tested rather than incidental
- All three acknowledgement outcomes remain 200; not-found still omits `alert_id`
- Null audit metadata is still exposed as `{}`
- `log_file` and `lines_requested` still in the logs response

**Changed, deliberately:** the three list endpoints now return rows. An operator
who asked for alerts and received an empty list now receives the alerts. This is
the only client-visible behaviour change in the phase, and it is the bug.

### Not changed, on purpose

- 567 pass, 2 pre-existing `search_algorithm` failures
- `alert_to_entity` converts `rule_code` and `severity` strictly. A row holding a
  value outside the vocabulary raises instead of being displayed. The only writer
  is `AuditService._raise_alerts_for`, so this means "written by something other
  than this application", and an alert whose code the domain cannot name is not
  one to show as if it were.

### Left alone deliberately

**Five routers still construct a concrete `UnitOfWork`** — `auth_router`,
`resources_router`, `category_router`, `support_chat_router`, `user_router`. This
is the pattern the phase set out to remove, and it is now the largest remaining
instance of it in the codebase. A rule banning it needs five ratchet entries, and
growing a file whose stated contract is that it can only shrink is the wrong
trade in the phase that empties it. Phase 9.

**`analytics_router` still imports `CurrentUser`, `get_current_user` and
`get_abuse_protection` from the security context.** Consuming another context's
composition root is not what R2 or R7 forbid, and unwiring it means giving
analytics its own view of the principal. Out of scope here; the `UnitOfWork` half
is done.

**`LogTail` is synchronous underneath an `async` signature.** `FileLogTail.tail`
hops to a worker thread because a large log on a slow disk would otherwise block
the event loop. `test_the_read_happens_off_the_event_loop_thread` asserts the hop
happens; it cannot assert that the hop was worth it, which is a judgement about
file sizes this project has not hit yet.

---

## Phase 9a — a port that answered without being asked, and a document that answered without looking

### What the file was

`ARCHITECTURE.md` is what a reviewer reads to decide whether a change to
`software_management` is placed correctly. Phase 1 found four divergences and
deferred the correction, on the condition that it happen "against something real in
Phase 9a".

It had drifted in roughly forty places across nineteen sections since. Not
cosmetic drift: a directory tree that stopped existing in Phase 1; port names that
collided with the concrete classes they described; a `Storage` port with a method it
has never had; two event classes that have never existed; a section describing the
search implementation as future work; and a quality gate requiring `mypy --strict`
in a project where mypy is not installed and is not in `requirements.txt`.

Two fabrications are worth naming individually, because both are the kind that
survive review:

```
$ python -m tests.architecture.layer_rules
[ok] R1  domain imports no framework, ORM or driver
```

That transcript appeared in this file after Phase 8 and in `ARCHITECTURE.md` §3.1.
It was written from memory. The real output is the eight lines now in both places,
and they are wordier than the invented ones because the rule docstrings are.

The second was a count: `domain/exceptions.py` was documented as holding 28
classes. It holds 25. Nothing else in the document is more load-bearing than a
count — the argument that `has_purchase` was safe to leave unimplemented is that
the surrounding code was small and well understood, and the count was part of that
picture.

### The defect: a port member with no implementation is a default value

`SQLAlchemySoftwareRepository` names its port as a base class:

```python
class SQLAlchemySoftwareRepository(ISoftwareRepository):
```

A `Protocol` subclass that is not itself a protocol is an ordinary class, so it
**inherits the port's method bodies**. `ISoftwareRepository.has_purchase` was
written as `...`, so it was not an unimplemented interface — it was an
implementation, supplied to every class that forgot to write one, returning
`None`.

Three files asked it about authorization (`SoftwareService.download_url`,
`download_artifact_url`, `DownloadService.create_download_url`), plus the router at
`software_router.py:238`. `None` is falsy, so every one of them reported "this user
bought nothing" — with nothing anywhere to say the question had gone unasked.

**The answer was right.** The purchase table was removed with the `billing` module,
so no purchase can be recorded and no user can be a buyer. That is what makes this
the interesting case rather than an ordinary missing implementation: a wrong answer
that nothing can distinguish from a right one, surviving until the day it stops
being true.

Three things had grown around it, all of which read as care:

- `DownloadService` guarded the call with `hasattr(repo, "has_purchase")`. The
  attribute was always inherited, so the guard was never once `False`.
- A codebase-wide sweep for exactly this defect, written with
  `pkgutil.walk_packages(app.__path__)`, reported the tree clean. `domain/` and
  `infrastructure/` have no `__init__.py`, so the walk descended past both and saw
  half this context. Every other architecture test in this repo walks the
  filesystem for the same reason.

### What changed

The port raises, the adapter states the truth, and the guard is on the shape rather
than on the answer (ADR 0013):

```python
# domain/ports/repositories/software_repository.py
async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool:
    """...raises NotImplementedError, with the reason in the docstring..."""

# infrastructure/persistence/repositories/sqlalchemy_software_repository.py
async def has_purchase(self, *, software_id: UUID, user_id: UUID) -> bool:
    return False   # no purchase table: the billing module removed it
```

`DownloadService.create_download_url` calls the port directly. The dead `hasattr`
guard is gone.

The choice worth reviewing is returning `False` rather than raising from the
adapter. Raising would make every request for a paid, non-public artifact a 500 —
a contract change inside a phase whose invariant is that the HTTP API does not
change, and a worse answer than the one already available. The 403 for unauthorized
users is preserved exactly, and the port still refuses to default, so the next
implementation that forgets is loud. If a reviewer disagrees and wants the loudness
at the call site instead, that is a one-line change to the adapter plus a
documented status-code change.

`tests/architecture/test_ports_have_no_silent_defaults.py` sweeps every explicit
protocol subclass in `app/` and fails on an inherited ellipsis body, with a
`RAISING_MEMBERS` table for members that are allowed to raise and a required reason
for each. It found exactly one instance across the codebase.

`tests/unit/test_software_repository.py` pins the behaviour: the port's body is not
an ellipsis, the concrete repository returns `False` rather than `None`, and a
purchase check is reachable only by an owner.

### The two failing tests, and what they were actually about

`tests/unit/test_search_algorithm.py` had two failures on `main` since Phase 0, kept
as pre-existing through eight phases. They were not stale tests. They were correct
and the code was wrong.

`SearchAlgorithm.rank` derived the score and `matched_fields` from **two**
derivations of the same facts: `_calculate_relevance_score` summed four signals,
and `_identify_matched_fields` re-derived which of them applied. They disagreed.
The query signals were recorded and the popularity and recency signals were not,
so a result could be ranked by a signal it did not claim — which is precisely what
a reader of `matched_fields` is asking it to answer.

Both are now one pass. `_score_contributions` returns `{signal: contribution}`,
the score is its sum, and `matched_fields` is its keys — with a zero weight
contributing nothing and therefore not claiming credit:

```python
contributions = self._score_contributions(software, query_tokens, query_normalized, now)
scored.append(ScoredSoftware(
    software=software,
    score=float(sum(contributions.values())),
    matched_fields=[name for name, value in contributions.items() if value > 0.0],
))
```

The exact-match bonus is preserved as its own signal, `name_exact`, rather than
folded into `name`: a query token appearing in the name is weak evidence and the
query *being* the name is strong, and that distinction predates the phase.

The score arithmetic is unchanged. Checked against the `HEAD` version of the file over
11 queries × 4 candidates — including the empty query, a no-match query and two
mixed-case ones — with ranking order compared as well as scores:

- ranking order identical on every query;
- largest score disagreement `3.0e-12`, which is summation order;
- `matched_fields` differs on all 44 comparisons, and the old set is a strict
  subset of the new one every time. That is the fix, not a regression: the old
  list claimed only what `_identify_matched_fields` could see.

To reproduce: `git show HEAD:...search_algorithm.py` into a file, import both
classes, and call `rank` with the same candidate list.

### The document guard

`tests/architecture/test_architecture_doc_matches_code.py` (ADR 0014) compares the
section 2 tree with the filesystem in both directions, resolves every
`app/`/`tests/`/`docs/` path named in backticks, asserts each name marked *(not
implemented)* is still absent, and recomputes the counts the document quotes. It
found two fabrications while it was being written — the exception count and a
`Clock` port described as two-method when it declares one — and it is the reason
§3.6 no longer claims `category_schema.py` validates `slug`, a field that schema has
never had.

It does not check arguments. A document that stops arguing is a worse document,
and no gate should be the reason to delete an argument.

### Findings recorded and not fixed

Each of these is in `ARCHITECTURE.md` at the section named, with the evidence.

**`api/errors.py` shadows the global handler registry** (§12.3). Every
`software_router` handler wraps its body in `except SoftwareDomainError: raise
http_error(exc)`, and `http_error` maps everything unrecognised to 400. So
`InvalidStateTransitionError` answers 400 where `handlers.py` declares 409, and
`RepositoryUnavailableError` answers 400 where it declares 503. Fixing it changes
status codes, so it needs a phase whose invariant permits that.

**Five routers still construct a concrete `UnitOfWork`** (§3.2) — `auth_router`,
`user_router`, `resources_router`, `category_router`, `support_chat_router` —
duplicating `dependencies.py:78` and `shared/dependencies.py:53`. Carried from
Phase 8 unchanged; a rule banning it needs five ratchet entries, and growing a
file whose stated contract is that it can only shrink is the wrong trade in a phase
whose point is that the checks are real.

**`SoftwareService` exposes a `repository` property with a setter**
(`software_service.py:61`) that installs a test override, and `software_router.py:336`
uses it to build a `SearchService` from the service's own repository. A router
reaching into a service's dependency is the thing ADR 0011 moved composition roots
to prevent.

**`SearchService.search` catches bare `Exception`** (§10.4) and re-raises
`RepositoryUnavailableError`, so it translates a driver error the repository
already translated and swallows every other — a `SoftwareNotFoundError` would reach
the client as "Search repository unavailable". `DownloadService.record_download`
carries a comment explaining why it does not do the same.

**Four reachable write paths record events nobody dispatches** (§11.2).
`update_pricing`, `deprecate_version`, `revoke_version` and `record_download` each
record domain events; only the upload path calls `pull_events` and hands them to
the publisher. `SoftwareDownloadedEvent` — the one analytics would want — is among
them. Six more event classes have no producer at all.

**`Clock` has no caller** (§3.3). A one-method port and `SystemClock` implement
it; no service takes a clock, and every timestamp in this context comes from
`datetime.now()` at the point of use.

**`SoftwareAccessPolicy` is defined twice** (§14) — byte-identical apart from a
trailing newline, at `domain/policies/` and `policies/`. The only importer of the
second is `tests/unit/test_software_access_policy.py`, which `tests/conftest.py`
lists in `collect_ignore`, so it has no test and no caller. Adopting it is a
behaviour change: `ensure_can_download` requires `PUBLISHED` where the live path
accepts `DEPRECATED`, and requires `is_public()` even for a buyer.

**`Category`'s invariants have no test at all** (§18), nor does
`Artifact.verify_integrity`, and every download path is tested only against
hand-written fakes.

### Contract

Preserved exactly.

- Route table unchanged — `test_public_http_surface.py` green.
- `GET /api/v1/software-management/search` returns `items`, `scores`, `total`,
  `limit`, `offset`, in that order, and still no `matched_fields`. Scores are
  arithmetically identical to Phase 8; `matched_fields` is internal and was wrong.
- Paid, non-public software still answers 403 to a non-owner, with or without a
  purchase record, because there is no purchase record.
- `has_purchase` returns `False`, which is what the inherited body effectively
  produced through `None`.
- All 636 tests pass; the 2 pre-existing failures are fixed, none introduced.

### Not changed, on purpose

- **The exact-match bonus is case-sensitive.** `_calculate_name_contributions`
  compares `software.name.lower()` against `query_normalized`, which is stripped
  but never lowercased, so `?q=MyPackage` scores lower than `?q=mypackage` for the
  same product and the bonus has never fired for a query containing a capital
  letter. Fixing it changes `score`, which is returned by the search route. Pinned
  by `test_the_exact_match_bonus_is_case_sensitive_and_that_is_pinned` — pinned
  rather than ignored, because it is otherwise indistinguishable from intended
  weighting: someone tuning `exact_match_boost` would see it have no effect on a
  mixed-case query and conclude the weight was wrong.
- **`_calculate_recency_score` catches bare `Exception`** and returns 0.0, so a
  broken timestamp is indistinguishable from an old one. Same reasoning: the
  `scores` array is on the wire.
- **`Software._ensure_modifiable` does not require `ACTIVE`**, although its error
  message says "Software must be ACTIVE to be modifiable". `DRAFT` has to be
  modifiable or nothing could be published. The behaviour is right and the message
  is wrong; the message is not on the wire, so it is recorded rather than changed.
- **`update_pricing` does not update `access_type`.** Pricing a free product
  leaves it `FREE`, so `requires_payment()` is False and the paid branch of the
  download check never runs. Changing it changes access outcomes.

### Mutation checks

Every claim this phase asserts was checked by breaking the code and confirming a
test failed.

| Mutation | Caught by |
|---|---|
| restore `...` to `ISoftwareRepository.has_purchase` | `test_a_raising_member_actually_raises` |
| `return False` above the raise in the same port member | same — the test was strengthened because this one survived |
| delete `SQLAlchemySoftwareRepository.has_purchase` | `test_no_implementation_inherits_a_silent_port_body` |
| make it `return None` | `test_software_repository.py` |
| remove the popularity contribution | `test_popularity_increases_score` |
| record zero-weight contributions | `test_a_zero_weight_signal_is_not_claimed` |
| remove `name_exact` from the contribution mapping | `test_an_exact_name_match_is_reported_separately` |
| delete a file listed in the document's tree | `test_the_tree_has_no_file_that_is_not_there` |
| add a file the tree omits | `test_the_tree_has_no_file_it_forgot` |
| change the exception count to 28 | `test_the_exception_count_the_document_quotes` |
| restore `matched_fields` to the search response | `test_matched_fields_is_still_out_of_the_search_response` |
| add an entry to `ratchet.json` | `test_the_ratchet_is_still_empty` |
| define `ClamAVScanner` while §8.3 says *(not implemented)* | `test_a_name_marked_not_implemented_is_still_absent` |

Thirteen mutations, thirteen caught — but only after one of them was caught twice.
`test_a_raising_member_actually_raises` originally asked whether the port body
*contained* a `raise`, which `return False` written above it satisfies: the method
silently defaulted to exactly what ADR 0013 exists to prevent, and the guard
passed. The test now requires the raise to be the first statement, which is the
shape `Clock.now` already had. This is the third time a check has passed because it
was looking at the wrong thing rather than because the code was right, after Phase
7b's route-table hash and Phase 8's `.gitignore` pattern.

The exception count was the other fabrication caught twice: the guard failed while
it was being written, on the 28 the document claimed, and again when a later edit
described `Clock` as it had been described rather than as it is.
