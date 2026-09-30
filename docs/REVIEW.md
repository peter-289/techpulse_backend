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
[ratcheted] R4: 5 known violation(s) recorded in the ratchet -- application must not import api/schema/infrastructure
[ratcheted] R5: 7 known violation(s) recorded in the ratchet -- an application service must not import an ORM model (it has no domain object)
[ratcheted] R6: 1 known violation(s) recorded in the ratchet -- an API router must not build SQLAlchemy statements
[ok]        R7: a module's API layer must not import another module's API layer
```

| Rule | Statement | Baseline | Now |
|---|---|---|---|
| R1 | domain imports no framework | 0 | 0 — hard |
| R2 | no cross-context `domain/` imports | 6 | 0 — **fixed in Phase 1** |
| R3 | domain imports no infrastructure | 0 | 0 — hard |
| R4 | application imports no `api`/`schema`/`infrastructure` | 1 | 5 — ratcheted |
| R5 | no service imports an ORM model | 7 | 7 — ratcheted |
| R6 | routers build no SQLAlchemy statements | 1 | 1 — ratcheted |
| R7 | no cross-context `api/` imports | 0 | 0 — hard |

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

