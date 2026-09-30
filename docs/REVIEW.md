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
| 7b | split `shared/dependencies.py`; revalidation off the ORM | — | — | pending |
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
| R6 | routers build no SQLAlchemy statements | 1 | 1 — `admin_router`, Phase 8 |
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
