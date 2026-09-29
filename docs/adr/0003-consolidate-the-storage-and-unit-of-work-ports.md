# 0003. Consolidate the storage port and the Unit of Work port

## Status

Accepted

## Context

Phase 1 gave the codebase an executable import-graph gate. Running it exposed
two things that the prose architecture document had described differently from
the code.

**Unit of Work.** `app/infrastructure/database/unit_of_work.py` was a single
class holding every repository in the system, and eight application services
imported it directly. That is the one dependency that makes a bounded context
unextractable: the service is coupled to the shared adapter rather than to a
contract, so "replace the database" stops being a local change. The stated fix
was for each service to depend on a `domain/ports/unit_of_work.py`.

There was a second problem hiding behind the first. The global Unit of Work
exposes every repository, so any service handed it can reach any context's
tables. A per-context port that merely renames the class fixes the import
without fixing the reach. `SoftwareManagementUnitOfWork` therefore lists
exactly `software_repo` and `category_repo`; there is no artifact repository
because artifacts have no independent lifecycle and are persisted through
`software_repo.save`.

**Storage.** `app/infrastructure/storage/local_storage.py` defined its own
`Storage` protocol, its own `DownloadUrlSigner` protocol, its own
`SignedDownloadUrl`, and its own six-class `StorageError` hierarchy, all
alongside near-identical definitions in
`app/modules/software_management/domain/ports/storage.py`.

The duplicated exception hierarchy was not a tidiness problem, it was a live
bug. When `download_service` was pointed at the domain exceptions, every
`except StorageFileNotFoundError` clause in it went dead: the adapter raised
the *infrastructure* class, which is not a subclass of the domain one. A
missing artifact would have escaped its error handler and surfaced as an
unhandled 500 from an unrelated frame.

## Decision

Consolidate both contracts into the domain, one definition each, and let
infrastructure depend on them.

- `app/modules/shared/unit_of_work.py` holds `UnitOfWorkPort`, the transaction
  contract (`__aenter__`, `__aexit__`, `read_only`, `commit`, `rollback`) that
  is the same in every context.
- Each context declares its own port in
  `app/modules/<context>/domain/ports/unit_of_work.py`, extending the shared one
  and listing only its repositories. software_management, user, authentication,
  resource and security each have one.
- Ports are `Protocol`s, not ABCs. An ABC would force the shared concrete class
  to subclass one base per context, which reintroduces the coupling at the
  class level; a structural protocol lets one adapter satisfy all five.
- The concrete `UnitOfWork` asserts conformance to all five ports at import
  time. A protocol is structural, so a repository missing from the class is not
  a type error at the injection point; it is an `AttributeError` on the first
  request that touches it. The check turns that into a startup failure.
- The storage contract and the storage exception hierarchy live only in
  `domain/ports/storage.py`. The signer contract lives in the pre-existing
  `domain/ports/download_signer.py`; Phase 3 corrected an interim decision
  recorded here that had duplicated it into `storage.py` as well.
  `local_storage.py` imports them and re-exports the names it previously
  defined, so existing importers keep working while resolving to a single class
  object.
- `app/exceptions/handlers.py` imports the storage exceptions from the domain
  port rather than from the adapter, so the HTTP mapping is keyed to the classes
  adapters actually raise.
- Rule R2 is refined, not relaxed. `app/infrastructure/**` and
  `app/modules/shared/**` may import another context's `domain.ports` and
  nothing else. Without this the new ports would trip the rule that made Phase
  1 possible. The narrowing matters: an entity import is how a shared module
  starts accumulating knowledge of aggregates it does not own, which is exactly
  the defect Phase 1 removed from `shared/mappers.py`.

## Consequences

- Six R4 ratchet entries are deleted. R4 goes 11 -> 5, the ratchet 19 -> 13.
- No application service imports the concrete Unit of Work. Enforced twice: the
  R4 rule statically, and a test in `tests/unit/test_unit_of_work.py` at
  runtime, so the guarantee survives someone re-adding a ratchet entry.
- The `except` clauses in `download_service` are live again. Pinned by
  `tests/unit/test_storage_port.py`, which asserts the adapter's exception
  names *are* the domain's, by identity.
- `download_service` no longer imports the local storage adapter; it depends on
  `Storage` and `DownloadUrlSigner` from the domain. Swapping to S3 or GCS is
  now a wiring change.
- The global `UnitOfWork` is still one class, and infrastructure still imports
  all five ports. That is a deliberate transitional state, recorded in ADR 0001.
  Splitting it per context is not scheduled: the boundary that matters for
  application code is already in place, and splitting the adapter is
  infrastructure work that no application code is waiting on. Revisit in Phase 9
  if the god object is still a problem once the contexts have real domain models.
- Four `domain/ports/unit_of_work.py` files annotate their repositories as
  `object` because those contexts have no domain model yet. `isinstance` still
  checks structure, so conformance is real; the annotations narrow in Phases 4
  through 6.
- The route table is unchanged: 50 routes, identical hash before and after.

## Alternatives considered

**One shared `UnitOfWorkPort` in `app/modules/shared`.** Fewer files, and the
import graph stays simpler. Rejected: every service could then reach every
repository, which is the coupling being removed. A single type that everything
shares is how the god object regrows after being renamed.

**Subclassing an ABC per context.** Explicit, and an editor would catch a
missing repository. Rejected for the reasons above: the concrete adapter would
need one base class per context, so the shared infrastructure would import
every context's domain at the class level and the runtime check would be
replaced by a coupling the ratchet would then have to allowlist.

**Leave the storage duplicates and re-export the domain ones from the adapter.**
Leaves the trap armed. The two hierarchies only stay in sync while someone
notices; the one time they diverged, the divergence was invisible.
