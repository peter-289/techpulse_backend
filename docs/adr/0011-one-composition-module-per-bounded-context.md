# ADR 0011: One composition module per bounded context

- **Status:** Accepted
- **Date:** 2026-09-30
- **Deciders:** refactor
- **Related:** ADR 0001, ADR 0004, ADR 0010

## Context

`app/modules/shared/dependencies.py` had reached 474 lines. It resolved the
database session, the Redis client, the unit of work, access-token decoding,
access-token revalidation, RBAC, the abuse-protection singleton, the malware
scanner, local storage, the download signer, the domain event publisher, the
artifact stager, the upload limits, the alert thresholds, the support-chat AI
provider, and four use-case factories — for five bounded contexts.

Nothing was wrong with any individual provider. The problem was that one module
had no owner, and the codebase had already paid for that three times:

- **Duplicated definitions.** `dependencies.py` and `security/token_manager.py`
  each defined `oauth2_scheme`, `credentials_exception`, `EXPECTED_ISSUER`,
  `EXPECTED_PURPOSE` and `EXPECTED_RESET_PURPOSE`. `dependencies.py` also held a
  copy of `ACCESS_TOKEN_REQUIRED_CLAIMS` that only existed because the copy that
  reads tokens lived there.
- **Cross-context reach-through.** `analytics_router` built its own `AuditService`
  from a concrete `UnitOfWork` and read the alert thresholds from the composition
  root directly, rather than through `get_audit_service`.
- **A service importing the composition root.** `auth_service` called
  `get_email_user` and `get_password_reset_user` — two pure functions — out of the
  module that wires the application together.

There was also the last unmodelled read in the codebase. `revalidate_access_token`
built `select(UserSession, User).join(...)` itself and read `revoked_at`,
`expires_at`, `status` and `role` off the rows, so the code path that runs on
essentially every authenticated request had no domain model behind it.

## Decision

Split the composition root by ownership. Each bounded context gets one
`dependencies.py` at its root, holding the providers that context answers for. The
shared remainder keeps only what has no owning context.

| Provider | Home |
|---|---|
| `get_db`, `get_redis`, `get_unit_of_work` | `app/modules/shared/dependencies.py` |
| tokens, principals, `require_role`, abuse protection, audit service | `app/modules/security/dependencies.py` |
| scanner, storage, signer, event publisher, stager, software use cases | `app/modules/software_management/dependencies.py` |
| the support-chat AI provider | `app/modules/user/dependencies.py` |

Token *verification* moves to `app/modules/security/token_manager.py`, next to the
code that mints the tokens it reads. The duplicated constants are deleted; one
definition of each remains.

`revalidate_access_token` reads through `SessionRepository.get_by_id` and
`UserRepository.get_user_by_id`, and decides with `UserSession.is_usable_at` and
`User.is_verified` instead of with attribute access on ORM rows.

## Rationale

**Why per context rather than one file.** Ownership is the only thing that was
missing. Every one of the twenty-odd providers had exactly one obvious home, which
is itself the evidence that they were misfiled: nothing about the split required a
judgement call. A module with no owner is where duplicated definitions and
reach-through couplings go to breed, and all three had already appeared.

**Why not per-context `api/dependencies.py`, which is what
`ARCHITECTURE.md` §2 and §9.1 specify.** ADR 0001 already rejected that layout, for
a reason this change does not dispute: it repeats the same `Depends(...)` plumbing
per module, and the baseline commit shows what that costs — `user/dependencies.py`
and `shared/dependencies.py` had already drifted apart. Nothing here duplicates
anything; each provider is still defined exactly once. What changes is *where* the
concerns live.

**Why not a `shared/dependencies/` package with per-concern submodules.** This is
the closer alternative, and it is a real option: it would keep every import path
under `app.modules.shared`, and it would satisfy ADR 0001's stated consequence that
`shared/dependencies.py` "can be split by concern". It was rejected because it
keeps the thing that is broken. Software management's use-case factories would
still live outside `software_management`, so the compiler cannot tell you that a
software-management provider belongs to software management, and the next
cross-context reach-through has nowhere to reveal itself. The split is worth doing
only if it changes where a provider *is*, not merely which file it is spelled in.

**Why the context root and not a layer directory.** A composition module
constructs objects; it does not serve HTTP, hold a domain rule, or orchestrate a
use case. Putting it in `api/` would classify `Depends`, `Request` and
`HTTPException` usage as the API layer, which is defensible but is a claim about
wiring being transport. The context root is where this codebase already puts files
that belong to no layer — `authentication/auth_router.py` and `auth_service.py`,
`security/audit_middleware.py`, `security/token_manager.py`. Consistency with the
existing convention beat a new one.

**Why token verification is not a provider.** `decode_access_token` and the
reset/verification decoders take a string and return claims. Nothing is injected
into them and they are not `Depends` callables. They are token handling, so they
sit with the token minting code — which is also what lets the duplicated constant
sets collapse into one.

**Why revalidation keeps two queries.** The old version joined the session and its
account in one statement; asking two repositories costs two round trips on every
authenticated request. Keeping it at one would need a port method returning "the
account behind this session", which puts an authentication-shaped join inside the
user context to save a local query. The `sub`/`sid` binding is checked against the
session's own `user_id` before the account lookup, so a mismatched token — the only
case that could waste the second query — still costs one.

## Consequences

**Good**

- `shared/dependencies.py` is 53 lines and imports no bounded context at all.
- Token constants have one definition. `auth_service` imports from the module that
  owns tokens rather than from the composition root.
- No ORM model is reachable from the request path's identity resolution, and
  `tests/architecture/test_request_path_has_no_orm_models.py` fails if one comes
  back.
- A software-management provider added later has one obvious location, and R2 would
  flag a context reaching for another context's use cases by path.

**Bad**

- This deviates from ADR 0001, which preferred a single container. It follows
  ADR 0001's "split by concern" consequence but not its placement. Recorded here
  rather than reconciled by editing ADR 0001, which is immutable once accepted.
- `ARCHITECTURE.md` §2 (the tree listing `api/dependencies.py`), §9.1 and §15.1
  now describe a layout the code does not use. The document was already behind the
  code in four places before this; Phase 9 corrects all of them, and this adds two
  more entries to that list.
- Every importer now names the module a provider came from, which is the opposite
  of ADR 0001's stated consequence. The mitigation is that the rule is mechanical
  — a provider has one home, and the import shows which — and
  `tests/architecture/test_request_path_has_no_orm_models.py` asserts
  `shared/dependencies.py` re-exports nothing, so the split cannot quietly collapse
  back into one module.
- `revalidation` costs one more query per authenticated request.

**Neutral**

- No route, request, response or status-code change; the route table is
  byte-identical, and the 401/403 outcomes of every check are unchanged.
- A session storage failure is still a 500; only the exception type changed.
- The repositories `revalidation` drives are still typed `object` at both call
  sites, because ADR 0001's R2 forbids a context naming another context's ports.
  This is the same gap ADR 0009 and ADR 0010 recorded; see `docs/REVIEW.md`.
- Ratchet unchanged at one entry. The files this phase touched were never
  violations under any of the eight rules, which is itself worth recording: the
  layering rules do not classify a context root, so nothing here is enforced by
  them. The new guard test exists because of that.