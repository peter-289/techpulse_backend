# ADR 0002: Mappers live in infrastructure, not in the shared kernel

- **Status:** Accepted
- **Date:** 2026-09-29
- **Deciders:** backend maintainers
- **Related:** ADR 0004 (enforce layer boundaries with a ratchet)

## Context

`app/modules/shared/mappers.py` had grown to 212 lines containing four unrelated
kinds of logic:

1. ORM model <-> domain entity conversion (`_software_to_entity`,
   `_software_to_model`, `_version_to_entity`, `_artifact_to_model`);
2. entity -> Pydantic response shaping (`_software_item`, `_version_item`);
3. domain exception -> `HTTPException` translation (`_error`);
4. assorted helpers (`_actor_uuid`, `_actor_int`, `_category`), two of which
   were dead.

Callers confirmed the split: `SQLAlchemySoftwareRepository` used only the
first group, and `software_router.py` used only the second and third.

Because the file lived in `app/modules/shared/`, every one of those imports
also made the shared kernel depend on `software_management`'s domain. Any
module importing a shared helper silently acquired a compile-time dependency
on the Software aggregate, the Version entity and the Artifact entity. That is
rule R2 in ADR 0004, and it was the one hard-rule violation present at the
start of the refactor.

`ARCHITECTURE.md` section 5.3 already said the right thing — "Mappers live in
`infrastructure/persistence/mappers/`" — the file was simply in the wrong place
when that section was written.

## Decision

Split `app/modules/shared/mappers.py` along the lines its callers already
drew, and put each part in the layer that owns that kind of work:

| Old symbol | New home | Why there |
|---|---|---|
| `*_to_entity`, `*_to_model` | `software_management/infrastructure/persistence/mappers/software_mapper.py` | A mapper depends on both the ORM model and the domain entities of one context. ARCHITECTURE.md 5.3. |
| `_software_item`, `_version_item` | `software_management/api/presenters.py` | Turning an entity into a wire format is transport shaping. |
| `_error` | `software_management/api/errors.py` | Mapping a domain error to a status code is a boundary concern. |
| `_actor_uuid`, `_actor_int` | deleted | Unreferenced. |
| `_category` | `api/presenters.py` | Presentation-only, with the shim documented in place. |

Rename the leading-underscore mapper functions to public names
(`software_to_entity`, `software_to_model`) since they are now imported across
a package boundary, where a leading underscore reads as "private" and is
misleading.

`tests/architecture/ratchet.json` has no R2 entry as a result, so R2 is a hard
rule from the start of the refactor.

## Rationale

**Why split by caller rather than keep one module per concern type.** The
existing callers already had the boundary right; only the file layout was
wrong. Moving code to match real usage means no caller changes beyond the
import line, which keeps the commit small and the review easy.

**Why presenters are in `api/`, not `application/`.** A service that returns a
Pydantic model has taken a dependency on the wire format. The moment the same
use case is driven by a message consumer or a CLI, the return type is wrong.
This is the same violation as R4, which is why R4 is ratcheted against
`SoftwareService`; `list_versions` is the remaining instance there.

**Why `api/errors.py` rather than the global handler registry.** A domain error
subtype can map to different statuses per context, and the global registry in
`app/exceptions/handlers.py` only knows the base types. Keeping the per-context
mapping in the per-context API layer means adding a domain error type forces a
decision about its HTTP status at the point the error is defined.

**Why delete `_actor_uuid` / `_actor_int`.** They were unreferenced in the
repository. Carrying them forward into a file that is now part of a documented
infrastructure boundary would give them a false impression of being load-bearing.

## Consequences

**Good**

- R2 is clean, so cross-context isolation is enforced as a hard rule for the
  rest of the refactor.
- `software_service.py` and `software_router.py` can now share
  `version_item()` instead of each maintaining their own version-rendering
  logic, which is how the same Pydantic shape ended up built in two places.

**Bad**

- A caller who imported from `app.modules.shared.mappers` gets an
  `ImportError` rather than a deprecation. There are two such callers and both
  were updated in the same commit, and the package is not published, so this is
  a non-issue in practice.
- `_category` remains a hack: it parses a `Category:` line out of the
  description because the read model still exposes a free-text category the
  aggregate has no field for. Splitting the file did not fix that, so it now
  carries an explicit note saying it is a shim and what replaces it.

**Follow-up**

- `SoftwareService.list_versions` still returns `SoftwareVersionRead`. Phase 3
  moves it to a domain read model and deletes the R4 entry.
