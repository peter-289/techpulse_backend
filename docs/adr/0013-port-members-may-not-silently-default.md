# ADR 0013: A port member may not silently default

- **Status:** Accepted
- **Date:** 2026-10-01
- **Deciders:** backend maintainers
- **Supersedes:** nothing
- **Related:** ADR 0002 (mappers live in infrastructure), ADR 0004 (layer boundaries and the ratchet), ADR 0005 (real domain events)

## Context

Every repository in this codebase names its port as a base class:

```python
class SQLAlchemySoftwareRepository(ISoftwareRepository):
```

A `Protocol` subclass that is not itself a protocol is an ordinary class, so it
**inherits the port's method bodies**. A port member written as `...` is therefore
not an unimplemented interface — it is an implementation, supplied to every class
that forgets to write one, returning `None`.

`ISoftwareRepository.has_purchase` was written as `...`. `SQLAlchemySoftwareRepository`
never overrode it, so every call returned `None`.

Three files asked that question about authorization. `SoftwareService.download_url`
and `download_artifact_url` and `DownloadService.create_download_url` each read it
as `not software.is_public() and not software.is_owned_by(user_id) and not
has_purchase`. A fourth site, the router at `software_router.py:238`, reached the
same conclusion through `SoftwareService.has_purchase`.

`None` is falsy, and a falsy `None` is indistinguishable from a real answer. Every
purchase check in the codebase reported "this user bought nothing" — with no
signal that the question had gone unasked.

**The answer was correct, which is the part worth writing down.** The purchase
table was removed with the `billing` module, so no purchase can be recorded and no
user can be a buyer. The wrong answer was accidentally the right one. Nothing
failed: no test asserted the value, no request returned an unexpected status, no
log line appeared. It would have survived until purchases were modelled, at which
point the failure would have looked like an authorization bug in a feature that had
not been written yet.

Three things had been built around it, all of which read as care:

- `DownloadService.create_download_url` guarded the call with
  `hasattr(repo, "has_purchase")`. The attribute was always inherited, so the guard
  was never once `False` — dead code shaped exactly like defensive programming.
- A codebase-wide sweep for exactly this defect, written with
  `pkgutil.walk_packages(app.__path__)`, reported the tree clean. `domain/` and
  `infrastructure/` have no `__init__.py`, so the walk descended past both and never
  saw half the files in the context.
- `tests/architecture/test_request_path_has_no_orm_models.py` and the layer rules
  both use `ast` over the filesystem for the same reason: a check that cannot see
  the code passes.

## Decision

1. **A port member that decides anything may not have a `...` body.** Such a member
   raises `NotImplementedError` instead, so a forgotten override fails at the first
   call with a traceback pointing at the port that owes the implementation.
   `Clock.now` in this same context already had this shape; `has_purchase` now
   matches it.
2. **Every explicit protocol subclass implements every member of the port.**
   `tests/architecture/test_ports_have_no_silent_defaults.py` sweeps `app/` and
   fails on any class that names a port and omits a member, unless that member is
   in its `RAISING_MEMBERS` table — each entry of which must name the reason that
   member is unsafe to default.
3. **Where the truthful answer exists, the adapter states it.**
   `SQLAlchemySoftwareRepository.has_purchase` returns `False` explicitly, with the
   reason in its docstring: there is no purchase to record.
4. **The sweep walks the filesystem, never `pkgutil`.** Namespace packages are
   importable and invisible to a package walk, and that invisibility is how a
   clean report was produced.

## Rationale

**Why not simply delete `has_purchase`.** The three call sites ask a real question
— "may this user download this without owning it?" — and a fourth condition is
where a purchase-based product would put it. Deleting the method would collapse
those checks silently into public-or-owner, which is a larger silent default than
the one being fixed, and it would make the eventual reintroduction look like a new
feature rather than the completion of a designed one.

**Why `False` in the adapter rather than an exception at the call site.** The
adapter is the only layer that knows *why* the answer is `False`, and it is the
layer that would have to change when purchases arrive. Raising would have turned
every request for a paid, non-public artifact into a 500 — a client-visible
contract change, in a phase whose invariant is that the HTTP API does not change,
and a strictly worse answer than the one already available. The 403 for
unauthorized users is preserved exactly.

**Why not rely on a test to catch this.** A test that asserted `has_purchase` is
`False` would have pinned today's answer without explaining it, and would still
pass if the port body were restored. The guard is placed on the *shape* — the
inherited ellipsis — so it fails on the defect rather than on one consequence of
it.

**Why raise in the port rather than in an `abc`.** These are `Protocol`s, which
cannot have abstract methods enforced at instantiation; the only mechanisms
available are the body itself and a structural check. The body is the one that
travels with the port to every reader of the file, and the sweep covers the rest.

**Acknowledged cost.** `raise NotImplementedError` in a port body is unusual, and a
reader who does not know the rule may read it as unfinished work. That is the cost
of making the alternative impossible to write by accident.

## Consequences

**Good**

- A forgotten port implementation fails loudly and names the port.
- The `hasattr` guard in `DownloadService` is gone, because the question it asked
  has an answer.
- The sweep found exactly one instance across `app/`, which is recorded as evidence
  that this is an isolated defect rather than a systemic one — and it found it by
  looking where the defect was, not by looking harder at the wrong tree.
- Any future port added with a `...` body on a decision-making member fails CI
  rather than shipping.

**Bad**

- `RAISING_MEMBERS` is a second place to remember. An entry must name a reason, and
  a test asserts each entry actually raises and is actually reachable, so it cannot
  rot into a silent list of things that are fine as they are.
- The sweep's completeness depends on its parsing staying complete. It pins a
  sample of the ports it must keep finding, so a parsing regression fails loudly
  instead of reporting an empty result.

**Neutral**

- The three call sites still each contain their own copy of the authorization
  check. Consolidating them is a behaviour-neutral refactor and is deferred; this
  ADR makes the wrong answer impossible, not the duplication.