# Architecture Decision Records

Structural decisions made while refactoring this codebase onto DDD / Clean
Architecture / Hexagonal boundaries. One file per decision, numbered, immutable
once accepted — a change of mind is a new ADR that supersedes the old one.

Read these alongside `app/modules/software_management/ARCHITECTURE.md`, which
describes the target structure. The ADRs record *why* particular choices were
made and what was rejected; the architecture document describes what the code
looks like. Where they disagree, the ADRs win and the architecture document is
a bug.

The boundary rules described here are executable:
`tests/architecture/layer_rules.py`.

## Index

| # | Title | Status |
|---|---|---|
| 0001 | [Module per bounded context, layers within](0001-module-per-bounded-context.md) | Accepted |
| 0002 | [Mappers live in infrastructure, not the shared kernel](0002-mappers-live-in-infrastructure.md) | Accepted |
| 0003 | *(reserved)* | — |
| 0004 | [Enforce layer boundaries with a ratchet](0004-enforce-layer-boundaries-with-a-ratchet.md) | Accepted |

## Template

```markdown
# ADR NNNN: <decision, as a statement>

- **Status:** Proposed | Accepted | Superseded by ADR NNNN
- **Date:** YYYY-MM-DD
- **Deciders:** <who>
- **Related:** <other ADRs>

## Context
<The forces at play. What made a decision necessary.>

## Decision
<What was decided, stated in the active voice.>

## Rationale
<Why this and not the alternatives. Name the rejected options.>

## Consequences
**Good** / **Bad** / **Neutral**
```

## Refactor phase map

The ADR numbers are independent of the refactor phases. For the phase-by-phase
breakdown, including the code for review, see `docs/REVIEW.md`.

| Phase | Scope | ADRs |
|---|---|---|
| 0 | Baseline commit, dependency and artefact hygiene | — |
| 1 | Layer boundary enforcement; mapper/presenter split | 0002, 0004 |
| 2 | `UnitOfWork` port; per-module composition roots | 0001 |
| 3 | `software_management` brought into line with its own rules | 0001 |
| 4-8 | Per-module domain models, in dependency order | 0001 |
| 9 | Ratchet drained, tests re-enabled, docs corrected | 0004 |
