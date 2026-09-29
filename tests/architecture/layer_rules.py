"""Static import-graph analysis for the DDD layer boundaries.

This module is the single source of truth for "is a layer boundary respected?".
It is consumed by ``test_layer_boundaries.py`` (CI) and can be run directly for
a report::

    python -m tests.architecture.layer_rules

The rules encode the dependency direction from
``app/modules/software_management/ARCHITECTURE.md`` section 3.1:

    api  ->  application  ->  domain  <-  infrastructure
                                    ^
                                    |
                              (ports only)

Analysis is done on the AST rather than with ``import-linter`` so the rules
live in the test suite, run with the project's own pytest invocation, and stay
readable in review. The trade-off is that it only sees *static* ``import``
statements: a ``importlib.import_module`` or a dependency injected at runtime
would not be caught. That is acceptable here because every cross-module
reference in this codebase is a static import.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path

#: Repository root, i.e. the directory that contains ``app/`` and ``tests/``.
REPO_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = REPO_ROOT / "app"

#: Sub-packages that mark a module as layer-structured. A module under
#: ``app/modules/<module>/<one of these>/...`` is assigned that layer.
LAYERS = frozenset(
    {"api", "application", "domain", "infrastructure", "schema", "policies"}
)

#: Layers that may only depend inward. ``policies`` is grouped with
#: ``application`` because a policy object is use-case logic that happens to be
#: stateless, not a domain concept living inside the aggregate.
INNER_LAYERS = frozenset({"domain", "application", "policies"})

#: Third-party packages that must never be reachable from the domain layer.
#: ARCHITECTURE.md 3.4 requires zero framework dependencies in the domain.
FRAMEWORK_ROOTS = frozenset(
    {"fastapi", "starlette", "sqlalchemy", "pydantic", "redis", "jose", "httpx"}
)

#: SQLAlchemy submodules that build queries. A router may import
#: ``sqlalchemy.ext.asyncio`` purely to type-annotate an ``AsyncSession``
#: dependency, but must never build statements.
QUERY_BUILDING_SQLALCHEMY = frozenset(
    {
        "sqlalchemy.select",
        "sqlalchemy.func",
        "sqlalchemy.and_",
        "sqlalchemy.or_",
        "sqlalchemy.update",
        "sqlalchemy.delete",
        "sqlalchemy.insert",
        "sqlalchemy.join",
        "sqlalchemy.aliased",
        "sqlalchemy.orm",
        "sqlalchemy.exc",
    }
)

#: Layer values that count as "outward": importing these from an inner layer is
#: a boundary violation. ``<outward>`` covers the shared adapter packages
#: (``app.infrastructure``, ``app.core``) which have no feature-module layer of
#: their own but are equally forbidden.
OUTWARD_LAYERS = frozenset({"api", "schema", "infrastructure", "<outward>"})

#: Suffixes that mark a file as belonging to the application (use-case) layer
#: for rules that are about services specifically rather than about a directory.
SERVICE_SUFFIXES = ("_service.py",)

#: Top-level packages under ``app/`` that are shared across bounded contexts,
#: mapped to how the layer rules must treat them.
#:
#: ``app.infrastructure`` and ``app.core`` are adapters. They read the
#: environment, own the ORM and wire concrete implementations, so a domain or
#: application module importing them is the same mistake as importing a
#: feature module's infrastructure directory, just harder to see because the
#: path contains no ``modules`` segment.
#:
#: ``app.exceptions`` is the shared kernel: ``DomainError`` is a genuine
#: cross-cutting domain concept that every context's exceptions derive from,
#: so domain and application are allowed to import it.
TOP_LEVEL_SHARED: dict[str, str] = {
    "app.infrastructure": "<outward>",
    "app.core": "<outward>",
    "app.exceptions": "<kernel>",
}

#: Files that are allowed to import another module's domain layer, with the
#: reason. These are deliberate cross-context bridges, not oversights, so they
#: are encoded in the rule rather than carried in the ratchet -- a ratchet entry
#: is meant to be temporary, and these would otherwise sit there forever.
#:
#: ``app/exceptions/handlers.py`` must translate every bounded context's domain
#: exceptions into HTTP responses, so it is the one place that is expected to
#: know about all of them.
PERMITTED_CROSS_CONTEXT_READERS: dict[str, str] = {
    "app/exceptions/handlers.py": (
        "The API exception handler is the single translation point from every "
        "bounded context's domain exceptions to HTTP responses."
    ),
}



def _module_name(path: Path) -> str:
    """Return the feature module a file belongs to.

    ``app/modules/user/api/router/user_router.py`` -> ``user``.
    Files directly under ``app/`` or ``app/core`` return their own top-level
    package name, which callers treat as "not a feature module".
    """
    parts = path.relative_to(REPO_ROOT).parts
    if len(parts) > 2 and parts[1] == "modules":
        return parts[2]
    return parts[1] if len(parts) > 1 else ""


def _layer_name(path: Path) -> str | None:
    """Return the layer a file belongs to, or ``None`` if it is not layered."""
    parts = path.relative_to(REPO_ROOT).parts
    if len(parts) > 3 and parts[1] == "modules":
        rest = parts[3:]
        return next((layer for layer in LAYERS if rest[0] == layer), None)
    return None


def _parse_imports(path: Path) -> set[str]:
    """Return every module name imported by ``path``.

    Both ``import a.b`` and ``from a.b import c`` are normalised to the
    imported module path, so callers can inspect the dotted prefix.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            imported.add(node.module)
    return imported


@dataclass(frozen=True, slots=True)
class Violation:
    """A single broken boundary, identified by a stable string key.

    The key deliberately contains the importing file, the imported module and
    the import path, so a reviewer reading a ratchet entry can find the
    offending line without running anything.
    """

    rule: str
    source: str
    target: str

    @property
    def key(self) -> str:
        return f"{self.source} -> {self.target}"


def _import_layer(target: str) -> tuple[str | None, str | None]:
    """Classify a dotted import as ``(feature_module, layer)``.

    Layer values:

    - a member of :data:`LAYERS` when the import targets a feature module's
      layer, e.g. ``app.modules.user.domain.entities`` ->
      ``("user", "domain")``;
    - ``"<outward>"`` for ``app.infrastructure`` and ``app.core``, which are
      shared adapters that inner layers must not reach;
    - ``"<kernel>"`` for ``app.exceptions``, the shared exception kernel;
    - ``None`` for anything else, which the callers ignore.
    """
    parts = target.split(".")
    if "modules" not in parts:
        for prefix, layer in TOP_LEVEL_SHARED.items():
            if target == prefix or target.startswith(prefix + "."):
                return None, layer
        return None, None

    index = parts.index("modules")
    if index + 2 >= len(parts):
        return None, None
    feature = parts[index + 1]
    rest = parts[index + 2 :]
    layer = rest[0] if rest[0] in LAYERS else None
    return feature, layer


@dataclass(frozen=True, slots=True)
class Rule:
    """A named boundary rule and the violations currently violating it."""

    rule_id: str
    description: str
    # ``None`` marks a hard rule: the violation set must be empty and it may
    # not appear in the ratchet at all.
    allowlist: tuple[str, ...] | None
    violations: tuple[Violation, ...]

    @property
    def keys(self) -> set[str]:
        return {v.key for v in self.violations}


def rule_domain_is_framework_free() -> Rule:
    """R1: the domain layer must not import any framework.

    Hard rule. ARCHITECTURE.md 3.4. Passing today, so it stays unenforced only
    by convention until it is guarded here.
    """
    violations = []
    for path in _python_files():
        if _layer_name(path) != "domain":
            continue
        for target in _parse_imports(path):
            if target.split(".")[0] in FRAMEWORK_ROOTS:
                violations.append(Violation("R1", _rel(path), target))
    return Rule(
        "R1",
        "domain must not import fastapi/starlette/sqlalchemy/pydantic/redis/jose/httpx",
        None,
        tuple(violations),
    )


def rule_bounded_context_isolation() -> Rule:
    """R2: a feature module must not import another module's domain layer.

    Hard rule. Cross-context coupling is only permitted through
    ``app.modules.shared``. The single deliberate exception is
    ``app/exceptions/handlers.py``, listed in
    ``PERMITTED_CROSS_CONTEXT_READERS``.

    One known violation remains: ``app/modules/shared/mappers.py`` maps ORM
    models to the software_management domain entities. ARCHITECTURE.md 5.3
    places mappers in ``infrastructure/persistence/mappers``; the shared kernel
    has no business knowing one context's aggregates.
    """
    violations = []
    for path in _python_files():
        source = _rel(path)
        if source in PERMITTED_CROSS_CONTEXT_READERS:
            continue
        own = _module_name(path)
        for target in _parse_imports(path):
            other, layer = _import_layer(target)
            if layer == "domain" and other is not None and other != own:
                violations.append(Violation("R2", source, target))
    return Rule(
        "R2",
        "a module must not import another module's domain layer (use app.modules.shared)",
        None,
        tuple(violations),
    )


def rule_domain_does_not_import_infrastructure() -> Rule:
    """R3: the domain layer must not import infrastructure.

    Hard rule. The domain declares ports; infrastructure implements them.
    Passing today.
    """
    violations = []
    for path in _python_files():
        if _layer_name(path) != "domain":
            continue
        for target in _parse_imports(path):
            _, layer = _import_layer(target)
            if layer in {"infrastructure", "<outward>"}:
                violations.append(Violation("R3", _rel(path), target))
    return Rule(
        "R3",
        "domain must not import infrastructure (ports belong in domain, implementations in infrastructure)",
        None,
        tuple(violations),
    )


def rule_application_depends_only_inward() -> Rule:
    """R4: application must not import api, schema or infrastructure.

    ARCHITECTURE.md 3.3: "Application ... Must never import SQLAlchemy models,
    FastAPI types, or filesystem APIs."

    "Infrastructure" here includes the shared adapter packages
    ``app.infrastructure`` and ``app.core``, not just a feature module's
    ``infrastructure/`` directory. In practice the dominant case is an
    application service importing the concrete ``UnitOfWork``, which lives in
    ``app.infrastructure.database``. Phase 2 moves those onto per-module domain
    ports.

    Ratcheted. Known violations are recorded in ``ratchet.json``.
    """
    violations = []
    for path in _python_files():
        if _layer_name(path) != "application":
            continue
        for target in _parse_imports(path):
            _, layer = _import_layer(target)
            if layer in OUTWARD_LAYERS:
                violations.append(Violation("R4", _rel(path), target))
    return Rule(
        "R4",
        "application must not import api/schema/infrastructure",
        None,
        tuple(violations),
    )


def rule_services_do_not_use_orm_models() -> Rule:
    """R5: an application service must not import an ORM model.

    This is the anemic-model check. A service that imports
    ``infrastructure.database.models`` is treating the persistence record as
    its domain object, which means no domain model exists for that concept.

    Ratcheted. Two known violations: UserService and SupportChatService.
    """
    violations = []
    for path in _python_files():
        if not path.name.endswith(SERVICE_SUFFIXES):
            continue
        for target in _parse_imports(path):
            if "infrastructure.database.models" in target:
                violations.append(Violation("R5", _rel(path), target))
    return Rule(
        "R5",
        "an application service must not import an ORM model (it has no domain object)",
        None,
        tuple(violations),
    )


def rule_routers_do_not_build_queries() -> Rule:
    """R6: an API router must not build SQLAlchemy statements.

    Importing ``sqlalchemy.ext.asyncio`` to annotate an ``AsyncSession``
    dependency is fine; the composition root needs the type. Calling
    ``select()`` in a handler is not: it is repository work done in the
    transport layer, bypassing both the application and domain layers.

    Ratcheted. One known violation: admin_router.
    """
    violations = []
    for path in _python_files():
        if _layer_name(path) != "api" or "router" not in path.name:
            continue
        for target in _parse_imports(path):
            if target in QUERY_BUILDING_SQLALCHEMY or (
                target == "sqlalchemy"
            ):
                violations.append(Violation("R6", _rel(path), target))
    return Rule(
        "R6",
        "an API router must not build SQLAlchemy statements",
        None,
        tuple(violations),
    )


def rule_api_does_not_import_another_modules_api() -> Rule:
    """R7: a router must not import another module's api layer.

    Hard rule. Keeps feature routers from calling each other's endpoints'
    wiring, which would couple bounded contexts at the transport layer.
    Passing today.
    """
    violations = []
    for path in _python_files():
        if _layer_name(path) != "api":
            continue
        own = _module_name(path)
        for target in _parse_imports(path):
            other, layer = _import_layer(target)
            if layer == "api" and other is not None and other != own:
                violations.append(Violation("R7", _rel(path), target))
    return Rule(
        "R7",
        "a module's API layer must not import another module's API layer",
        None,
        tuple(violations),
    )


def _python_files() -> list[Path]:
    return sorted(APP_ROOT.rglob("*.py"))


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


ALL_RULES = (
    rule_domain_is_framework_free,
    rule_bounded_context_isolation,
    rule_domain_does_not_import_infrastructure,
    rule_application_depends_only_inward,
    rule_services_do_not_use_orm_models,
    rule_routers_do_not_build_queries,
    rule_api_does_not_import_another_modules_api,
)


def collect() -> list[Rule]:
    """Run every rule and return the results, including hard rules."""
    return [factory() for factory in ALL_RULES]


@dataclass(frozen=True, slots=True)
class RatchetEntry:
    """One accepted, known violation plus the phase that is meant to remove it."""

    rule_id: str
    key: str
    phase: str

    @property
    def source(self) -> str:
        return self.key.split(" -> ", 1)[0]

    @property
    def target(self) -> str:
        return self.key.split(" -> ", 1)[-1]

    def as_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule_id,
            "source": self.source,
            "import": self.target,
            "phase": self.phase,
        }


def load_ratchet(path: Path) -> dict[str, RatchetEntry]:
    """Load the checked-in allowlist of accepted, known violations.

    The on-disk format is a flat list of ``{rule, source, import, phase}``
    objects under a ``violations`` key, rather than a map keyed by rule. A flat
    list keeps each entry self-describing: when one rule's violations are
    cleared by three different phases, the remaining entries still say which
    phase owns them.

    Returns a mapping of ``rule_id -> {violation key -> entry}``.
    """
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))

    by_rule: dict[str, dict[str, RatchetEntry]] = {}
    for item in raw.get("violations", []):
        entry = RatchetEntry(
            rule_id=item["rule"],
            key=f"{item['source']} -> {item['import']}",
            phase=item["phase"],
        )
        by_rule.setdefault(entry.rule_id, {})[entry.key] = entry
    return by_rule


def allowed_violations(
    ratchet: dict[str, dict[str, RatchetEntry]], rule_id: str
) -> set[str] | None:
    """Return the allowlisted keys for a rule, or ``None`` for a hard rule.

    ``None`` means the rule is hard: it must have zero violations and must not
    appear in the ratchet at all.
    """
    entries = ratchet.get(rule_id)
    if entries is None:
        return None
    return set(entries)


def compare(
    rule: Rule, ratchet: dict[str, dict[str, RatchetEntry]]
) -> tuple[set[str], set[str], bool]:
    """Compare a rule against the ratchet.

    Returns ``(new, stale, is_hard)``:

    - ``new``   -- present in the code, absent from the ratchet. A regression.
    - ``stale`` -- present in the ratchet, absent from the code. Already fixed;
      the entry should be deleted.
    - ``is_hard`` -- the rule is a hard rule and may not be ratcheted.
    """
    allowed = allowed_violations(ratchet, rule.rule_id)
    if allowed is None:
        return rule.keys, set(), True
    return rule.keys - allowed, allowed - rule.keys, False


def _main() -> int:
    """Print a human-readable report. Returns a process exit code."""
    ratchet = load_ratchet(RATCHET_PATH)
    hard_failures = 0
    ratchet_failures = 0

    for rule in collect():
        new, stale, is_hard = compare(rule, ratchet)
        label = "HARD FAIL" if is_hard else "RATCHET DRIFT"
        good = "ok" if is_hard else "ratcheted"

        if is_hard and not new:
            print(f"[ok]        {rule.rule_id}: {rule.description}")
            continue
        if not is_hard and not new and not stale:
            print(
                f"[{good}] {rule.rule_id}: {len(rule.keys)} known violation(s) "
                f"recorded in the ratchet -- {rule.description}"
            )
            continue

        if is_hard:
            hard_failures += 1
        else:
            ratchet_failures += 1
        print(f"[{label}] {rule.rule_id}: {rule.description}")
        for key in sorted(new):
            print(f"    NEW   {key}")
        for key in sorted(stale):
            print(f"    FIXED {key}  (remove from {RATCHET_PATH.name})")
        print(f"    -> update {RATCHET_PATH.relative_to(REPO_ROOT)} to match")

    return 1 if (hard_failures or ratchet_failures) else 0


RATCHET_PATH = Path(__file__).resolve().parent / "ratchet.json"


if __name__ == "__main__":
    raise SystemExit(_main())
