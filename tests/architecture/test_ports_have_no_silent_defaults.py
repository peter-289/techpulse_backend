"""A port member with a ``...`` body is a default value, not an interface.

The implementations in this codebase subclass their port *explicitly* rather than
structurally::

    class SQLAlchemySoftwareRepository(ISoftwareRepository):

A ``Protocol`` subclass that is not itself a protocol is an ordinary class, so it
inherits the port's method bodies. A member written as ``...`` is therefore
answered on an implementation that forgot to write it — quietly, at the first
call, with a traceback pointing at the port rather than at the class that owes the
implementation.

That is tolerable for a member whose value is only displayed, and it is not
tolerable for one that decides an authorization outcome, because ``None`` is
falsy and a falsy ``None`` is indistinguishable from a real answer. Phase 9a found
exactly that: ``ISoftwareRepository.has_purchase`` was never implemented, returned
``None`` for every user, and cost a 403 to any buyer of a paid product. The answer
was accidentally right — there is no purchase table, so nobody can be a buyer —
which is the dangerous part: a wrong answer that nothing can tell from a right one.

Two properties are enforced here:

1. no implementation inherits a port body, except for a member listed in
   ``RAISING_MEMBERS``, which the port itself refuses to default; and
2. each such member's body raises, so a forgotten override fails loudly.

The sweep parses the tree rather than importing it, and walks the filesystem
rather than using ``pkgutil.walk_packages``. Both choices are load-bearing.
Importing ``app.infrastructure.database.db_setup`` needs ``DATABASE_URL``, so an
import-based sweep is only as complete as the environment it runs in — it would
report fewer problems the less the environment was set up, which is the wrong
direction for a gate. And ``app/modules/software_management/domain/`` and
``infrastructure/`` have no ``__init__.py`` and are importable only as namespace
packages, so a package walk descends past neither and misses half the files in
this context without reporting anything. That is how a whole-codebase audit of
this exact defect first came back clean.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

APP_ROOT = Path(__file__).resolve().parents[2] / "app"

#: Port members whose body must raise instead of ``...``, each with the reason it
#: is one an implementation has to think about. Adding an entry is a decision that
#: the member is not safe to default.
RAISING_MEMBERS: dict[str, str] = {
    "ISoftwareRepository.has_purchase": (
        "it answers an authorization question, and an unimplemented one must not "
        "default to 'this user bought nothing' -- see the module docstring"
    ),
}

#: Ports the sweep must keep finding, so an empty or shrunken result fails.
EXPECTED_PORTS: frozenset[str] = frozenset(
    {
        "ISoftwareRepository",
        "ICategoryRepository",
        "ArtifactRepository",
        "SoftwareManagementUnitOfWork",
        "UserUnitOfWork",
        "UnitOfWorkPort",
        "SecurityUnitOfWork",
        "ResourceUnitOfWork",
    }
)


@dataclass(frozen=True)
class Port:
    """A ``Protocol`` class found in the tree."""

    dotted: str
    methods: tuple[str, ...]
    path: Path

    @property
    def short(self) -> str:
        return self.dotted.rsplit(".", 1)[-1]


@dataclass(frozen=True)
class Implementation:
    """A concrete class that names a port in its bases."""

    dotted: str
    port: Port
    path: Path
    defines: frozenset[str]


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(APP_ROOT.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _python_files() -> list[Path]:
    return sorted(p for p in APP_ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def _is_ellipsis_body(fn: ast.AST) -> bool:
    return (
        isinstance(fn, ast.Expr)
        and isinstance(fn.value, ast.Constant)
        and fn.value.value is Ellipsis
    )


def _is_docstring(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _sweep() -> tuple[dict[str, Port], list[Implementation]]:
    """Collect every protocol in the tree and every class that names one."""
    ports: dict[str, Port] = {}
    classes: list[tuple[str, Path, ast.ClassDef]] = []

    for path in _python_files():
        module = _module_name(path)
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            named = {b.id for b in node.bases if isinstance(b, ast.Name)}
            if "Protocol" in named:
                ports[node.name] = Port(
                    dotted=f"{module}.{node.name}",
                    methods=tuple(
                        child.name
                        for child in node.body
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    ),
                    path=path,
                )
            else:
                classes.append((module, path, node))

    implementations: list[Implementation] = []
    for module, path, node in classes:
        named = {b.id for b in node.bases if isinstance(b, ast.Name)}
        defines = frozenset(
            child.name
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        for port in ports.values():
            if port.short in named and port.short not in defines:
                implementations.append(
                    Implementation(
                        dotted=f"{module}.{node.name}",
                        port=port,
                        path=path,
                        defines=defines,
                    )
                )
    return ports, implementations


PORTS, IMPLEMENTATIONS = _sweep()
RAISING = set(RAISING_MEMBERS)


def test_the_sweep_still_finds_the_ports() -> None:
    """A gate that finds nothing is not a gate.

    The sweep is hand-rolled, so it can break silently: an ``ast`` shape change, a
    rename, a base written as a subscript. This pins a sample of what it has to
    keep finding, so an empty result fails instead of passing.
    """
    missing = EXPECTED_PORTS - set(PORTS)
    assert not missing, (
        "the port sweep stopped finding ports it found before, so the rest of this "
        f"file is checking nothing. Missing: {sorted(missing)}"
    )
    assert len(PORTS) >= 20, (
        f"the sweep found {len(PORTS)} protocols; it found 20+ before. A large drop "
        "means a parsing change, not a refactor."
    )
    assert IMPLEMENTATIONS, "the sweep found no class that explicitly subclasses a port"


def test_every_raising_member_names_a_port_the_sweep_finds() -> None:
    """``RAISING_MEMBERS`` may not rot into naming things that do not exist."""
    unknown = set(RAISING) - {
        f"{port.short}.{member}" for port in PORTS.values() for member in port.methods
    }
    assert not unknown, f"RAISING_MEMBERS names members no port declares: {sorted(unknown)}"


@pytest.mark.parametrize("key", sorted(RAISING))
def test_a_raising_member_actually_raises(key: str) -> None:
    """A member listed as raising must raise, not ``...``.

    ``RAISING_MEMBERS`` is only worth something while it matches the port bodies.
    Restoring ``...`` to ``has_purchase`` is precisely the change this file exists
    to catch, and it is caught here rather than by the sweep above: the concrete
    repository overrides the method now, so nothing inherits it any more and the
    sweep has nothing to complain about.

    "Contains a ``raise``" is not the same claim as "raises", and the difference was
    found by mutation rather than by reading: putting ``return False`` *above* the
    ``raise`` leaves the raise in the body, unreachable, and the method silently
    defaults to exactly what this ADR exists to prevent. So the raise has to be the
    first statement — which is also the shape ``Clock.now`` already had.
    """
    port_short, member = key.rsplit(".", 1)
    port = PORTS[port_short]
    tree = ast.parse(port.path.read_text(), filename=str(port.path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != port_short:
            continue
        for child in node.body:
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if child.name != member:
                continue
            assert not any(_is_ellipsis_body(stmt) for stmt in child.body), (
                f"{key} is listed in RAISING_MEMBERS but its body is `...`, so an "
                f"implementation that forgets to override it returns None.\n  {port.path}"
            )
            first = next(
                (stmt for stmt in child.body if not _is_docstring(stmt)), None
            )
            assert first is not None and isinstance(first, ast.Raise), (
                f"{key} is listed in RAISING_MEMBERS but its body does not begin with "
                f"a raise, so it can return before reaching one.\n  {port.path}"
            )
            return
    raise AssertionError(f"{key} is in RAISING_MEMBERS but {member} is not on {port_short}")


@pytest.mark.parametrize(
    "implementation", IMPLEMENTATIONS, ids=[i.dotted for i in IMPLEMENTATIONS]
)
def test_no_implementation_inherits_a_silent_port_body(
    implementation: Implementation,
) -> None:
    """A port member an implementation does not write is answered by the port.

    The port's body is the answer, and for most members that body is ``...``, which
    returns ``None``. The only acceptable such member is one the port refuses to
    default, so the failure is loud and names the port.
    """
    inherited = set(implementation.port.methods) - set(implementation.defines)
    undeclared = sorted(
        member
        for member in inherited
        if f"{implementation.port.short}.{member}" not in RAISING
    )
    assert not undeclared, (
        f"{implementation.dotted} subclasses {implementation.port.dotted} without "
        f"implementing {', '.join(undeclared)}, so those calls are answered by the "
        "port's body instead of by this class.\n"
        f"  {implementation.path}\n"
        "Implement the method, or — if it is one an implementation has to think "
        "about deliberately — add it to RAISING_MEMBERS with a reason and give the "
        "port a body that raises."
    )


def test_the_raising_member_is_still_reachable() -> None:
    """A raising member must be reached by production code.

    ``has_purchase`` has three call sites. If a refactor removed them, the method
    would still be right and the finding it records would no longer describe
    anything live, so leaving it declared would be a comment about a problem
    nobody can hit.
    """
    callers = {
        str(path)
        for path in _python_files()
        if "ports" not in path.parts
        and "has_purchase" in path.read_text()
    }
    assert len(callers) >= 3, (
        "has_purchase is expected to be called from at least three files — two "
        f"application services and one router. Found {sorted(callers)}. If the call "
        "sites are gone, update RAISING_MEMBERS and the module docstring."
    )
