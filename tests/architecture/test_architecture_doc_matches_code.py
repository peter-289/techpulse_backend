"""ARCHITECTURE.md has to describe the code, or it is worse than nothing.

The previous version of ``app/modules/software_management/ARCHITECTURE.md`` had
drifted from the code in roughly forty places across nineteen sections: a directory
tree that no longer existed, port names that collided with the concrete classes they
described, an event that had never existed, a port method described as part of a
contract it has never had, a quality gate requiring ``mypy --strict`` in a project
where mypy is not installed, and a section describing as future work a search
implementation that had already shipped. Phase 9a rewrote it against the code.

Rewriting it once buys nothing on its own, because the drift was not a one-off. It is
what happens when a document describing a moving system has nothing to say about
which of its sentences are still true. So the document makes claims that are
mechanically checkable, and this file checks them:

1. the tree in section 2 is compared with the filesystem, in both directions;
2. every ``app/``, ``tests/`` or ``docs/`` path the document names must exist;
3. every name it marks *(not implemented)* must still be absent from ``app/``,
   so a target cannot quietly become a claim;
4. the counts it quotes — routes, events, exceptions, the size of the ``Clock``
   port — are recomputed rather than trusted;
5. the behavioural claims that would be most damaging if they stopped being true
   (the empty ratchet, ``matched_fields`` staying out of the HTTP response, the
   test gaps it records) are asserted against the code.

What is deliberately *not* checked: prose, opinions, and the reasoning. A document
that stops arguing is a worse document, and this gate should never be the reason to
delete an argument. It checks facts.

The filesystem is walked rather than imported, for the same reason
``test_ports_have_no_silent_defaults.py`` does it: ``domain/`` and
``infrastructure/`` have no ``__init__.py``, so a package walk descends past both
and would report half this context as absent.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTEXT = REPO_ROOT / "app/modules/software_management"
DOC = CONTEXT / "ARCHITECTURE.md"
TEXT = DOC.read_text(encoding="utf-8")

#: Backticked repository paths the document claims exist. Patterns are anchored on a
#: known prefix so that a deliberately-cited dead path (``software/software.py`` in
#: section 16) is not mistaken for a broken reference.
REFERENCED_PATH = re.compile(
    r"`((?:app|tests|docs)/[A-Za-z0-9_./-]+\.(?:py|md|json|yml))`"
)

#: ``(router file, routes, prefix)`` as quoted in the section 2 tree.
ROUTER_CLAIM = re.compile(
    r"(?P<router>\w+_router\.py)\s+(?P<routes>\d+) routes, prefix (?P<prefix>\S+)"
)

EVENT_CLAIM = re.compile(r"defines (\d+) (?:event )?classes")
EXCEPTION_CLAIM = re.compile(r"`domain/exceptions\.py` holds (\d+) classes")
CLOCK_CLAIM = re.compile(r"`Clock` is an? (\w+)-method protocol")

NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
}

#: Names the document marks as not implemented. Each must still be undefined
#: somewhere in ``app/``; when one appears, section 8 is describing the present as
#: the future and has to be rewritten.
NOT_IMPLEMENTED = ("CategoryMapper", "ArtifactMapper", "S3Storage", "AzureBlobStorage",
                   "ClamAVScanner", "VirusTotalScanner", "HeuristicScanner")

#: Test gaps section 18 records. A test appearing for one of these means the
#: document's "partly" has become "mostly" and the row is no longer true.
RECORDED_TEST_GAPS = ("verify_integrity", "DuplicateCategoryError", "CategoryInUseError")


# --------------------------------------------------------------------------- tree


def _documented_tree() -> dict[str, str]:
    """Parse the fenced tree under "## 2. Directory structure" into {path: note}."""
    block = re.search(
        r"## 2\. Directory structure\s*```\n(.*?)```", TEXT, re.DOTALL
    )
    assert block, "section 2 has no fenced tree to check; this test needs its shape"

    entries: dict[str, str] = {}
    stack: dict[int, str] = {0: ""}
    for line in block.group(1).splitlines():
        marker = re.search(r"[├└]── ", line)
        if marker is None:
            continue
        # Each level is four columns wide, whether it draws a guide (``│   ``) or
        # blanks (``    ``) — a tree that mixes the two still nests correctly.
        depth = marker.start() // 4 + 1
        name, _, note = line[marker.end() :].partition("  ")
        name = name.strip()
        is_dir = name.endswith("/")
        name = name.rstrip("/")
        parent = stack.get(depth - 1, "")
        path = f"{parent}/{name}" if parent else name
        stack[depth] = path
        # Directories are implied by the files under them; comparing them against
        # the filesystem would need a directory walk for no extra signal.
        if not is_dir:
            entries[f"{CONTEXT.name}/{path}"] = note.strip()
    return entries


def _actual_tree() -> set[str]:
    found = set()
    for path in CONTEXT.rglob("*"):
        if "__pycache__" in path.parts or not path.is_file():
            continue
        if path.suffix in {".py", ".md"}:
            found.add(f"{CONTEXT.name}/{path.relative_to(CONTEXT)}")
    return found


def _is_python(path: str) -> bool:
    return path.endswith(".py")


# ------------------------------------------------------------------- code reading


def _module_names(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [n.name for n in tree.body if isinstance(n, ast.ClassDef)]


def _app_defines(name: str) -> bool:
    return any(
        name in _module_names(path)
        for path in (REPO_ROOT / "app").rglob("*.py")
        if "__pycache__" not in path.parts
    )


def _protocol_methods(path: Path, class_name: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return [
                child.name
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
    raise AssertionError(f"{class_name} is not defined in {path}")


def _routes(path: Path) -> int:
    """Count the routes a router declares.

    Counted from the source rather than from ``app.routes`` so that importing the
    application is not a precondition of checking a document about it.
    """
    source = path.read_text(encoding="utf-8")
    return len(re.findall(r"^@router\.\w+\(", source, re.MULTILINE))


def _prefix(path: Path) -> str:
    match = re.search(r'APIRouter\(prefix="([^"]+)"', path.read_text(encoding="utf-8"))
    assert match, f"no APIRouter prefix in {path}"
    return match.group(1)


def _tests_say(needle: str) -> list[str]:
    """Test modules mentioning ``needle``.

    This file is excluded: it names the recorded gaps as strings, which is the point
    of recording them, not coverage of them.
    """
    this_file = Path(__file__).resolve()
    return sorted(
        str(path.relative_to(REPO_ROOT))
        for path in (REPO_ROOT / "tests").rglob("*.py")
        if "__pycache__" not in path.parts
        and path.resolve() != this_file
        and needle in path.read_text(encoding="utf-8")
    )


# ------------------------------------------------------------------------- tests


def test_the_tree_has_no_file_that_is_not_there() -> None:
    """A tree entry that does not exist is the document describing a plan."""
    missing = sorted(set(_documented_tree()) - _actual_tree())
    assert not missing, (
        "section 2 documents paths that do not exist in the context:\n"
        + "\n".join(f"  {path}" for path in missing)
        + "\nEither the file moved or the tree is describing a layout that was "
        "reached in an earlier phase."
    )


def test_the_tree_has_no_file_it_forgot() -> None:
    """A new file that the document does not mention is how it starts rotting again."""
    undocumented = sorted(_actual_tree() - set(_documented_tree()))
    assert not undocumented, (
        "these files exist in the context but section 2 does not list them:\n"
        + "\n".join(f"  {path}" for path in undocumented)
        + "\nAdd each to the tree with what it is, or delete it if it is dead."
    )


def test_every_path_the_document_names_exists() -> None:
    """Every repository path in backticks has to resolve.

    Paths without a repository prefix are exempt: section 16 quotes three dead paths
    from an older layout on purpose, and a gate that cannot tell a quoted corpse from
    a broken reference trains people to ignore it.
    """
    dangling = []
    for reference in sorted(set(REFERENCED_PATH.findall(TEXT))):
        if "*" in reference:
            if not list(REPO_ROOT.glob(reference)):
                dangling.append(reference)
        elif not (REPO_ROOT / reference).exists():
            dangling.append(reference)
    assert not dangling, (
        "the document names paths that do not exist:\n"
        + "\n".join(f"  {path}" for path in dangling)
    )


def test_the_tree_lists_the_context_root() -> None:
    """The tree is checked by parsing it, so its shape is a precondition."""
    tree = _documented_tree()
    assert "software_management/ARCHITECTURE.md" in tree, (
        "the parsed tree has no root entry; the branch-marker shape changed and this "
        "whole file is checking nothing"
    )
    assert any(_is_python(path) for path in tree), "the parsed tree lists no modules"


@pytest.mark.parametrize("name", NOT_IMPLEMENTED)
def test_a_name_marked_not_implemented_is_still_absent(name: str) -> None:
    """A section labelled *(not implemented)* must not drift into describing code.

    This is the direction that needs a gate. The reverse — a class appearing where
    the document said it would — is caught by the tree check and by the counts
    below; without this one, a future adapter could be added and the document would
    keep calling it future work.
    """
    assert f"`{name}`" in TEXT, (
        f"{name} is guarded here but section 8 no longer names it as not implemented; "
        "either it was implemented or the guard should be removed"
    )
    assert not _app_defines(name), (
        f"{name} is marked *(not implemented)* in section 8 but is now defined in app/. "
        "The document is describing the present as the future; rewrite the section."
    )


@pytest.mark.parametrize(
    ("router", "routes", "prefix"), sorted(ROUTER_CLAIM.findall(TEXT)),
    ids=[m.group("router") for m in ROUTER_CLAIM.finditer(TEXT)],
)
def test_the_route_counts_the_document_quotes(
    router: str, routes: str, prefix: str
) -> None:
    """Section 2 quotes a route count and a prefix per router; both are recomputed."""
    path = CONTEXT / "api/routers" / router
    assert _routes(path) == int(routes), (
        f"section 2 says {router} declares {routes} routes; it declares {_routes(path)}. "
        "The tree comment is a claim about the code, so update it."
    )
    assert _prefix(path) == prefix, (
        f"section 2 says {router} is mounted at {prefix}; it is mounted at {_prefix(path)}"
    )


def test_the_event_count_the_document_quotes() -> None:
    claimed = EVENT_CLAIM.search(TEXT)
    assert claimed, (
        "no 'defines N event classes' claim found; the sentence section 11.2 needs was "
        "reworded and the count is no longer checked"
    )
    actual = len(_module_names(CONTEXT / "domain/events/events.py"))
    assert actual == int(claimed.group(1)), (
        f"section 11.2 says {claimed.group(1)} event classes; there are {actual}"
    )


def test_the_exception_count_the_document_quotes() -> None:
    claimed = EXCEPTION_CLAIM.search(TEXT)
    assert claimed, (
        "no 'domain/exceptions.py holds N classes' claim found; section 12.1 was "
        "reworded and the count is no longer checked"
    )
    actual = len(_module_names(CONTEXT / "domain/exceptions.py"))
    assert actual == int(claimed.group(1)), (
        f"section 12.1 says {claimed.group(1)} exception classes; there are {actual}"
    )


def test_the_size_of_the_clock_port_the_document_quotes() -> None:
    """Section 3.3 justifies the port's placement by what it contains."""
    claimed = CLOCK_CLAIM.search(TEXT)
    assert claimed, (
        "no 'Clock is a N-method protocol' claim found; section 3.3 was reworded and "
        "the size of the port is no longer checked"
    )
    word = claimed.group(1)
    assert word in NUMBER_WORDS, f"unparseable number word in section 3.3: {word!r}"
    methods = _protocol_methods(CONTEXT / "application/ports/clock.py", "Clock")
    assert len(methods) == NUMBER_WORDS[word], (
        f"section 3.3 calls Clock a {word}-method protocol; it declares "
        f"{', '.join(methods)}"
    )


def test_the_ratchet_is_still_empty() -> None:
    """Section 3.1 claims no rule is allowlisted. An entry means one is."""
    ratchet = (REPO_ROOT / "tests/architecture/ratchet.json").read_text(encoding="utf-8")
    violations = re.search(r'"violations"\s*:\s*\[(.*?)\]', ratchet, re.DOTALL)
    assert violations, "ratchet.json has no 'violations' list to check"
    assert not violations.group(1).strip(), (
        "ratchet.json has allowlisted violations, so the eight rules are not all hard "
        "anymore and section 3.1 is wrong. Delete the entries when their phase lands."
    )


def test_all_eight_layer_rules_are_named() -> None:
    """Section 3.1 and section 18 both claim eight rules; check the code agrees."""
    rules = (REPO_ROOT / "tests/architecture/layer_rules.py").read_text(encoding="utf-8")
    declared = sorted(set(re.findall(r'"(R[1-9])"', rules)), key=lambda r: int(r[1:]))
    assert declared == [f"R{n}" for n in range(1, 9)], (
        f"layer_rules.py declares {declared}, not R1-R8; update section 3.1 and 18"
    )
    absent = [rule for rule in declared if rule not in TEXT]
    assert not absent, f"the document never mentions {', '.join(absent)}"


def test_matched_fields_is_still_out_of_the_search_response() -> None:
    """Section 15.5 justifies the Phase 9a search refactor on this claim.

    The refactor was allowed to change ``ScoredSoftware.matched_fields`` because the
    field is internal. That reasoning holds only while the route drops it, and the
    route returning it would make the exact-match case-sensitivity defect
    client-visible.
    """
    route = (CONTEXT / "api/routers/software_router.py").read_text(encoding="utf-8")
    body = route.split('@router.get("/search")', 1)[1]
    body = body.split("\n@router.", 1)[0]
    assert "matched_fields" not in body, (
        "the search route now mentions matched_fields, so section 15.5's claim that it "
        "is not part of any HTTP response is no longer true"
    )
    for key in ("items", "scores", "total", "limit", "offset"):
        assert f'"{key}"' in body, (
            f"the search route no longer returns {key!r}; section 15.5 lists the keys"
        )


@pytest.mark.parametrize("needle", RECORDED_TEST_GAPS)
def test_the_test_gaps_the_document_records_are_still_gaps(needle: str) -> None:
    """Section 18 calls test coverage "partly" and names what is missing.

    The direction that matters is a test appearing. Someone closing one of these gaps
    is doing the right thing, and the only consequence should be a line to edit in
    section 18 — not a document that understates what is covered.
    """
    found = _tests_say(needle)
    assert not found, (
        f"{needle} now has test coverage ({', '.join(found)}), so the Phase 9a gap it "
        "was recorded under no longer holds. Update docs/REVIEW.md and section 18."
    )