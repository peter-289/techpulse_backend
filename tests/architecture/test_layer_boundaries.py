"""CI gate for the DDD layer boundaries.

Runs every rule in ``layer_rules`` and compares the result against
``ratchet.json``. The comparison is strict equality in both directions:

- a violation in the code that is not in the ratchet **fails** -- this is the
  regression guard, and it is the reason this file exists;
- a ratchet entry whose violation no longer occurs **fails** -- the entry has
  served its purpose and must be removed, so the ratchet can only shrink.

The second direction is what stops the ratchet from becoming a graveyard. It
is slightly annoying day to day and worth it: a ratchet that only grows is
indistinguishable from having no gate at all.

To see the current state without failing:

    python -m tests.architecture.layer_rules
"""

from __future__ import annotations

import pytest

from tests.architecture import layer_rules
from tests.architecture.layer_rules import (
    RATCHET_PATH,
    RatchetEntry,
    compare,
    collect,
    load_ratchet,
)

RULES = collect()
RATCHET = load_ratchet(RATCHET_PATH)
FLAT_ENTRIES: list[RatchetEntry] = [
    entry for entries in RATCHET.values() for entry in entries.values()
]


def test_every_rule_is_well_formed() -> None:
    """Every rule must have a unique id and a description a reviewer can act on.

    ``ALL_RULES`` is a tuple of factories and ``RULES`` is their evaluated
    result, so this also fails if a factory raises or returns the wrong shape.
    """
    ids = [rule.rule_id for rule in RULES]
    assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"
    assert len(RULES) == len(layer_rules.ALL_RULES), "a rule factory produced no rule"
    for rule in RULES:
        assert rule.rule_id and rule.rule_id[0] == "R", (
            f"rule id {rule.rule_id!r} should look like 'R<n>'"
        )
        assert len(rule.description) > 20, (
            f"{rule.rule_id} needs a description that states the rule, not a name"
        )


def test_ratchet_covers_only_real_rules() -> None:
    """A ratchet entry for a rule that does not exist is always stale."""
    known = {rule.rule_id for rule in RULES}
    unknown = {entry.rule_id for entry in FLAT_ENTRIES} - known
    assert not unknown, f"ratchet.json references unknown rules: {sorted(unknown)}"


def test_ratchet_entries_are_well_formed() -> None:
    """Each entry must name the phase that will remove it.

    This is what stops the ratchet becoming a graveyard of "we'll get to it":
    an entry cannot be added without a commitment to delete it later.
    """
    for entry in FLAT_ENTRIES:
        assert entry.phase and len(entry.phase) > 5, (
            f"ratchet entry {entry.key} has no 'phase' explaining which "
            f"refactor phase removes it"
        )
        assert " -> " in entry.key, f"malformed ratchet key: {entry.key!r}"


def test_ratchet_has_no_duplicates() -> None:
    """The same violation must not be listed twice under one rule.

    Note this is a duplicate *(rule, violation)* pair, not a duplicate
    violation. One import can legitimately break two rules at once -- an
    application service importing an ORM model is both "R4: application
    imports infrastructure" and "R5: a service imports an ORM model" -- and
    each needs its own entry so each ratchet can drain independently.
    """
    pairs = [(entry.rule_id, entry.key) for entry in FLAT_ENTRIES]
    duplicates = {pair for pair in pairs if pairs.count(pair) > 1}
    assert not duplicates, f"duplicate ratchet entries: {sorted(duplicates)}"


def test_ratchet_is_sorted() -> None:
    """Keep the file diffable: entries ordered by (rule, source, import)."""
    on_disk = [
        (entry.rule_id, entry.source, entry.target) for entry in FLAT_ENTRIES
    ]
    assert on_disk == sorted(on_disk), (
        "ratchet.json entries are not sorted by (rule, source, import), which "
        "makes diffs noisy. Re-sort the file."
    )


def test_ratchet_is_not_used_for_rules_that_pass() -> None:
    """A rule that passes must not be ratcheted 'just in case'."""
    for rule in RULES:
        if rule.rule_id in RATCHET and not rule.keys:
            offenders = sorted(RATCHET[rule.rule_id])
            raise AssertionError(
                f"{rule.rule_id} has no violations but is present in "
                f"{RATCHET_PATH.name}; remove: {offenders}"
            )


@pytest.mark.parametrize("rule", RULES, ids=[r.rule_id for r in RULES])
def test_layer_boundary_is_respected(rule: layer_rules.Rule) -> None:
    """No new boundary violation, and no stale ratchet entry.

    Strict equality in both directions is what makes the ratchet trustworthy: a
    violation that is neither new nor stale is the only kind allowed to remain.
    """
    new, stale, is_hard = compare(rule, RATCHET)

    if is_hard:
        assert not new, (
            f"{rule.rule_id}: {rule.description}\n"
            f"This is a hard rule, so there must be zero violations, and it may "
            f"not be added to {RATCHET_PATH.name}.\n"
            f"New violations:\n  " + "\n  ".join(sorted(new))
        )
        return

    assert not new, (
        f"{rule.rule_id}: {rule.description}\n"
        f"A new violation was introduced and is not recorded in "
        f"{RATCHET_PATH.name}. Fix it rather than allowlisting it.\n"
        f"  " + "\n  ".join(sorted(new))
    )
    assert not stale, (
        f"{rule.rule_id}: {rule.description}\n"
        f"These violations are listed in {RATCHET_PATH.name} but no longer "
        f"occur. Delete the entries.\n"
        f"  " + "\n  ".join(sorted(stale))
    )
