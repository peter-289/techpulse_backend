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
from tests.architecture.layer_rules import RATCHET_PATH, compare, collect, load_ratchet

RULES = collect()
RATCHET = load_ratchet(RATCHET_PATH)


def _rule(rule_id: str) -> layer_rules.Rule:
    for rule in RULES:
        if rule.rule_id == rule_id:
            return rule
    raise AssertionError(f"no rule named {rule_id}")


def test_every_rule_is_well_formed() -> None:
    """Every rule must have a unique id and a description a reviewer can act on.

    ``ALL_RULES`` is a tuple of factories and ``RULES`` is their evaluated
    result, so this also fails if a factory raises or returns the wrong shape.
    """
    ids = [rule.rule_id for rule in RULES]
    assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"
    assert len(RULES) == len(layer_rules.ALL_RULES), (
        "a rule factory did not produce a rule"
    )
    for rule in RULES:
        assert rule.rule_id and rule.rule_id[0] == "R", (
            f"rule id {rule.rule_id!r} should look like 'R<n>'"
        )
        assert len(rule.description) > 20, (
            f"{rule.rule_id} needs a description that states the rule, not just "
            f"a name"
        )
        for violation in rule.violations:
            assert violation.key in rule.keys


def test_ratchet_covers_only_real_rules() -> None:
    """A ratchet entry for a rule that does not exist is always stale."""
    known = {rule.rule_id for rule in RULES}
    unknown = set(RATCHET) - known
    assert not unknown, f"ratchet.json references unknown rules: {sorted(unknown)}"


@pytest.mark.parametrize("rule", RULES, ids=[r.rule_id for r in RULES])
def test_layer_boundary_is_respected(rule: layer_rules.Rule) -> None:
    """No new boundary violation, and no stale ratchet entry."""
    new, stale, is_hard = compare(rule, RATCHET)
    phase = ""
    if not is_hard:
        phase = RATCHET.get(rule.rule_id, {}).get("_phase", "")

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
    assert phase, (
        f"{rule.rule_id} has ratcheted violations but no '_phase' note in "
        f"{RATCHET_PATH.name} explaining which refactor phase removes them."
    )


def test_ratchet_is_only_used_for_soft_rules() -> None:
    """A rule that passes must not be ratcheted 'just in case'."""
    for rule in RULES:
        if rule.rule_id in RATCHET and not rule.keys:
            raise AssertionError(
                f"{rule.rule_id} has no violations but is present in "
                f"{RATCHET_PATH.name}; remove the entry."
            )


def test_ratchet_is_ordered_and_deduplicated() -> None:
    """Keep the file diffable: sorted, no duplicates."""
    for rule_id, entry in RATCHET.items():
        violations = entry.get("violations", [])
        assert violations == sorted(violations), (
            f"{rule_id} violations are not sorted, which makes diffs noisy"
        )
        assert len(violations) == len(set(violations)), (
            f"{rule_id} contains duplicate entries"
        )
