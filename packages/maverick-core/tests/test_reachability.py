"""The reachability ledger, and the docs claim it protects.

The reachability ledger answers "does production reach this module?" from the
import graph, so docs and reviews do not have to infer it from comments.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from maverick import reachability

CLASSES = {"PRODUCTION", "CI_ONLY", "CLI_ONLY", "TEST_ONLY", "UNREACHED"}


def test_module_inventory_ignores_generated_package_copies(
    tmp_path,
    monkeypatch,
) -> None:
    """Build trees and unpacked sdists are artifacts, not source modules."""
    dist = tmp_path / "packages" / "maverick-core"
    source = dist / "maverick"
    generated = dist / "build" / "lib" / "maverick"
    unpacked = dist / "maverick_agent-0.1.7" / "maverick"
    for root in (source, generated, unpacked):
        root.mkdir(parents=True)
        (root / "__init__.py").write_text("", encoding="utf-8")
        (root / "agent.py").write_text("", encoding="utf-8")

    monkeypatch.setattr(reachability, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(reachability, "PACKAGES", ("maverick-core",))

    assert set(reachability.all_modules()) == {"maverick", "maverick.agent"}


@pytest.fixture(scope="module")
def table() -> dict[str, str]:
    return reachability.classify()


def test_it_classifies_a_substantial_tree(table) -> None:
    """Anti-vacuity: every assertion below is empty if the walk finds nothing."""
    assert len(table) > 500, len(table)
    assert set(table.values()) <= CLASSES


def test_the_kernel_is_production_reachable(table) -> None:
    """Control: if these are not PRODUCTION the graph walk is broken."""
    for mod in ("maverick.agent", "maverick.orchestrator", "maverick.audit.writer",
                "maverick.capability", "maverick.budget"):
        assert table.get(mod) == "PRODUCTION", (mod, table.get(mod))


def test_lazy_runtime_imports_are_declared_reachable(table) -> None:
    """A lazy import is still a production edge, without eager side effects."""
    for mod in (
        "maverick.audit.erase",
        "maverick.automation_import.manual",
        "maverick.automation_import.notion",
        "maverick.automation_import.uipath",
        "maverick.automation_import.zapier",
    ):
        assert table.get(mod) == "PRODUCTION", (mod, table.get(mod))


def test_the_two_modules_that_misled_a_review_classify_correctly(table) -> None:
    """The concrete case this ledger exists to prevent.

    One is genuinely unreachable from production and one backs a shipping
    command; the ledger must classify both.
    """
    # erasure_verify backs `maverick erase-verify`.
    assert table.get("maverick.erasure_verify") in {"PRODUCTION", "CLI_ONLY"}, (
        table.get("maverick.erasure_verify"))
    # sigstore_signing is reachable or not, but the ledger must have an opinion
    # rather than leaving a reader to infer one from a header comment.
    assert table.get("maverick.sigstore_signing") in CLASSES


def test_the_lock_is_committed_and_current(table) -> None:
    lock = reachability.load_lock()
    assert lock, "no reachability.lock.json committed; run --regen"
    assert reachability.drift(table, lock) == [], (
        "the committed ledger no longer matches the import graph; run "
        "`python -m maverick.reachability --regen` and review the diff")


def test_drift_detects_a_module_losing_its_caller() -> None:
    """Negative control: the gate must fire when something goes dark."""
    lock = {"maverick.agent": "PRODUCTION"}
    now = {"maverick.agent": "UNREACHED"}
    problems = reachability.drift(now, lock)
    assert problems and "lost a caller" in problems[0]


def test_drift_detects_a_new_unreached_module() -> None:
    problems = reachability.drift({"maverick.brand_new": "UNREACHED"}, {})
    assert problems and "nothing reaches" in problems[0]


def test_drift_allows_a_promotion() -> None:
    """Wiring something up must not fail the build."""
    assert reachability.drift(
        {"maverick.x": "PRODUCTION"}, {"maverick.x": "TEST_ONLY"}) == []


def test_drift_allows_deletion() -> None:
    assert reachability.drift({}, {"maverick.gone": "PRODUCTION"}) == []


def test_the_cli_refuses_an_empty_classification(monkeypatch, capsys) -> None:
    monkeypatch.setattr(reachability, "classify", dict)
    assert reachability.main(["--ci"]) == 2
    assert "classified 0 modules" in capsys.readouterr().err


def test_list_rejects_an_unknown_class(capsys) -> None:
    assert reachability.main(["--list", "NONSENSE"]) == 2
    assert "unknown class" in capsys.readouterr().err


# -- the claim this ledger protects ----------------------------------------

FEATURES = Path(reachability.REPO_ROOT) / "docs" / "FEATURES.md"

#: Modules named in FEATURES.md that the ledger says nothing reaches. Recorded
#: rather than asserted-away: FEATURES.md opens with "what Lightwork does
#: today", so each entry here is a live overclaim awaiting a wire-or-delete
#: decision. Shrink it; do not grow it.
KNOWN_FEATURE_OVERCLAIMS: set[str] = set()


#: Phrases that make naming an unreached module honest rather than a claim.
#: The rule is not "never mention it" -- a built-but-unwired module is worth
#: documenting. The rule is that the reader must not have to guess.
DISCLAIMERS = ("not yet wired", "unreached", "built but", "built, not yet",
               "no production code path", "nothing in production imports")


def _named_in_features_without_disclaimer(doc: Path | None = None) -> set[str]:
    """Modules named in the doc with no nearby honesty marker.

    Scoped to the bullet around the mention rather than the whole document, so
    one disclaimer somewhere cannot launder every other claim. Takes a path so
    the rule itself is testable against a fixture.
    """
    doc = doc or FEATURES
    if not doc.is_file():  # pragma: no cover
        return set()
    text = doc.read_text(encoding="utf-8")
    out: set[str] = set()
    for m in re.finditer(r"`?([a-z][a-z0-9_]{3,})\.py`?", text):
        start = text.rfind("\n- ", 0, m.start())
        if start == -1:
            start = max(0, m.start() - 400)
        end = text.find("\n- ", m.end())
        if end == -1:
            end = min(len(text), m.end() + 400)
        window = text[start:end].lower()
        if not any(d in window for d in DISCLAIMERS):
            out.add(m.group(1))
    return out


def test_features_does_not_advertise_unreached_modules(table) -> None:
    """FEATURES.md says "what Lightwork does today". Hold it to that."""
    unreached = {n.rsplit(".", 1)[-1] for n, c in table.items() if c == "UNREACHED"}
    named = _named_in_features_without_disclaimer()
    overclaimed = sorted((named & unreached) - KNOWN_FEATURE_OVERCLAIMS)
    assert not overclaimed, (
        f"FEATURES.md names {overclaimed}, which nothing in the import graph "
        "reaches. Either wire the module up, delete it, or move the claim out "
        "of a document whose first line is 'what Lightwork does today'.")


def test_the_overclaim_register_has_no_stale_entries(table) -> None:
    """A recorded overclaim that got fixed must be removed from the register."""
    unreached = {n.rsplit(".", 1)[-1] for n, c in table.items() if c == "UNREACHED"}
    stale = sorted(KNOWN_FEATURE_OVERCLAIMS - unreached)
    assert not stale, (
        f"{stale} are recorded as FEATURES.md overclaims but are now reachable; "
        "remove them from KNOWN_FEATURE_OVERCLAIMS.")


def test_the_disclaimer_rule_can_actually_fail(tmp_path) -> None:
    """Negative control. A rule that accepts everything protects nothing.

    Also pins the scoping: a disclaimer on one bullet must not excuse an
    undisclaimed claim in another, which is the obvious way this check would
    quietly stop working.
    """
    doc = tmp_path / "FEATURES.md"
    doc.write_text(
        "- **Honest** (`disclaimed_mod.py`) — built but unreached: nothing in "
        "production imports it.\n"
        "- **Overclaim** (`sneaky_mod.py`) — does this today, no caveat.\n",
        encoding="utf-8")
    named = _named_in_features_without_disclaimer(doc)
    assert "sneaky_mod" in named, named
    assert "disclaimed_mod" not in named, named


def test_lock_file_shape() -> None:
    data = json.loads(reachability.LOCK.read_text(encoding="utf-8"))
    assert set(data["modules"].values()) <= CLASSES
    assert data["counts"]["PRODUCTION"] > 100
