"""Every shield rule must be load-bearing, provably.

A measurement found **22 of 40** builtin rules individually deletable with the
corpus still catching exactly the same set of attacks -- and every check still
green. The rules were real; nothing proved they mattered. A refactor could have
dropped half the detector and no gate would have noticed, while
``benchmarks/security`` kept publishing an F1 for the whole set.

This is mutation testing scoped to the detector: delete one rule, require the
corpus to notice. It is the same idea as the repo's existing negative controls,
applied to the thing the security story rests on.

Note the limit, because it is the one that bit here before: this proves each
rule you *wrote* is exercised. It says nothing about an attack class nobody
wrote a rule for. Held-out true-positive rate in ``benchmarks/security`` is the
measurement for that; this is the regression floor underneath it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "benchmarks" / "security"))

corpus = pytest.importorskip("corpus", reason="security benchmark corpus absent")
builtin_rules = pytest.importorskip("maverick_shield.builtin_rules")

#: Rules whose coverage is deliberately shared with another rule, with the
#: covering rule named. Defence in depth is legitimate -- two patterns matching
#: one phrasing is not a defect -- but it must be recorded, or "this rule is
#: redundant" and "nobody wrote a case for it" become indistinguishable.
DELIBERATE_OVERLAP: dict[str, str] = {}

#: Benign cases the regex layer flags today. Pinned as a ceiling: adding rules
#: must not quietly raise the false-positive rate, which is the usual cost of
#: chasing coverage.
MAX_FALSE_POSITIVES = 2


#: The rule-coverage cases live in their own file, not in
#: shield_jailbreak_corpus.txt. That corpus has a second consumer --
#: test_jailbreak_corpus_minimum_detection_rate asserts the looks_like_jailbreak
#: heuristic flags >=70% of EVERY line in it -- so cases aimed at the regex
#: layer dragged an unrelated detector's measured baseline down. One corpus per
#: question.
COVERAGE_CORPUS = (
    Path(__file__).resolve().parent / "data" / "shield_rule_coverage_corpus.txt"
)


def _rules():
    return list(builtin_rules.RULES)


def _coverage_cases() -> list:
    """Attack cases written specifically to pin one rule each."""
    if not COVERAGE_CORPUS.is_file():  # pragma: no cover
        return []
    out = []
    for i, raw in enumerate(COVERAGE_CORPUS.read_text(encoding="utf-8").splitlines()):
        s = raw.strip()
        if s and not s.startswith("#"):
            out.append(corpus.Case(id=f"cov-{i}", label="attack",
                                   split="coverage", category="rule_coverage",
                                   text=s))
    return out


def _attacks():
    return [c for c in corpus.load_all() if c.label == "attack"] + _coverage_cases()


def _benign():
    return [c for c in corpus.load_all() if c.label == "benign"]


def _caught(rules, text: str) -> bool:
    for r in rules:
        try:
            if r.pattern.search(text):
                return True
        except Exception:  # pragma: no cover -- a broken pattern is its own bug
            continue
    return False


def _caught_ids(rules, cases) -> set[str]:
    return {c.id for c in cases if _caught(rules, c.text)}


def test_the_corpus_and_rule_set_are_both_substantial() -> None:
    """Anti-vacuity: the whole file passes trivially over empty inputs."""
    assert len(_rules()) >= 30, len(_rules())
    assert len(_attacks()) >= 80, len(_attacks())


@pytest.mark.parametrize(
    "index", range(len(_rules())),
    ids=[getattr(r, "name", f"rule{i}") for i, r in enumerate(_rules())])
def test_each_rule_is_load_bearing(index: int) -> None:
    """Deleting this rule must make the corpus miss something.

    If it does not, the rule is either dead weight or untested -- and the
    difference matters, so record a genuine overlap in DELIBERATE_OVERLAP
    rather than deleting the assertion.
    """
    rules = _rules()
    name = getattr(rules[index], "name", f"rule{index}")
    attacks = _attacks()
    full = _caught_ids(rules, attacks)
    without = _caught_ids(rules[:index] + rules[index + 1:], attacks)
    lost = full - without

    if name in DELIBERATE_OVERLAP:
        assert not lost, (
            f"{name} is recorded as overlapping with "
            f"{DELIBERATE_OVERLAP[name]}, but it is now uniquely catching "
            f"{sorted(lost)}. Remove it from DELIBERATE_OVERLAP.")
        return

    assert lost, (
        f"deleting rule {name!r} changes nothing: no corpus case depends on "
        "it. Add an attack line to "
        "packages/maverick-core/tests/data/shield_jailbreak_corpus.txt that "
        "only this rule catches, or record the covering rule in "
        "DELIBERATE_OVERLAP. A rule nothing exercises can be dropped in a "
        "refactor while the published F1 still describes the full set.")


def test_false_positives_do_not_grow() -> None:
    """Coverage must not be bought with benign-traffic noise.

    The cheap way to make the test above pass is a broader pattern; this is the
    counterweight.
    """
    flagged = sorted(_caught_ids(_rules(), _benign()))
    assert len(flagged) <= MAX_FALSE_POSITIVES, (
        f"regex layer flags {len(flagged)} benign case(s) {flagged}; the "
        f"recorded ceiling is {MAX_FALSE_POSITIVES}. A new rule widened the "
        "net. Tighten it, or raise the ceiling deliberately and say why.")


def test_every_attack_case_is_reachable_by_some_rule_or_recorded() -> None:
    """The corpus contains attacks the regex layer does NOT catch. Say so.

    Those are the honest part of the benchmark -- they are what the F1 in
    benchmarks/security/RESULTS.md is measuring against. This test does not
    demand they all be caught; it pins that we know the number, so a drop shows
    up as a change rather than as an unremarkable green run.
    """
    attacks = _attacks()
    caught = _caught_ids(_rules(), attacks)
    missed = len(attacks) - len(caught)
    # Recorded, not aspirational: the builtin layer is a ~20-pattern subset and
    # is measured at F1 0.821-0.900, so a substantial miss count is expected.
    assert missed <= len(attacks) * 0.55, (
        f"the regex layer now misses {missed}/{len(attacks)} corpus attacks, "
        "which is worse than the measured baseline. Something regressed.")
    assert caught, "the regex layer catches nothing at all"
