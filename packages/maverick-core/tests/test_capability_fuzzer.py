"""Capability-leak fuzzer: the REAL maverick.capability boundary must survive
the full probe battery with zero leaks; a deliberately-broken substring
matcher must not. Probe generation is seeded-PRNG deterministic.
"""
from __future__ import annotations

import json

from maverick.capability import Capability
from maverick.capability_fuzzer import (
    FuzzReport,
    fuzz,
    fuzz_roundtrip,
    generate_probes,
    main,
)

GRANTED = {"fs.read", "fs.write", "shell.exec", "web_search"}


def _real_cap() -> Capability:
    # No max_risk: the risk ceiling consults tool_risk/config, which is not
    # what the *name-matching* boundary under test here is about.
    return Capability(principal="fuzz-target", allow_tools=frozenset(GRANTED))


# --- the real implementation -------------------------------------------------

def test_real_capability_has_zero_leaks():
    report = fuzz(_real_cap(), GRANTED, seed=0, rounds=600)
    assert report.probes > 400          # the battery really ran
    assert report.leaks == ()
    assert report.ok


def test_real_capability_with_deny_set_has_zero_leaks():
    cap = Capability(
        principal="fuzz-target",
        allow_tools=frozenset(GRANTED),
        deny_tools=frozenset({"shell.exec.sudo"}),
    )
    assert fuzz(cap, GRANTED, seed=3, rounds=500).ok


def test_granted_names_still_permitted():
    # The fuzzer must not "pass" because the grant denies everything.
    cap = _real_cap()
    for name in GRANTED:
        assert cap.permits(name)


def test_specific_adversarial_probes_denied_by_real_capability():
    cap = _real_cap()
    for probe in (
        "FS.WRITE",            # case variant
        "ѕhell.exec",          # Cyrillic 's' homoglyph
        "shell.exec.x",        # suffix scope creep
        "xshell.exec",         # prefix
        "shell/exec",          # separator swap
        "shell:exec",
        "shell.exec\x00",      # embedded NUL
        "shell.*",             # glob
        "*",
        "",                    # empty
        " fs.read",            # whitespace
        "fs.read" * 100,       # very long
    ):
        assert cap.permits(probe) is False, f"leak: {probe!r}"


# --- determinism ---------------------------------------------------------------

def test_probe_generation_is_deterministic():
    a = generate_probes(GRANTED, seed=1, rounds=300)
    b = generate_probes(GRANTED, seed=1, rounds=300)
    assert a == b
    assert len(a) == 300


def test_seed_changes_the_mutation_tail():
    granted = {"fs.read", "shell.exec"}
    a = generate_probes(granted, seed=1, rounds=300)
    b = generate_probes(granted, seed=2, rounds=300)
    assert a != b                        # PRNG tail differs by seed
    # ... but the structured battery (everything before the tail) is shared.
    assert a[:50] == b[:50]


def test_fuzz_is_repeatable():
    r1 = fuzz(_real_cap(), GRANTED, seed=7, rounds=200)
    r2 = fuzz(_real_cap(), GRANTED, seed=7, rounds=200)
    assert r1 == r2


def test_probe_battery_covers_documented_classes():
    whys = {why for _, why in generate_probes(GRANTED, seed=0, rounds=600)}
    assert {"case_variant", "homoglyph", "prefix", "suffix", "separator_swap",
            "whitespace", "empty", "null_byte", "long_name", "glob",
            "random_mutation"} <= whys


# --- a broken matcher must be caught ------------------------------------------

class BrokenSubstringCapability:
    """The classic bug: 'is the probe related to a grant?' via substring."""

    def __init__(self, granted):
        self.granted = set(granted)

    def permits(self, name: str) -> bool:
        return any(g in name or name in g for g in self.granted)


def test_broken_substring_matcher_leaks():
    report = fuzz(BrokenSubstringCapability(GRANTED), GRANTED, seed=0, rounds=600)
    assert not report.ok
    leaked_probes = {p for p, _ in report.leaks}
    assert "shell.exec.x" in leaked_probes       # superstring leak
    assert "" in leaked_probes                   # empty-string-in-grant leak
    leaked_whys = {why.split(":", 1)[0] for _, why in report.leaks}
    assert "suffix" in leaked_whys and "prefix" in leaked_whys


class RaisingCapability:
    def permits(self, name: str) -> bool:
        raise TypeError("hostile probe")


def test_permits_raising_counts_as_deny():
    report = fuzz(RaisingCapability(), {"fs.read"}, seed=0, rounds=100)
    assert report.ok and isinstance(report, FuzzReport)


# --- serialize/parse roundtrip -------------------------------------------------

def test_real_capability_roundtrip_unsupported():
    # Capability serializes (signing_bytes) but deliberately has no parse;
    # the roundtrip fuzz reports that instead of inventing one.
    rt = fuzz_roundtrip(_real_cap(), seed=0)
    assert rt.supported is False and rt.ok


class SloppyGrant:
    """Parses corrupt input into a permissive default -- the forbidden move."""

    def __init__(self, allow):
        self.allow = set(allow)

    def permits(self, name: str) -> bool:
        return "*" in self.allow or name in self.allow

    def serialize(self) -> str:
        return json.dumps(sorted(self.allow))

    @classmethod
    def parse(cls, blob: str) -> SloppyGrant:
        try:
            return cls(json.loads(blob))
        except (ValueError, TypeError):
            return cls(["*"])             # fail-open default: the bug


class StrictGrant(SloppyGrant):
    """Correct behavior: corrupt input raises, never broadens."""

    @classmethod
    def parse(cls, blob: str) -> StrictGrant:
        data = json.loads(blob)           # raises on corrupt input
        if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
            raise ValueError("not a grant")
        return cls(data)


def test_roundtrip_catches_permissive_default():
    rt = fuzz_roundtrip(SloppyGrant(["fs.read"]), seed=0, rounds=100)
    assert rt.supported and not rt.ok
    assert any("broader" in why for _, why in rt.leaks)


def test_roundtrip_passes_strict_parser():
    rt = fuzz_roundtrip(StrictGrant(["fs.read"]), seed=0, rounds=100)
    assert rt.supported and rt.ok


# --- CI entry point -------------------------------------------------------------

def test_main_exits_zero_on_clean_boundary(capsys):
    assert main(["--rounds", "300"]) == 0
    out = capsys.readouterr().out
    assert "0 leaks" in out and "LEAK" not in out
