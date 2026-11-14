"""Capability-leak fuzzer: hunt for permission-boundary holes
.

:class:`maverick.capability.Capability` is the least-privilege boundary —
``permits(name)`` decides whether a principal may use a tool, via exact
membership in the grant (``allow_tools``), deny-set subtraction, and an
optional risk ceiling. The classic way such boundaries rot is *almost*-equal
names: a matcher that lowercases, trims, globs, or substring-compares will
answer ``True`` for ``"FS.WRITE"``, ``"shell.exec.x"`` or a Cyrillic
``"ѕhell"`` when only ``"fs.write"`` / ``"shell.exec"`` were granted.

This module is a deterministic property fuzzer for that boundary: given a
capability and the set of names *literally* granted, it generates adversarial
probes — case variants, unicode confusables, prefix/suffix tricks, separator
swaps, empty/whitespace, embedded NULs, very long names, glob characters,
plus PRNG character mutations — and asserts ``permits()`` answers ``False``
for every probe outside the literal grant. A ``True`` is a **leak**.

Determinism: every probe comes from ``random.Random(seed)`` over a *sorted*
view of the grant (set iteration order is hash-randomized across processes;
sorting first makes the probe list reproducible run-to-run), so CI failures
replay exactly. A ``permits()`` that *raises* on a hostile probe counts as a
deny — refusing is safe; only ``True`` leaks.

:func:`fuzz_roundtrip` covers the serialization boundary for capability types
that support it: mutated serialized forms must either fail to parse or parse
into a grant **no broader** than the original — corrupt input must never
decay into a permissive default. The real :class:`Capability` serializes
(``signing_bytes``) but deliberately has no ``parse``; the roundtrip check
reports ``supported=False`` for it and exists for grant types that do
round-trip (e.g. wire-format grants in A2A handoffs).

Pure, offline, stdlib-only library + a CI-friendly :func:`main` that exits 1
on leaks. Nothing imports it by default; it changes no behavior.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

# Latin -> visually-confusable Cyrillic (the classic homoglyph spoof set).
_HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "h": "һ",
    "i": "і", "o": "о", "p": "р", "s": "ѕ",
    "x": "х", "y": "у",
}

_SEPARATORS = ("/", ":", "-", "_", "..", " ")
_GLOB_CHARS = ("*", "?", "[a-z]")


@dataclass(frozen=True)
class FuzzReport:
    """Outcome of one fuzz run. ``leaks`` pairs each leaking probe with why
    it was expected to be denied (the generator that produced it)."""

    probes: int
    leaks: tuple[tuple[str, str], ...]

    @property
    def ok(self) -> bool:
        return not self.leaks


@dataclass(frozen=True)
class RoundtripReport:
    """Outcome of :func:`fuzz_roundtrip`. ``supported`` is False when the
    capability type has no parse counterpart (nothing to fuzz)."""

    supported: bool
    mutants: int
    leaks: tuple[tuple[str, str], ...]

    @property
    def ok(self) -> bool:
        return not self.leaks


def _structured_probes(name: str) -> list[tuple[str, str]]:
    """The systematic adversarial variants of one granted name."""
    probes: list[tuple[str, str]] = []

    def add(p: str, why: str) -> None:
        probes.append((p, why))

    # Case variants: an exact matcher must be case-sensitive.
    for variant in (name.upper(), name.title(), name.swapcase(), name.capitalize()):
        add(variant, "case_variant")
    # Unicode confusables: swap each confusable letter once, and all at once.
    for latin, cyr in _HOMOGLYPHS.items():
        if latin in name:
            add(name.replace(latin, cyr, 1), "homoglyph")
    confused = "".join(_HOMOGLYPHS.get(ch, ch) for ch in name)
    add(confused, "homoglyph")
    # Prefix / suffix tricks: scope creep by adjacency.
    add("x" + name, "prefix")
    add(name + "x", "suffix")
    add(name + ".x", "suffix")
    add(name + ".", "suffix")
    add("." + name, "prefix")
    # Separator swaps: "shell.exec" vs "shell/exec" vs "shell:exec" ...
    if "." in name:
        for sep in _SEPARATORS:
            add(name.replace(".", sep), "separator_swap")
        head, _, tail = name.rpartition(".")
        add(f"{head}.*", "glob")
        add(f"{head}.{tail.upper()}", "case_variant")
    # Whitespace wrappers and embeddings.
    add(" " + name, "whitespace")
    add(name + " ", "whitespace")
    add(name + "\n", "whitespace")
    add(name.replace(name[0], name[0] + " ", 1), "whitespace")
    # Embedded NULs: C-string truncation style smuggling.
    add(name + "\x00", "null_byte")
    add("\x00" + name, "null_byte")
    add(name[: max(1, len(name) // 2)] + "\x00" + name[max(1, len(name) // 2):],
        "null_byte")
    # Very long names: buffer/normalization edge behavior.
    add(name * 100, "long_name")
    add(name + "a" * 4096, "long_name")
    # Glob characters: a matcher that fnmatches grants is wide open.
    for g in _GLOB_CHARS:
        add(name + g, "glob")
        add(g + name, "glob")
    return probes


def _global_probes() -> list[tuple[str, str]]:
    """Grant-independent probes (empty-ish and pure-glob inputs)."""
    return [
        ("", "empty"),
        (" ", "empty"),
        ("\t", "empty"),
        ("\n", "empty"),
        ("\x00", "null_byte"),
        ("*", "glob"),
        ("**", "glob"),
        ("?", "glob"),
    ]


def _mutate(name: str, rng: random.Random) -> tuple[str, str]:
    """One PRNG-driven character mutation of ``name``."""
    ops = ("insert", "delete", "replace", "double")
    op = rng.choice(ops)
    pos = rng.randrange(max(1, len(name)))
    ch = chr(rng.randrange(33, 127))
    if op == "insert":
        return name[:pos] + ch + name[pos:], "random_mutation"
    if op == "delete" and len(name) > 1:
        return name[:pos] + name[pos + 1:], "random_mutation"
    if op == "replace" and name:
        return name[:pos] + ch + name[pos + 1:], "random_mutation"
    return name + name[-1:], "random_mutation"


def generate_probes(granted, *, seed: int = 0, rounds: int = 500) -> list[tuple[str, str]]:
    """Deterministic list of exactly ``rounds`` (probe, why) pairs.

    Structured variants of every granted name first (sorted, so the output
    is identical across processes regardless of set hash order), then PRNG
    mutations until ``rounds`` is reached. Probes that collide with a granted
    name are filtered later by the caller — a probe must only be *expected*
    denied when it is outside the literal grant.
    """
    rng = random.Random(seed)
    names = sorted(str(n) for n in granted)
    pool: dict[str, str] = {}  # probe -> why (first generator wins; ordered)
    for probe, why in _global_probes():
        pool.setdefault(probe, why)
    for name in names:
        for probe, why in _structured_probes(name):
            pool.setdefault(probe, why)
    items = list(pool.items())[:rounds]
    while len(items) < rounds and names:
        probe, why = _mutate(rng.choice(names), rng)
        if probe not in pool:
            pool[probe] = why
            items.append((probe, why))
    return items


def fuzz(capability, granted, *, seed: int = 0, rounds: int = 500) -> FuzzReport:
    """Probe ``capability.permits`` with adversarial names; report leaks.

    ``granted`` is the set of names *literally* granted — the only names for
    which ``permits()`` may answer True. Probes that happen to equal a
    granted name are skipped (they are legitimately permitted, not leaks).
    A probe whose ``permits()`` raises counts as denied.
    """
    granted_set = {str(n) for n in granted}
    leaks: list[tuple[str, str]] = []
    tested = 0
    for probe, why in generate_probes(granted_set, seed=seed, rounds=rounds):
        if probe in granted_set:
            continue
        tested += 1
        try:
            permitted = bool(capability.permits(probe))
        except Exception:
            permitted = False  # refusing a hostile probe is a deny, not a leak
        if permitted:
            leaks.append((probe, f"{why}: not in the literal grant"))
    return FuzzReport(probes=tested, leaks=tuple(leaks))


def _find_parse(spec):
    """A parse counterpart on the spec's type (class/static method), if any."""
    for attr in ("parse", "from_json", "deserialize", "loads"):
        fn = getattr(type(spec), attr, None)
        if callable(fn):
            return fn
    return None


def _serialized(spec) -> str | None:
    for attr in ("serialize", "to_json", "dumps"):
        fn = getattr(spec, attr, None)
        if callable(fn):
            out = fn()
            return out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)
    fn = getattr(spec, "signing_bytes", None)
    if callable(fn):
        return fn().decode("utf-8", "replace")
    return None


def fuzz_roundtrip(spec, *, seed: int = 0, rounds: int = 200) -> RoundtripReport:
    """Mutate ``spec``'s serialized form; corrupted bytes must never parse
    into a *broader* grant.

    Supported only when the type exposes both a serializer (``serialize`` /
    ``to_json`` / ``dumps`` / ``signing_bytes``) and a parser (``parse`` /
    ``from_json`` / ``deserialize`` / ``loads``); otherwise
    ``supported=False`` (the real :class:`~maverick.capability.Capability`
    has no parser — that is itself a safe design). For every mutant that
    *does* parse, each adversarial probe (plus a canary name) permitted by
    the mutant must also be permitted by the original; anything extra is a
    leak. A parse that raises is correct behavior.
    """
    parse = _find_parse(spec)
    blob = _serialized(spec)
    if parse is None or blob is None:
        return RoundtripReport(supported=False, mutants=0, leaks=())
    rng = random.Random(seed)
    canaries = ["__fuzzer_canary__", "shell.exec", "*", ""]
    mutants: list[str] = ["", "{", "null", "[]", "{}", blob + blob]
    while len(mutants) < rounds:
        m, _ = _mutate(blob, rng)
        cut = rng.randrange(len(blob) + 1)
        mutants.append(m)
        if len(mutants) < rounds:
            mutants.append(blob[:cut])  # truncation
    leaks: list[tuple[str, str]] = []
    for mutant in mutants[:rounds]:
        try:
            parsed = parse(mutant)
        except Exception:
            continue  # rejecting corrupt input is the required behavior
        if parsed is None:
            continue
        for probe in canaries:
            try:
                mutant_says = bool(parsed.permits(probe))
                original_says = bool(spec.permits(probe))
            except Exception:
                continue
            if mutant_says and not original_says:
                leaks.append((probe, "mutated serialized form parsed into a "
                                     "broader grant"))
    return RoundtripReport(supported=True, mutants=min(len(mutants), rounds),
                           leaks=tuple(leaks))


def main(argv=None) -> int:
    """Fuzz the real Capability with a representative grant.

    Exits 1 on any leak. No CI workflow runs this entry point today; the
    module's tests exercise the same fuzzing.
    """
    import argparse

    parser = argparse.ArgumentParser(description="capability-leak fuzzer")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--rounds", type=int, default=500)
    args = parser.parse_args(argv)

    from .capability import Capability

    granted = {"fs.read", "fs.write", "shell.exec", "web_search", "http_fetch"}
    cap = Capability(
        principal="fuzzer",
        allow_tools=frozenset(granted),
        deny_tools=frozenset({"shell.exec.sudo"}),
    )
    report = fuzz(cap, granted, seed=args.seed, rounds=args.rounds)
    rt = fuzz_roundtrip(cap, seed=args.seed)
    print(f"capability fuzz: {report.probes} probes, {len(report.leaks)} leaks; "
          f"roundtrip: {'n/a (no parse)' if not rt.supported else f'{rt.mutants} mutants, {len(rt.leaks)} leaks'}")
    for probe, why in (*report.leaks, *rt.leaks):
        print(f"  LEAK: permits({probe!r}) is True -- {why}")
    return 0 if (report.ok and rt.ok) else 1


if __name__ == "__main__":  # pragma: no cover -- CI entry point
    raise SystemExit(main())


__all__ = [
    "FuzzReport",
    "RoundtripReport",
    "generate_probes",
    "fuzz",
    "fuzz_roundtrip",
    "main",
]
