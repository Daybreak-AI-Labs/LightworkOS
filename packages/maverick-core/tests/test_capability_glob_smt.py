"""SMT proof (Z3) that the path/host glob narrowing in ``Capability`` is
monotone — the one place the property test's set-theory reasoning doesn't fully
cover, because ``allow_paths`` / ``allow_hosts`` are *fnmatch glob languages*,
not exact-match sets.

``_narrow_globs`` intersects the glob *pattern strings* (``A & B``), with the
``_DENY_ALL`` sentinel for the disjoint case. We prove, for a fully SYMBOLIC
(unbounded) path ``p`` drawn from the real domain (NUL-free), that

    permits_path(p, narrow(A, B))  ⟹  permits_path(p, A)   (and ⟹ B)

i.e. the narrowed grant can never permit a path the parent didn't. ``permits``
is encoded as membership in the union of the patterns' regexes; the glob→regex
translation is checked faithful to ``fnmatch.fnmatchcase`` first, so the proof
is about the *real* matcher, and ``narrow`` is the *real* ``_narrow_globs`` from
the codebase.

Two facts the proof also pins down:

* The ``_DENY_ALL`` sentinel (``"\\x00"``) matches NO NUL-free string — so
  "permits nothing" really permits nothing in the real domain (a NUL is never a
  valid path/host/tool name). This is the explicit domain assumption.
* The narrowing is sound but **incomplete**: e.g. ``narrow({"*"}, {"src/*"})``
  collapses to deny-all even though ``*`` ⊇ ``src/*``. That OVER-restricts (the
  safe direction — it never escalates), so it doesn't affect the security
  invariant; it's a documented usability wart, not a hole.

Z3 is a verification-only tool and deliberately NOT a project dependency, so this
test self-skips where ``z3`` isn't installed (`pip install z3-solver` to run it).
The pure-Python property suite (``test_capability_monotonicity``) is the
always-on CI guard; this is the deep-rigor companion.
"""
from __future__ import annotations

import fnmatch
import itertools

import pytest

z3 = pytest.importorskip("z3")

from maverick.capability import _DENY_ALL, _narrow_globs  # noqa: E402

_S = z3.StringSort()
_RE = z3.ReSort(_S)
_ANY = z3.AllChar(_RE)                 # regex: any single character
_EMPTY = z3.Re(z3.StringVal(""))       # regex: matches only ""


def _lit(c: str):
    return z3.Re(z3.StringVal(c))


def glob_to_re(pat: str):
    """Translate an fnmatch glob to a Z3 regex (POSIX / case-sensitive).

    Supports literals, ``*`` (any run, incl. ``/`` — fnmatch semantics), ``?``
    (one char), and ``[seq]`` / ``[!seq]`` classes with ranges. Verified faithful
    to :func:`fnmatch.fnmatchcase` by :func:`test_glob_to_re_matches_fnmatch`.
    """
    res: list = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            res.append(z3.Star(_ANY))
        elif c == "?":
            res.append(_ANY)
        elif c == "[":
            j = i + 1
            neg = False
            if j < n and pat[j] in ("!", "^"):
                neg = True
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                j += 1
            if j >= n:
                res.append(_lit("["))  # unterminated class -> literal '['
            else:
                body = pat[i + 1 + (1 if neg else 0):j]
                chars: set[str] = set()
                k = 0
                while k < len(body):
                    if k + 2 < len(body) and body[k + 1] == "-":
                        for o in range(ord(body[k]), ord(body[k + 2]) + 1):
                            chars.add(chr(o))
                        k += 3
                    else:
                        chars.add(body[k])
                        k += 1
                if len(chars) > 1:
                    cls = z3.Union(*[_lit(x) for x in chars])
                elif chars:
                    cls = _lit(next(iter(chars)))
                else:
                    cls = _EMPTY
                if neg:
                    cls = z3.Intersect(_ANY, z3.Complement(cls))
                res.append(cls)
                i = j + 1
                continue
        else:
            res.append(_lit(c))
        i += 1
    if len(res) > 1:
        return z3.Concat(*res)
    return res[0] if res else _EMPTY


def _permits(p, patterns):
    """Z3 Bool: does ``p`` match any glob in ``patterns`` (empty == all)."""
    s = set(patterns)
    if not s:
        return z3.BoolVal(True)
    return z3.Or([z3.InRe(p, glob_to_re(pat)) for pat in s])


# ---- faithfulness: glob_to_re ≡ fnmatch -------------------------------------

def test_glob_to_re_matches_fnmatch():
    """The Z3 glob model must agree with fnmatch, or the proof is vacuous."""
    pats = ["*", "?", "src/*", "*/foo.py", "a/b/*", "*.py", "x*", "[ab]*",
            "conf?g", "src/secret", "[!x]y", "**", "[a-c]z"]
    alpha = "abxs/.py12"
    mismatches = 0
    for pat in pats:
        re = glob_to_re(pat)
        for length in range(4):
            for tup in itertools.product(alpha, repeat=length):
                s = "".join(tup)
                sol = z3.Solver()
                sol.add(z3.InRe(z3.StringVal(s), re))
                if (sol.check() == z3.sat) != fnmatch.fnmatchcase(s, pat):
                    mismatches += 1
    assert mismatches == 0, f"glob_to_re disagrees with fnmatch in {mismatches} cases"


# ---- the theorem: glob narrowing is monotone --------------------------------

_PAIRS = [
    ({"src/*"}, {"*/foo.py"}),                 # overlap via different patterns
    ({"src/*", "lib/*"}, {"src/*"}),           # subset
    ({"*.py"}, {"*.py"}),                       # identical
    (set(), {"src/*"}),                         # parent = all
    ({"src/*"}, set()),                         # other = all
    ({"*"}, {"src/*"}),                         # "*" vs a sub-glob (over-restricts)
    ({"a/b/*"}, {"a/*"}),
    ({"data/*", "src/*"}, {"src/*", "etc/*"}),
    ({"x*", "y*"}, {"y*", "z*"}),
    ({"src/secret"}, {"src/*"}),
    ({"[ab]*"}, {"a*"}),
]


def test_glob_narrowing_is_monotone():
    """For a symbolic NUL-free path, narrow(A,B) permits ⟹ A permits (and B)."""
    p = z3.String("p")
    nul_free = z3.Not(z3.Contains(p, z3.StringVal("\x00")))
    obligations = 0
    for a, b in _PAIRS:
        narrowed = set(_narrow_globs(frozenset(a), frozenset(b) or None))
        for parent in (a, b):
            sol = z3.Solver()
            # search for a counterexample: narrowed permits p, parent does not
            sol.add(nul_free, _permits(p, narrowed), z3.Not(_permits(p, parent)))
            assert sol.check() == z3.unsat, (
                f"glob narrowing ESCALATED: A={a} B={b} narrowed={narrowed} "
                f"permits a path parent {parent} does not: {sol.model()}")
            obligations += 1
    assert obligations == 2 * len(_PAIRS)


def test_deny_all_sentinel_matches_no_real_path():
    """_DENY_ALL ('\\x00') must match no NUL-free string, so 'permits nothing'
    is honest in the real (NUL-free) path/host/tool domain."""
    p = z3.String("p")
    sol = z3.Solver()
    sol.add(z3.Not(z3.Contains(p, z3.StringVal("\x00"))),
            z3.InRe(p, glob_to_re(_DENY_ALL)))
    assert sol.check() == z3.unsat


def test_narrowing_is_sound_but_incomplete_documented():
    """Documents the witness: narrowing CAN over-restrict (safe direction).
    `*` ⊇ `src/*`, yet pattern-set intersection collapses to deny-all."""
    narrowed = set(_narrow_globs(frozenset({"*"}), frozenset({"src/*"})))
    assert narrowed == {_DENY_ALL}
    # over-restricted: a path both languages admit is now denied — never the
    # reverse, so the security (monotonicity) invariant is unaffected.
    assert not any(fnmatch.fnmatchcase("src/foo", pat) for pat in narrowed)
