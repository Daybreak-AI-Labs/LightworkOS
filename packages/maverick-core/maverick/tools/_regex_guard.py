"""Evaluate untrusted regular expressions with a hard time limit.

Python's ``re`` has no match timeout and holds the GIL while it backtracks, so
a model- or schema-supplied pattern such as ``(a+)+$`` or ``(.*a){10}!`` can
freeze the whole process, and no shape check catches every slow pattern
without also refusing ordinary ones. Instead, a pattern that contains a
quantifier is searched in a separate interpreter (``sys.executable -I``, the
secret-scrubbed child environment, a neutral working directory, no shell),
and the parent kills the child when the time budget runs out, as
``maverick.parser_isolation`` does for untrusted parsers.

A pattern with no quantifier at all (no ``*``, ``+``, ``?`` or ``{``) cannot
backtrack, so it is searched in-process. Pattern and text lengths are capped
before anything runs.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

MAX_PATTERN_CHARS = 1000
MAX_TEXT_CHARS = 100_000
DEFAULT_TIMEOUT_S = 1.0
_MAX_CHILD_OUTPUT = 64 * 1024
_QUANTIFIER_CHARS = frozenset("*+?{")

# Reads {"p": [patterns], "t": text, "f": flags} from stdin and prints the
# list of match results. The patterns were already compiled by the parent.
_CHILD = (
    "import json, re, sys\n"
    "d = json.loads(sys.stdin.read())\n"
    "rx = [re.compile(p, d['f']) for p in d['p']]\n"
    "print(json.dumps([r.search(d['t']) is not None for r in rx]))\n"
)


class RegexGuardError(ValueError):
    """The pattern could not be evaluated."""


class PatternInvalid(RegexGuardError):
    """The pattern is too long or does not compile."""

    def __init__(self, index: int, message: str) -> None:
        super().__init__(message)
        self.index = index


class PatternTimeout(RegexGuardError):
    """Evaluation exceeded the time budget; the child process was killed."""


def pattern_error(pattern: str) -> str | None:
    """Why ``pattern`` cannot be used (too long, does not compile), or None."""
    if len(pattern) > MAX_PATTERN_CHARS:
        return f"pattern longer than {MAX_PATTERN_CHARS} characters"
    try:
        re.compile(pattern)
    except re.error as e:
        return str(e)
    return None


def _run_child(payload: bytes, timeout_s: float) -> bytes:
    from . import scrub_child_env
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", _CHILD],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=scrub_child_env(), cwd=os.path.abspath(os.sep),
    )
    try:
        out, err = proc.communicate(payload, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        raise PatternTimeout(f"pattern took longer than {timeout_s:g}s to evaluate") from None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    if proc.returncode != 0:
        tail = err[-200:].decode("utf-8", "replace")
        raise RegexGuardError(f"regex child failed (exit {proc.returncode}): {tail}")
    return out[:_MAX_CHILD_OUTPUT]


def guarded_search_all(
    patterns: list[str], text: str, *, flags: int = 0,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> list[bool]:
    """``re.search(p, text, flags) is not None`` for each pattern, all within
    one ``timeout_s`` budget.

    Raises ``PatternInvalid`` (with ``.index``) for a pattern that is too long
    or does not compile, ``PatternTimeout`` when the budget runs out, and
    ``RegexGuardError`` for an oversized text or a failed child.
    """
    if len(text) > MAX_TEXT_CHARS:
        raise RegexGuardError(f"text longer than {MAX_TEXT_CHARS} characters")
    for i, pattern in enumerate(patterns):
        problem = pattern_error(pattern)
        if problem:
            raise PatternInvalid(i, problem)
    if not any(_QUANTIFIER_CHARS & set(p) for p in patterns):
        return [re.search(p, text, flags) is not None for p in patterns]
    payload = json.dumps({"p": patterns, "t": text, "f": int(flags)}).encode("utf-8")
    raw = _run_child(payload, timeout_s)
    try:
        result = json.loads(raw.decode("utf-8"))
    except ValueError as e:
        raise RegexGuardError("regex child returned malformed output") from e
    if not (isinstance(result, list) and len(result) == len(patterns)
            and all(isinstance(r, bool) for r in result)):
        raise RegexGuardError("regex child returned malformed output")
    return result


def guarded_search(
    pattern: str, text: str, *, flags: int = 0,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> bool:
    """``re.search(pattern, text, flags) is not None`` under a time limit."""
    return guarded_search_all([pattern], text, flags=flags, timeout_s=timeout_s)[0]
