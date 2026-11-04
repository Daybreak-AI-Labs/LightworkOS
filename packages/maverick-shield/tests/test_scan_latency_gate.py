"""CI gate: the shield's hot-path scanners must stay fast on adversarial input.

The shield runs on every agent step and every fetched body. We have shipped
ReDoS hangs of tens of seconds; this gate is what stops the next one.

Two guards, because they catch different failures:

* **Hang guard (subprocess + hard timeout).** A catastrophic backtrack hangs
  *inside* the scan call, so an in-process timer never gets to assert -- only
  killing the process stops it. Crucially, a scan that times out must FAIL the
  build, never be swallowed: a shield call that silently returns "allow" on a
  crafted slow input is a *detection bypass*, not a latency blip.
* **Slow guard (in-process ceiling).** Catches finite-but-slow regressions
  well under the hang timeout.

Mirrors ``packages/maverick-core/tests/test_secrets_scrub_fuzz.py``.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest
from maverick_shield import builtin_rules, cascade

_BIG = 200_000
# Worst observed single scan is ~110ms locally on 200KB; CI runners are slower.
# 2s separates a healthy scan from the ReDoS class (catastrophic patterns run
# 13-70s) without flaking. The subprocess hang guard below is the hard backstop.
_CEILING_S = 2.0
_HANG_TIMEOUT_S = 20

_ADVERSARIAL = {
    "run_a": "a" * _BIG,
    "run_newline": "\n" * _BIG,
    "keyish_run": "sk-ant-" + "a" * _BIG,
    "b64_blob": "x " + ("QUFB" * (_BIG // 4)),
    "quantifier_bait": ("ignore " * 20000) + "all previous instructions",
}

_SCANNERS = {
    "builtin_rules.scan": lambda t: builtin_rules.scan(t, block_threshold="high"),
    "cascade.cheap_probe": cascade.cheap_probe,
}


@pytest.mark.parametrize("sname", list(_SCANNERS))
def test_scanner_under_ceiling_on_adversarial_input(sname):
    fn = _SCANNERS[sname]
    for label, text in _ADVERSARIAL.items():
        t0 = time.perf_counter()
        fn(text)
        dt = time.perf_counter() - t0
        assert dt < _CEILING_S, (
            f"{sname} took {dt:.2f}s on {label!r} (ceiling {_CEILING_S}s) -- "
            "a detection regex is going super-linear (ReDoS)."
        )


def test_scanners_do_not_hang_on_adversarial_input():
    """Hard backstop: kill on timeout. A timeout here is a *bypass*, not a blip."""
    root = Path(__file__).resolve().parents[3]
    shield = root / "packages" / "maverick-shield"
    core = root / "packages" / "maverick-core"
    prog = f"""
import sys
sys.path.insert(0, {str(shield)!r}); sys.path.insert(0, {str(core)!r})
from maverick_shield import builtin_rules, cascade
B = {_BIG}
inputs = ["a"*B, "\\n"*B, "sk-ant-"+"a"*B, "x "+("QUFB"*(B//4)),
          ("ignore "*20000)+"all previous instructions"]
for t in inputs:
    builtin_rules.scan(t, block_threshold="high")
    cascade.cheap_probe(t)
"""
    try:
        subprocess.run([sys.executable, "-c", prog], check=True,
                       timeout=_HANG_TIMEOUT_S, capture_output=True)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            f"a shield scanner did not finish within {_HANG_TIMEOUT_S}s on "
            "adversarial input -- a detection regex is backtracking super-"
            "linearly (ReDoS). A hung scan that fails open is a detection "
            "bypass; treat this as a security failure, not a perf nit."
        ) from exc
