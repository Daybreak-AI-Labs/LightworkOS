"""Cascade routing thresholds: malformed or non-finite settings fall back to
the defaults instead of disabling the cascade."""
from __future__ import annotations

import os
import subprocess
import sys


def test_malformed_threshold_settings_fall_back_to_defaults(monkeypatch):
    # A bad value used to make `import maverick.routing` raise ValueError.
    env = {**os.environ, "MAVERICK_ESCALATE_BELOW": "high",
           "MAVERICK_ESCALATE_TOOL_DEPTH": "deep"}
    probe = ("import maverick.routing as r; "
             "print(r.ESCALATE_VERIFIER_BELOW, r.ESCALATE_TOOL_DEPTH)")
    done = subprocess.run([sys.executable, "-c", probe], env=env,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    assert done.stdout.split() == ["0.6", "3"]
    from maverick.routing import escalate_below
    monkeypatch.setenv("MAVERICK_ESCALATE_BELOW", "nan")
    assert escalate_below() == 0.6
