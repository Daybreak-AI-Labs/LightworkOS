"""The relevance gate cuts injected noise without losing the right skills.

Deterministic (lexical path), so it is the free CI guard that the
precision-improving gate keeps working.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recall_precision as RP  # noqa: E402


def test_gate_cuts_false_positives_without_losing_recall():
    ungated = RP.measure(0.0)
    gated = RP.measure(4.0)
    # The gate must sharply reduce noise (false positives on unrelated queries)...
    assert gated["false_positive_rate"] < ungated["false_positive_rate"]
    assert gated["false_positive_rate"] <= 0.25
    # ...while keeping the right skill reachable for genuine queries.
    assert gated["recall_at_1"] >= 0.8


def test_ungated_is_noisy_baseline():
    # Documents the problem the gate fixes: ungated lexical recall fires on
    # unrelated queries (shared common words), the noise-injection failure mode.
    assert RP.measure(0.0)["false_positive_rate"] > RP.measure(4.0)["false_positive_rate"]
