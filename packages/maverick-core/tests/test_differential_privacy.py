"""differential_privacy: Laplace mechanism for (epsilon)-DP aggregates."""
from __future__ import annotations

from maverick.tools.differential_privacy import differential_privacy


def _run(**kw):
    return differential_privacy().fn(kw)


def test_seed_makes_noise_reproducible():
    a = _run(op="noisy_count", value=100, epsilon=0.5, seed=42)
    b = _run(op="noisy_count", value=100, epsilon=0.5, seed=42)
    assert a == b
    assert a.startswith("noisy_count:")
    assert "0.5-differentially-private" in a


def test_output_omits_true_aggregate():
    out = _run(op="noisy_count", value=12345, epsilon=0.5, seed=42)
    assert "true=" not in out
    assert "12345" not in out
    assert "true aggregate omitted" in out


def test_count_is_nonnegative_integer():
    out = _run(op="noisy_count", value=0, epsilon=0.1, seed=1)
    val = int(out.split("\n")[0].split(":")[1].strip())
    assert val >= 0  # clamped


def test_noisy_sum_uses_sensitivity():
    out = _run(op="noisy_sum", value=1000, epsilon=1.0, sensitivity=50, seed=7)
    assert out.startswith("noisy_sum:")
    assert "sensitivity=50" in out and "laplace_scale=50" in out


def test_different_seeds_differ():
    a = _run(op="noisy_count", value=100, epsilon=0.5, seed=1)
    b = _run(op="noisy_count", value=100, epsilon=0.5, seed=2)
    assert a != b


def test_validation_errors():
    assert _run(op="noisy_count", value=10, epsilon=0).startswith("ERROR")
    assert _run(op="noisy_count", value="x", epsilon=1).startswith("ERROR")
    assert _run(op="noisy_sum", value=10, epsilon=1, sensitivity=0).startswith("ERROR")
    assert _run(op="noisy_sum", value=10, epsilon=1).startswith("ERROR")  # missing sensitivity
    assert _run(op="nope", value=10, epsilon=1).startswith("ERROR")


def test_laplace_no_domain_error_when_random_returns_zero():
    # Regression: _laplace did `math.log(1 - 2*abs(u))`; when rng.random()
    # returns exactly 0.0, u == -0.5 and the argument is 0 -> math domain error.
    # The argument must be floored just above 0 so the draw is always defined.
    import math

    from maverick.tools.differential_privacy import _laplace

    class _ZeroRng:
        def random(self):
            return 0.0

    val = _laplace(_ZeroRng(), 1.0)
    assert math.isfinite(val)


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "differential_privacy" in names
