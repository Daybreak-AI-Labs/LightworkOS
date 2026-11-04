"""energy_accounting: energy / CO2 accounting for inference."""
from __future__ import annotations

from maverick.tools.energy_accounting import energy_accounting


def _est(**kw):
    return energy_accounting().fn({"op": "estimate", **kw})


def test_tokens_with_defaults():
    # 1,000,000 tokens @ 0.3 Wh/1k = 300 Wh; 300 Wh * 400 g/kWh / 1000 = 120 g
    out = _est(tokens=1_000_000)
    assert out.startswith("OK")
    assert "energy=300.0000 Wh" in out
    assert "co2e=120.0000 g" in out
    assert "0.3 Wh/1k tokens" in out
    assert "400 gCO2e/kWh" in out


def test_gpu_seconds():
    # 700 W for 3600 s = 700 Wh; 700 * 400 / 1000 = 280 g
    out = _est(gpu_seconds=3600)
    assert "energy=700.0000 Wh" in out
    assert "co2e=280.0000 g" in out


def test_custom_factors():
    # 2000 tokens @ 0.5 Wh/1k = 1 Wh; grid 1000 -> 1 g
    out = _est(tokens=2000, wh_per_ktok=0.5, grid_g_co2_per_kwh=1000)
    assert "energy=1.0000 Wh" in out
    assert "co2e=1.0000 g" in out


def test_default_op_is_estimate():
    out = energy_accounting().fn({"tokens": 1000})
    assert out.startswith("OK")


def test_requires_exactly_one_basis():
    assert energy_accounting().fn({"op": "estimate"}).startswith("ERROR")  # neither
    assert _est(tokens=1000, gpu_seconds=10).startswith("ERROR")  # both


def test_errors():
    t = energy_accounting()
    assert t.fn({"op": "nope", "tokens": 1}).startswith("ERROR")
    assert t.fn({"op": "estimate", "tokens": -5}).startswith("ERROR")
    assert t.fn({"op": "estimate", "tokens": "lots"}).startswith("ERROR")
    assert t.fn({"op": "estimate", "tokens": 1, "grid_g_co2_per_kwh": -1}).startswith("ERROR")
