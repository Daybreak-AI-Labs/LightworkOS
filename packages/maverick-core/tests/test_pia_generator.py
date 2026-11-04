"""pia_generator: Privacy Impact Assessment generator."""
from __future__ import annotations

from maverick.tools.pia_generator import pia_generator


def _run(**kw):
    return pia_generator().fn({"op": "generate", **kw})


def test_low_risk_minimal():
    out = _run(system="CRM", data_categories=["name", "email"],
               purposes=["support"], retention_days=90)
    assert out.startswith("# Privacy Impact Assessment: CRM")
    assert "Overall risk: LOW" in out
    assert "- 90 days" in out
    assert "## Risk flags\n- none" in out


def test_special_category_flag():
    out = _run(system="Clinic", data_categories=["name", "health records"],
               purposes=["care"], retention_days=365)
    assert "Overall risk: HIGH" in out
    assert "special-category" in out and "health records" in out


def test_third_country_transfer_flag():
    out = _run(system="App", data_categories=["email"], purposes=["marketing"],
               retention_days=30, transfers=["US", "DE"])
    assert "Overall risk: HIGH" in out
    assert "third-country transfer to: US" in out
    # DE is EEA, must not be flagged as a third country.
    assert "third-country transfer to: US, DE" not in out


def test_no_retention_limit_flag():
    out = _run(system="Logs", data_categories=["ip"], purposes=["debug"])
    assert "Overall risk: HIGH" in out
    assert "no retention limit" in out
    assert "UNBOUNDED" in out


def test_zero_retention_is_unbounded():
    out = _run(system="X", data_categories=["a"], purposes=["b"], retention_days=0)
    assert "no retention limit" in out


def test_errors_and_unknown_op():
    t = pia_generator()
    assert t.fn({"op": "generate", "data_categories": ["a"], "purposes": ["b"]}).startswith("ERROR")
    assert t.fn({"op": "generate", "system": "S", "purposes": ["b"]}).startswith("ERROR")
    assert t.fn({"op": "generate", "system": "S", "data_categories": [], "purposes": ["b"]}).startswith("ERROR")
    assert t.fn({"op": "nope", "system": "S", "data_categories": ["a"], "purposes": ["b"]}).startswith("ERROR")


def test_factory_identity():
    t = pia_generator()
    assert t.name == "pia_generator"
    assert t.parallel_safe is True
