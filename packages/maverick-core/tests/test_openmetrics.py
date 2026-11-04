"""openmetrics: OpenMetrics/Prometheus text exposition renderer."""
from __future__ import annotations

from maverick.tools.openmetrics import openmetrics


def _render(**kw):
    return openmetrics().fn({"op": "render", **kw})


def test_basic_exposition_shape():
    out = _render(metrics=[
        {"name": "http_requests_total", "type": "counter", "value": 42,
         "help": "Total requests"},
    ])
    lines = out.splitlines()
    assert lines[0] == "# HELP http_requests_total Total requests"
    assert lines[1] == "# TYPE http_requests_total counter"
    assert lines[2] == "http_requests_total 42"  # no labels -> no braces
    assert lines[-1] == "# EOF"
    assert out.endswith("# EOF\n")


def test_labels_rendered_sorted():
    out = _render(metrics=[
        {"name": "temp", "type": "gauge", "value": 1,
         "labels": {"zone": "b", "host": "a"}},
    ])
    # labels sorted by key for determinism
    assert 'temp{host="a",zone="b"} 1' in out


def test_label_value_escaping():
    out = _render(metrics=[
        {"name": "m", "type": "gauge", "value": 0,
         "labels": {"path": 'a"b\\c'}},
    ])
    # " -> \" and \ -> \\
    assert r'm{path="a\"b\\c"} 0' in out


def test_help_escaping_and_float_value():
    out = _render(metrics=[
        {"name": "m", "type": "gauge", "value": 1.5, "help": "line1\nline2"},
    ])
    assert "# HELP m line1\\nline2" in out  # newline escaped in HELP
    assert "m 1.5" in out


def test_invalid_name_and_label_rejected():
    assert _render(metrics=[{"name": "1bad", "type": "gauge", "value": 1}]).startswith("ERROR")
    bad_label = _render(metrics=[
        {"name": "ok", "type": "gauge", "value": 1, "labels": {"1x": "y"}},
    ])
    assert bad_label.startswith("ERROR")


def test_errors():
    t = openmetrics()
    assert t.fn({"op": "render"}).startswith("ERROR")  # no metrics
    assert t.fn({"op": "render", "metrics": []}).startswith("ERROR")
    assert _render(metrics=[{"name": "m", "type": "bogus", "value": 1}]).startswith("ERROR")
    assert _render(metrics=[{"name": "m", "type": "gauge", "value": "x"}]).startswith("ERROR")
    assert _render(metrics=[{"name": "m", "type": "gauge", "value": True}]).startswith("ERROR")  # bool rejected
    assert t.fn({"op": "nope", "metrics": [{"name": "m", "type": "gauge", "value": 1}]}).startswith("ERROR")
