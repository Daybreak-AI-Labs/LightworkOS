"""Tests for the geocode tool (maverick.tools.geocode)."""
from __future__ import annotations

from unittest.mock import MagicMock

# ---------- Geocode tool ----------

def test_geocode_requires_op():
    from maverick.tools.geocode import geocode
    assert "op is required" in geocode().fn({})


def test_geocode_forward_renders(monkeypatch):
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=[{
        "lat": "37.4220", "lon": "-122.0841",
        "display_name": "1600 Amphitheatre Parkway, Mountain View, CA",
    }])
    # geocode routes through the SSRF-safe client now; mock that seam.
    import maverick.tools._ssrf as _ssrf
    monkeypatch.setattr(_ssrf, "safe_get", lambda url, **kw: resp)
    from maverick.tools.geocode import geocode
    out = geocode().fn({"op": "forward", "query": "googleplex"})
    assert "37.4220" in out
    assert "Mountain View" in out


def test_geocode_reverse_renders(monkeypatch):
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={
        "display_name": "Liberty Island, Manhattan, NYC, NY",
        "address": {"city": "New York", "country": "USA"},
    })
    import maverick.tools._ssrf as _ssrf
    monkeypatch.setattr(_ssrf, "safe_get", lambda url, **kw: resp)
    from maverick.tools.geocode import geocode
    out = geocode().fn({"op": "reverse", "lat": 40.6892, "lon": -74.0445})
    assert "Liberty Island" in out
    assert "New York" in out


def test_geocode_reverse_requires_coords():
    from maverick.tools.geocode import geocode
    out = geocode().fn({"op": "reverse"})
    assert "lat and lon" in out
