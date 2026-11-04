"""Tests for the shared provider base (maverick.providers.base)."""
from __future__ import annotations

# --- provider SDK clients get a bounded timeout ---

def test_llm_http_timeout_is_bounded():
    from maverick.providers.base import llm_http_timeout
    t = llm_http_timeout()
    if t is not None:  # httpx present
        import httpx
        assert isinstance(t, httpx.Timeout)
