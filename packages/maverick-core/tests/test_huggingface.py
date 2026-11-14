"""Tests for the Hugging Face tool (maverick.tools.huggingface)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- HuggingFace tool ----------

def test_hf_requires_op():
    from maverick.tools.huggingface import huggingface
    assert "op is required" in huggingface().fn({})


def test_hf_requires_model():
    from maverick.tools.huggingface import huggingface
    out = huggingface().fn({"op": "infer"})
    assert "model is required" in out


def test_hf_missing_httpx(monkeypatch):
    monkeypatch.setitem(sys.modules, "httpx", None)
    from maverick.tools.huggingface import huggingface
    out = huggingface().fn({"op": "infer", "model": "x", "inputs": "y"})
    assert "httpx not installed" in out


def test_hf_infer_calls_api(monkeypatch):
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=[
        {"label": "POSITIVE", "score": 0.99},
    ])
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    monkeypatch.setenv("HUGGINGFACE_API_TOKEN", "hf_xxx")
    from maverick.tools.huggingface import huggingface
    out = huggingface().fn({
        "op": "infer", "model": "distilbert-base-uncased-finetuned-sst-2-english",
        "inputs": "I love this!",
    })
    assert "POSITIVE" in out
    call_kwargs = fake_httpx.post.call_args.kwargs
    assert call_kwargs["headers"]["Authorization"].startswith("Bearer hf_xxx")
    assert call_kwargs["json"]["inputs"] == "I love this!"


def test_hf_infer_error_propagates(monkeypatch):
    resp = MagicMock()
    resp.status_code = 503
    resp.json = MagicMock(return_value={"error": "Model loading"})
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.huggingface import huggingface
    out = huggingface().fn({"op": "infer", "model": "x", "inputs": "y"})
    assert "ERROR" in out and "503" in out


def test_hf_summarize_requires_text():
    from maverick.tools.huggingface import huggingface
    out = huggingface().fn({"op": "summarize", "model": "x"})
    assert "non-empty text" in out


def test_hf_image_classify_requires_url():
    from maverick.tools.huggingface import huggingface
    out = huggingface().fn({"op": "image_classify", "model": "x"})
    assert "requires url" in out


def test_hf_image_classify_blocks_private_ip(monkeypatch):
    # Now routed through the IP-pinning _ssrf.safe_get (closes the TOCTOU
    # rebind window); a blocked host surfaces as BlockedHost.
    import maverick.tools._ssrf as ssrf
    from maverick.tools.huggingface import huggingface

    def _boom(url, **k):
        raise ssrf.BlockedHost("127.0.0.1 is loopback")

    monkeypatch.setattr(ssrf, "safe_get", _boom)
    out = huggingface().fn({"op": "image_classify", "model": "x", "url": "http://127.0.0.1/a.png"})
    assert "refusing" in out


def test_hf_image_classify_rejects_redirects(monkeypatch):
    import maverick.tools._ssrf as ssrf
    resp = MagicMock()
    resp.status_code = 302
    resp.content = b""
    resp.headers = {"content-type": "text/plain"}
    monkeypatch.setattr(ssrf, "safe_get", lambda url, **k: resp)
    from maverick.tools.huggingface import huggingface
    out = huggingface().fn({"op": "image_classify", "model": "x", "url": "https://example.com/i.png"})
    assert "image fetch 302" in out


def test_hf_model_id_and_image_url_stay_within_policy(monkeypatch):
    """The model id went into the URL unencoded (so '../../api/whoami-v2'
    retargeted the bearer token), and the image URL ignored the network
    posture that removes http_fetch under deny-all."""
    import maverick.tenant.egress as egress
    import maverick.tools._ssrf as ssrf
    from maverick.tools.huggingface import huggingface

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    out = huggingface().fn({"op": "infer", "model": "../../api/whoami-v2?x=1#", "inputs": "y"})
    assert out.startswith("ERROR:") and not fake_httpx.post.called

    fetched = MagicMock()
    monkeypatch.setattr(ssrf, "safe_get", fetched)
    monkeypatch.setattr(egress, "egress_allowed", lambda tool, host: False)
    out = huggingface().fn({"op": "image_classify", "model": "o/m", "url": "https://example.com/i.png"})
    assert "egress policy blocks" in out and not fetched.called
