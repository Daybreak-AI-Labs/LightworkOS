"""jwt_inspect: offline JWT decode + validation."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from maverick.tools.jwt_inspect import jwt_inspect


def _b64(obj) -> str:
    raw = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _make(header, payload, secret=None):
    h, p = _b64(header), _b64(payload)
    signing_input = f"{h}.{p}".encode()
    if secret and header.get("alg") == "HS256":
        sig = _b64(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    else:
        sig = "sig"
    return f"{h}.{p}.{sig}"


def _i(token, **kw):
    kw["op"] = "inspect"
    kw["token"] = token
    return jwt_inspect().fn(kw)


def test_decode_claims_unverified():
    tok = _make({"alg": "HS256", "typ": "JWT"}, {"iss": "acme", "sub": "u1", "exp": 2000, "role": "admin"})
    out = _i(tok, now=1000)
    assert out.startswith("UNVERIFIED")
    assert "iss=acme" in out and "sub=u1" in out
    assert "custom claims: role" in out
    assert "time: valid" in out
    assert "signature: unverified" in out


def test_expired():
    tok = _make({"alg": "HS256"}, {"exp": 1000})
    out = _i(tok, now=2000)
    assert out.startswith("INVALID")
    assert "EXPIRED 1000s ago" in out


def test_not_yet_valid_with_leeway():
    tok = _make({"alg": "HS256"}, {"nbf": 1000})
    assert _i(tok, now=990).startswith("INVALID")          # 10s early
    assert _i(tok, now=990, leeway=30).startswith("UNVERIFIED")  # within leeway


def test_hs256_signature_valid():
    tok = _make({"alg": "HS256"}, {"sub": "u", "exp": 2000}, secret="topsecret")
    out = _i(tok, now=1000, secret="topsecret")
    assert out.startswith("VALID")
    assert "signature: VALID" in out


def test_hs256_signature_invalid():
    tok = _make({"alg": "HS256"}, {"sub": "u"}, secret="topsecret")
    out = _i(tok, now=1000, secret="wrong")
    assert out.startswith("INVALID")
    assert "signature: INVALID" in out


def test_alg_none_flagged():
    tok = _make({"alg": "none"}, {"sub": "u"})
    out = _i(tok, now=1000, secret="x")
    assert out.startswith("INVALID")
    assert "INSECURE (alg=none" in out


def test_alg_none_flagged_without_secret():
    tok = _make({"alg": "none"}, {"sub": "u"})
    out = _i(tok, now=1000)
    assert out.startswith("INVALID")
    assert "INSECURE (alg=none" in out


def test_not_cacheable_because_default_now_is_time_dependent():
    from maverick.cache.tool import cacheable

    tool = jwt_inspect()
    assert tool.parallel_safe is False
    assert cacheable(tool) is False


def test_asymmetric_unverifiable():
    tok = _make({"alg": "RS256"}, {"sub": "u"})
    out = _i(tok, now=1000, secret="x")
    assert "unverifiable here (asymmetric alg RS256)" in out
    assert out.startswith("UNVERIFIED")


def test_errors():
    t = jwt_inspect()
    assert t.fn({"op": "inspect", "token": ""}).startswith("ERROR")
    assert t.fn({"op": "inspect", "token": "a.b"}).startswith("ERROR")  # not 3 parts
    assert t.fn({"op": "inspect", "token": "!!!.!!!.x"}).startswith("ERROR")  # bad base64/json
    assert t.fn({"op": "inspect", "token": "a.b.c", "now": "x"}).startswith("ERROR")
    assert t.fn({"op": "nope", "token": "a.b.c"}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "jwt_inspect" in names
