"""http_fetch asks a person before it sends anything but a plain read.

http_fetch accepted POST with a request body and never asked for consent, so
with the default open egress an agent could send data to any public address
without a person's approval (unless information-flow control happened to flag
the call). Every request that is not a body-less GET or HEAD now goes through
the exact-operation consent gate, like ``shell``: a fresh human decision bound
to the method, address, headers and body, refused when nobody can answer.
"""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

SECRET = "sk-live-" + "Q7" * 20  # pragma: allowlist secret


class _Resp:
    status_code = 200
    reason_phrase = "OK"
    encoding = "utf-8"
    url = "https://api.example.test/v1/items"
    headers = {"content-type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_bytes(self, chunk_size=None):
        yield b'{"ok": true}'


@pytest.fixture
def sent(monkeypatch, tmp_path):
    """Record every request that reaches the network boundary."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")  # offline: no DNS
    monkeypatch.setenv("MAVERICK_FETCH_NO_SCAN", "1")
    calls: list[dict] = []

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def stream(self, method, url, headers=None, content=None):
            calls.append({"method": method, "url": url,
                          "headers": dict(headers or {}), "body": content})
            return _Resp()

    import maverick.tools._ssrf as ssrf

    monkeypatch.setattr(ssrf, "safe_client", lambda url, **kw: _Client())
    return calls


def _fetch(args):
    from maverick.tools.http_fetch import http_fetch

    return http_fetch().fn(args)


def _post(**extra):
    return {
        "url": "https://api.example.test/v1/items?page=2",
        "method": "POST",
        "headers": {"Content-Type": "application/json",
                    "Authorization": f"Bearer {SECRET}"},
        "body": json.dumps({"name": "quarterly numbers", "rows": 3}),
        **extra,
    }


def _approve_as_human(monkeypatch, cards=None):
    import maverick.safety.consent as consent

    def approve(*_args, **kwargs):
        if cards is not None:
            cards.append(kwargs)
        return SimpleNamespace(granted=True, source="dashboard", actor="user:reviewer")

    monkeypatch.setattr(consent, "require_consent", approve)


def _deny_and_capture(monkeypatch):
    import maverick.safety as safety

    calls: list[dict] = []

    def deny(*args, **kwargs):
        calls.append({"action": args[0] if args else None, **kwargs})
        raise safety.ConsentDenied("http_fetch")

    monkeypatch.setattr(safety, "require_operation_consent", deny)
    return calls


def test_post_is_refused_when_no_person_can_answer(sent, monkeypatch):
    """A headless run cannot silently send data: nothing reaches the network."""
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    out = _fetch(_post())
    assert out.startswith("ERROR:")
    assert "not approved" in out
    assert sent == []


def test_silent_auto_approve_is_not_human_consent(sent, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-approve")
    out = _fetch(_post())
    assert "not approved" in out
    assert sent == []


def test_post_is_refused_under_auto_deny(sent, monkeypatch):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "auto-deny")
    out = _fetch(_post())
    assert "not approved" in out
    assert sent == []


@pytest.mark.parametrize("method", ["GET", "HEAD", "get"])
def test_plain_reads_need_no_approval(sent, monkeypatch, method):
    calls = _deny_and_capture(monkeypatch)
    out = _fetch({"url": "https://api.example.test/v1/items", "method": method,
                  "render": "raw"})
    assert "HTTP 200 OK" in out
    assert calls == []
    assert [c["method"] for c in sent] == [method.upper()]


@pytest.mark.parametrize(
    "args",
    [
        {"method": "PUT", "body": "x=1"},
        {"method": "DELETE"},
        {"method": "patch", "body": "x=1"},
        # A body sends data whatever the method says.
        {"method": "GET", "body": "x=1"},
        {"body": "x=1"},
        {"method": "HEAD", "body": "x=1"},
    ],
    ids=["put", "delete", "patch-lowercase", "get-with-body", "default-with-body",
         "head-with-body"],
)
def test_every_other_request_asks_first(sent, monkeypatch, args):
    calls = _deny_and_capture(monkeypatch)
    out = _fetch({"url": "https://api.example.test/v1/items", **args})
    assert "not approved" in out
    assert len(calls) == 1
    assert sent == []


def test_post_runs_once_after_a_person_approves(sent, monkeypatch):
    _approve_as_human(monkeypatch)
    args = _post()
    out = _fetch(args)
    assert "HTTP 200 OK" in out
    assert len(sent) == 1
    assert sent[0]["method"] == "POST"
    assert sent[0]["url"] == args["url"]
    assert sent[0]["body"] == args["body"]
    assert sent[0]["headers"]["Authorization"] == f"Bearer {SECRET}"


def test_request_names_the_destination_and_binds_the_exact_request(sent, monkeypatch):
    calls = _deny_and_capture(monkeypatch)
    args = _post()
    _fetch(args)

    (call,) = calls
    assert call["action"] == "http_fetch"
    assert call["risk"] == "high"
    assert "api.example.test" in call["scope"]
    assert "api.example.test" in call["detail"]
    assert "POST" in call["detail"]
    assert call["allow_auto_approve"] is False
    assert call["consult_ledger"] is False
    assert call["irreversible"] is True
    assert call["before"] and call["after"]
    # The decision is bound to everything that will be sent, secrets included.
    params = call["parameters"]
    assert params["method"] == "POST"
    assert params["url"] == args["url"]
    assert params["body"] == args["body"]
    assert params["headers"]["Authorization"] == f"Bearer {SECRET}"
    assert params["headers"]["Content-Type"] == "application/json"
    assert call["parameters_provider"]() == params
    # What the person reads: method, address, headers and body, with the
    # credential hidden.
    shown = "\n".join(call["parameter_summary"])
    assert "POST" in shown
    assert "https://api.example.test/v1/items?page=2" in shown
    assert "Content-Type" in shown and "application/json" in shown
    assert "quarterly numbers" in shown
    assert "[REDACTED:sensitive field]" in shown
    assert SECRET not in shown


def test_sensitive_address_parts_are_hidden_from_the_reviewer(sent, monkeypatch):
    calls = _deny_and_capture(monkeypatch)
    url = "https://bob:hunter2@api.example.test/hook?api_key=abc123&team=blue"  # pragma: allowlist secret
    _fetch({"url": url, "method": "POST", "body": "hello"})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert "hunter2" not in shown and "abc123" not in shown
    assert "team=blue" in shown
    assert "hunter2" not in call["scope"] and "bob" not in call["scope"]
    assert call["parameters"]["url"] == url


def test_keyed_secrets_in_a_json_body_are_hidden_like_connector_requests(sent, monkeypatch):
    calls = _deny_and_capture(monkeypatch)
    body = json.dumps({"user": "dana", "password": "hunter2-correct-horse"})  # pragma: allowlist secret
    _fetch({"url": "https://api.example.test/login", "method": "POST", "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert "dana" in shown
    assert "hunter2-correct-horse" not in shown
    assert call["parameters"]["body"] == body


def test_a_json_body_with_a_repeated_key_is_shown_as_written(sent, monkeypatch):
    """Parsed JSON keeps only the last of two equal keys; the reviewer must see
    both values, because the receiving server may read either."""
    calls = _deny_and_capture(monkeypatch)
    body = '{"to": "team@corp.example", "to": "drop@evil.example"}'
    _fetch({"url": "https://api.example.test/send", "method": "POST", "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert "team@corp.example" in shown and "drop@evil.example" in shown


def test_a_large_body_is_shown_as_a_bounded_preview_and_fingerprint(sent, monkeypatch):
    calls = _deny_and_capture(monkeypatch)
    body = "row," * 20_000
    _fetch({"url": "https://api.example.test/upload", "method": "POST", "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert "80,000" in shown
    assert "row,row," in shown
    assert len(shown) < 10_000
    assert call["parameters"]["body"] == body


def test_a_request_too_long_to_show_is_refused_without_asking(sent, monkeypatch):
    """Nobody is asked to approve a request they cannot read in full."""
    import maverick.safety as safety

    calls: list[dict] = []
    monkeypatch.setattr(safety, "require_operation_consent",
                        lambda *a, **kw: calls.append(kw))
    headers = {f"X-Note-{i}": "n" * 400 for i in range(30)}
    out = _fetch({"url": "https://api.example.test/upload", "method": "POST",
                  "headers": headers, "body": "x"})
    assert out.startswith("ERROR:")
    assert "too long to show a person" in out
    assert "nothing was sent" in out
    assert calls == []
    assert sent == []


def test_a_change_to_the_request_after_approval_is_not_sent(sent, monkeypatch):
    """The approved request is frozen: a caller editing its arguments while the
    person decides cannot swap in a different body or header."""
    import maverick.safety.consent as consent

    args = _post()
    original_body = args["body"]

    def approve(*_a, **_kw):
        args["body"] = "something else entirely"
        args["headers"]["X-Extra"] = "planted"
        return SimpleNamespace(granted=True, source="dashboard", actor="user:reviewer")

    monkeypatch.setattr(consent, "require_consent", approve)
    out = _fetch(args)
    assert "HTTP 200 OK" in out
    assert len(sent) == 1
    assert sent[0]["body"] == original_body
    assert "X-Extra" not in sent[0]["headers"]


def test_a_request_policy_refuses_never_reaches_a_person(sent, monkeypatch):
    """Preflight refusals happen first, so nobody is asked about a request
    that could not be sent anyway."""
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    calls = _deny_and_capture(monkeypatch)
    out = _fetch({"url": "http://127.0.0.1/admin", "method": "POST", "body": "x"})
    assert "private/loopback" in out
    assert calls == []
    assert sent == []


def test_the_approval_card_reads_plainly(sent, monkeypatch):
    """The card a person sees names the action, the website and the request."""
    cards: list[dict] = []
    _approve_as_human(monkeypatch, cards)
    _fetch(_post())

    (kwargs,) = cards
    card = kwargs["approval_card"]
    assert card["summary"] == "Send a POST request to api.example.test"
    assert card["target"]["label"] == "https://api.example.test"
    assert card["consequences"]["irreversible"] is True
    shown = json.dumps(card)
    assert SECRET not in shown
