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


def test_keyed_secrets_in_a_large_json_body_are_hidden_from_its_preview(sent, monkeypatch):
    """A body too long to show in full is previewed after the same field
    redaction, while its fingerprint still fixes the exact body sent."""
    calls = _deny_and_capture(monkeypatch)
    body = json.dumps({"password": "hunter2-correct-horse", "payload": "x" * 5000})  # pragma: allowlist secret
    _fetch({"url": "https://api.example.test/login", "method": "POST", "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert "hunter2-correct-horse" not in shown
    assert "[REDACTED:sensitive field]" in shown
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert f"{len(body):,}" in shown
    assert call["parameters"]["body"] == body


@pytest.mark.parametrize("filler", ["", "&note=" + "x" * 5000], ids=["short", "long"])
def test_keyed_secrets_in_a_form_body_are_hidden(sent, monkeypatch, filler):
    calls = _deny_and_capture(monkeypatch)
    body = "user=dana&password=hunter2-correct-horse" + filler  # pragma: allowlist secret
    _fetch({"url": "https://api.example.test/login", "method": "POST",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert "user=dana" in shown
    assert "hunter2-correct-horse" not in shown
    assert call["parameters"]["body"] == body


@pytest.mark.parametrize("headers,body", [
    ({}, json.dumps({"token": "Z" * 100_000, "to": "x"})),  # pragma: allowlist secret
    ({"Content-Type": "application/x-www-form-urlencoded"}, "password=" + "Z" * 100_000 + "&to=x"),  # pragma: allowlist secret
], ids=["json", "form"])
def test_a_long_body_keeps_its_size_and_fingerprint_when_hiding_shortens_it(sent, monkeypatch, headers, body):
    """Whether a body is shown in full is decided on the body that will be
    sent: hiding a long value must not make a large upload look small."""
    calls = _deny_and_capture(monkeypatch)
    _fetch({"url": "https://api.example.test/upload", "method": "POST", "headers": headers, "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert f"{len(body):,} characters" in shown
    assert "ZZZZ" not in shown


def test_compact_json_that_fits_is_shown_in_full(sent, monkeypatch):
    # The card spaces each boundary, so the body must fit as the card shows it.
    calls = _deny_and_capture(monkeypatch)
    body = "[" + ",".join(["1"] * 900) + "]"
    _fetch({"url": "https://api.example.test/upload", "method": "POST", "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert "body_sha256" not in shown and "body_preview" not in shown
    assert shown.count("1, 1, ") > 0


def test_a_preview_of_non_ascii_text_is_cut_between_characters(sent, monkeypatch):
    """The preview is cut from readable text, not from an escaped copy of it,
    and the note does not compare lengths of two different strings."""
    calls = _deny_and_capture(monkeypatch)
    body = json.dumps({"text": "\u00e9" * 1000}, ensure_ascii=False)
    _fetch({"url": "https://api.example.test/upload", "method": "POST", "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert f"The body has {len(body):,} characters" in shown
    assert "\\u00e9\\u00e9" in shown  # the card escapes each character once
    assert "\\\\u00e9" not in shown  # never twice


@pytest.mark.parametrize("filler", ["", ', "payload": "' + "x" * 5000 + '"'], ids=["short", "long"])
def test_a_json_body_with_a_repeated_key_still_hides_sensitive_values(sent, monkeypatch, filler):
    calls = _deny_and_capture(monkeypatch)
    body = ('{"password": "hunter2-correct-horse", "to": "team@corp.example", '  # pragma: allowlist secret
            '"to": "drop@evil.example"' + filler + "}")
    _fetch({"url": "https://api.example.test/send", "method": "POST", "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert "hunter2-correct-horse" not in shown
    assert "team@corp.example" in shown and "drop@evil.example" in shown
    assert call["parameters"]["body"] == body


@pytest.mark.parametrize("body", ["[" * 990 + "]" * 990, '{"a":' * 900 + "1" + "}" * 900, "[" * 5000 + "]" * 5000],
                         ids=["array", "object", "beyond-the-parser"])
def test_a_deeply_nested_body_is_refused_cleanly(sent, body):
    out = _fetch({"url": "https://api.example.test/upload", "method": "POST", "body": body})
    assert out.startswith("ERROR:") and "nothing was sent" in out
    assert sent == []


def test_the_card_says_which_bodies_have_values_hidden(sent, monkeypatch):
    calls = _deny_and_capture(monkeypatch)
    body = '--b\r\nContent-Disposition: form-data; name="note"\r\n\r\nhello\r\n--b--\r\n'
    _fetch({"url": "https://api.example.test/upload", "method": "POST",
            "headers": {"Content-Type": "multipart/form-data; boundary=b"}, "body": body})

    (call,) = calls
    shown = "\n".join(call["parameter_summary"])
    assert "JSON and form bodies" in shown and "Any other body is shown as written" in shown


def _card(monkeypatch, body, headers=None, url="https://api.example.test/upload"):
    calls = _deny_and_capture(monkeypatch)
    out = _fetch({"url": url, "method": "POST", "headers": headers or {}, "body": body})
    assert len(calls) == 1, out  # a person was asked, not refused before
    return "\n".join(calls[0]["parameter_summary"])


@pytest.mark.parametrize("headers,body", [
    ({"Content-Type": "application/x-www-form-urlencoded"}, "password=a&" * 270),  # pragma: allowlist secret
    ({}, "[" + ",".join(["1e15"] * 595) + "]"),
    ({}, json.dumps({"token": [1] * 1200}, separators=(",", ":"))),
], ids=["form", "exponents", "short-values"])
def test_hiding_values_never_pushes_a_short_body_off_the_card(sent, monkeypatch, headers, body):
    _card(monkeypatch, body, headers)


@pytest.mark.parametrize("body", [
    '{"q":"weather"}' + " \t" * 50_000,
    '{"v":0.' + "1" * 100_000 + "}",
], ids=["whitespace", "digits"])
def test_padding_does_not_make_a_large_body_look_small(sent, monkeypatch, body):
    shown = _card(monkeypatch, body)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert f"{len(body):,} characters" in shown


@pytest.mark.parametrize("body", [
    "\ufeff" + json.dumps({"password": "hunter2-correct-horse", "a": 1}),  # pragma: allowlist secret
    '{"password": "hunter2-correct-horse", "n": ' + "1" * 4301 + "}",  # pragma: allowlist secret
    json.dumps({"password": {"hunter2-correct-horse": True}, "user": "alice"}),  # pragma: allowlist secret
], ids=["byte-order-mark", "long-integer", "secret-held-as-a-key"])
def test_sensitive_values_in_any_json_body_are_hidden(sent, monkeypatch, body):
    shown = _card(monkeypatch, body)
    assert "hunter2-correct-horse" not in shown


def test_the_address_fragment_is_not_shown_because_it_is_never_sent(sent, monkeypatch):
    shown = _card(monkeypatch, "x", url="https://api.example.test/cb?page=2#access_token=hunter2&type=bearer")
    assert "hunter2" not in shown and "#" not in shown.split("Request part")[1]
    assert "https://api.example.test/cb?page=2" in shown


def test_a_body_that_cannot_be_encoded_is_refused_cleanly(sent):
    out = _fetch({"url": "https://api.example.test/upload", "method": "POST", "body": "x\ud800" * 2000})
    assert out.startswith("ERROR:") and "nothing was sent" in out
    assert sent == []


def test_a_long_json_body_is_read_only_as_far_as_the_preview_needs(sent, monkeypatch):
    """Rendering what the reviewer reads stops once the preview is full, so a
    body of many megabytes costs no more to show than a short one."""
    import maverick.governed_tools as governed_tools

    real, checked = governed_tools._sensitive_request_key, []
    monkeypatch.setattr(governed_tools, "_sensitive_request_key",
                        lambda key: checked.append(key) or real(key))
    body = json.dumps([{"row": index, "note": "n"} for index in range(100_000)])
    shown = _card(monkeypatch, body)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert 0 < len(checked) < 2_000


@pytest.mark.parametrize("body", [
    '{"user": "dana", "password": "hunter2-correct-horse"}',  # pragma: allowlist secret
    '[{"token": "hunter2-correct-horse"}]',  # pragma: allowlist secret
    json.dumps({"password": "hunter2-correct-horse", "pad": "p" * 5000}),  # pragma: allowlist secret
    '{"note":"x&password=hunter2-correct-horse&y=1"}',  # pragma: allowlist secret
], ids=["object", "array", "long", "pairs-inside"])
def test_a_json_body_declared_as_a_form_is_refused_before_anyone_is_asked(sent, monkeypatch, body):
    """A server may read such a body as JSON or as a form, and the two readings
    hide different values, so it is refused with the fix to make."""
    import maverick.safety as safety

    asked: list[dict] = []
    monkeypatch.setattr(safety, "require_operation_consent", lambda *a, **kw: asked.append(kw))
    out = _fetch({"url": "https://api.example.test/upload", "method": "POST", "body": body,
                  "headers": {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}})
    assert out.startswith("ERROR:") and "application/json" in out and "nothing was sent" in out
    assert asked == [] and sent == []


def test_a_large_numeric_body_is_read_only_as_far_as_the_preview_needs(sent, monkeypatch):
    """The body is not parsed whole: its tokens are read until the preview is
    full, so a large numeric body costs what a short one does."""
    import maverick.tools.http_fetch as http_fetch_module

    real, reads = http_fetch_module._JSON_TOKEN, []

    class Counted:
        def match(self, text, position):
            reads.append(position)
            return real.match(text, position)

    monkeypatch.setattr(http_fetch_module, "_JSON_TOKEN", Counted())
    body = json.dumps(list(range(500_000)))
    shown = _card(monkeypatch, body)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert 0 < len(reads) < 10_000


@pytest.mark.parametrize("url,headers,body", [
    ("https://api.example.test/x?a=1;password=hunter2-correct-horse", {}, "x"),  # pragma: allowlist secret
    ("https://api.example.test/x", {"Content-Type": "application/x-www-form-urlencoded"},
     "a=1;password=hunter2-correct-horse"),  # pragma: allowlist secret
], ids=["query", "form"])
def test_pairs_separated_by_semicolons_are_hidden_too(sent, monkeypatch, url, headers, body):
    shown = _card(monkeypatch, body, headers, url=url)
    assert "hunter2-correct-horse" not in shown and "a=1" in shown


def test_a_connection_string_in_the_body_does_not_hide_the_rest_of_the_request(sent, monkeypatch):
    body = '{"replica":"redis://u:p@cache","dump":"customer_list"}'  # pragma: allowlist secret
    shown = _card(monkeypatch, body, {"X-Mirror": "https://other.example/in"},
                  url="https://api.example.test/v1/import?carry=data")
    assert "u:p@" not in shown
    assert "customer_list" in shown and "X-Mirror" in shown and "/v1/import?carry=data" in shown


@pytest.mark.parametrize("args", [
    {"body": {"a": 1}},
    {"body": [1, 2]},
    {"body": 5},
    {"body": "x", "headers": {"X-Count": 5}},
    {"body": "x", "headers": {"X-Note": "caf\u00e9"}},
    {"body": "x", "headers": {"Content-Type": ["application/x-www-form-urlencoded"]}},
    {"body": "x", "headers": ["X-Note: hello"]},
    {"body": "x", "headers": {"X-A": "b\r\nX-Evil: c"}},
    {"body": "x", "headers": {"X-A": "b\x00c"}},
    {"body": "x", "headers": {"Bad Name": "v"}},
    {"body": "x", "headers": {"": "v"}},
    {"body": "x", "headers": {"X:Y": "v"}},
    {"body": "x", "method": 5},
    {"body": "x", "headers": {"X-A": " lead"}},
    {"body": "x", "headers": {"X-A": "trail "}},
    {"body": "xx", "headers": {"Content-Length": "1"}},
    {"body": "x", "headers": {"Transfer-Encoding": "gzip"}},
], ids=["object-body", "array-body", "number-body", "number-header", "non-ascii-header",
        "list-header", "header-list", "line-break-header", "nul-header", "spaced-name",
        "empty-name", "colon-name", "number-method", "leading-space", "trailing-space",
        "content-length", "transfer-encoding"])
def test_a_request_that_cannot_be_sent_is_refused_before_anyone_is_asked(sent, monkeypatch, args):
    import maverick.safety as safety

    asked: list[dict] = []
    monkeypatch.setattr(safety, "require_operation_consent", lambda *a, **kw: asked.append(kw))
    out = _fetch({"url": "https://api.example.test/upload", "method": "POST", **args})
    assert out.startswith("ERROR:") and "nothing was sent" in out
    assert asked == [] and sent == []


# A secret pattern only ever hides text inside one value: a header value, a
# part of the address, a JSON string, a form pair or a plain-text body. A match
# that would run from one value into the next is not hidden, so it cannot hide
# the fields, headers or address between them.
_AZURE_START = "DefaultEndpointsProtocol=https;AccountName="
_AZURE_KEY = ";AccountKey=" + "A" * 40


@pytest.mark.parametrize("url,headers,body", [
    ("https://api.example.test/v1/import/" + _AZURE_KEY, {"X-Mirror": "https://other.example/in"},
     _AZURE_START + "x"),
    ("https://api.example.test/v1/import", {"X-Mirror": "https://other.example/in", "X-Z": "-----END PRIVATE KEY-----"},
     "note: -----BEGIN PRIVATE KEY----- x"),
    ("https://api.example.test/v1/import", {"Accept": "*", "User-Agent": "agent", "X-Mirror": "a@b"},
     "redis://a"),
], ids=["azure-body-to-address", "key-body-to-header", "uri-body-to-headers"])
def test_a_secret_pattern_cannot_run_from_the_body_into_the_headers_or_address(sent, monkeypatch, url, headers, body):
    shown = _card(monkeypatch, body, headers, url=url)
    assert "X-Mirror" in shown and "/import" in shown


@pytest.mark.parametrize("body", [
    json.dumps({"conn": _AZURE_START, "to": "drop@evil.example", "data": "customer_list", "z": _AZURE_KEY}),
    json.dumps({"a": "-----BEGIN PRIVATE KEY-----", "to": "drop@evil.example", "data": "customer_list",
                "b": "-----END PRIVATE KEY-----"}),
    json.dumps({"cache": "redis://localhost", "to": "drop@evil.example", "data": "customer_list"}),
], ids=["azure", "private-key", "connection-uri"])
def test_a_secret_pattern_cannot_hide_json_fields_between_two_values(sent, monkeypatch, body):
    shown = _card(monkeypatch, body)
    assert "drop@evil.example" in shown and "customer_list" in shown


def test_a_form_pair_with_a_connection_string_hides_only_its_own_value(sent, monkeypatch):
    body = "replica=redis://u:p@cache&dump=customer_list&to=drop@evil.example"  # pragma: allowlist secret
    shown = _card(monkeypatch, body, {"Content-Type": "application/x-www-form-urlencoded"})
    assert "u:p@" not in shown
    assert "dump=customer_list" in shown and "to=drop@evil.example" in shown


@pytest.mark.parametrize("body", [
    "-----BEGIN PRIVATE KEY-----\n" + "AAECAwQFBgcICQoLDA0ODxAREhMU\n" * 300 + "-----END PRIVATE KEY-----\n",
    json.dumps({"key": "-----BEGIN PRIVATE KEY-----\n" + "AAECAwQFBgcICQoLDA0ODxAREhMU\n" * 300 + "-----END PRIVATE KEY-----"}),
    "FOO=1\nINTERNAL_API_TOKEN=Zq8vT3pLmN0xR7wK2yB5\nBAR=2\n",  # pragma: allowlist secret
    json.dumps({"pad": "x" * 2940, "replica": "redis://admin:S3cretPassw0rdQ@cache.internal:6379/0",  # pragma: allowlist secret
                "more": "y" * 5000}),
    "x" * 2967 + " redis://admin:S3cretPassw0rdQ@cache.internal:6379/0 " + "y" * 5000,  # pragma: allowlist secret
], ids=["long-key", "long-key-in-json", "env-line", "uri-at-the-cut", "uri-at-the-cut-in-text"])
def test_secrets_are_hidden_in_the_body_as_written_before_the_preview_is_cut(sent, monkeypatch, body):
    shown = _card(monkeypatch, body)
    assert "AAECAwQFBgcICQoLDA0ODxAREhMU" not in shown
    assert "Zq8vT3pLmN0xR7wK2yB5" not in shown and "S3cretPassw0rdQ" not in shown


@pytest.mark.parametrize("headers", [
    {"Content-Type": "text/plain", "content-type": "application/x-www-form-urlencoded"},
    {"Content-Type": "application/x-www-form-urlencoded,text/plain"},
    {"Content-Type": "Application/X-WWW-Form-Urlencoded text/plain"},
], ids=["second-header", "comma", "space"])
def test_any_content_type_naming_a_form_makes_the_body_a_form(sent, monkeypatch, headers):
    shown = _card(monkeypatch, "user=dana&password=hunter2-correct-horse", headers)  # pragma: allowlist secret
    assert "hunter2-correct-horse" not in shown and "user=dana" in shown


@pytest.mark.parametrize("body", [
    "[" + ",".join(["1e15"] * 400) + "]",
    '{"amount": 1E400, "small": 1e-400, "exact": 9007199254740993.0, "zero": -0}',
], ids=["exponents", "unusual-numbers"])
def test_json_numbers_are_shown_as_written(sent, monkeypatch, body):
    shown = _card(monkeypatch, body)
    assert "body_sha256" not in shown
    for written in ("1e15", "1E400", "1e-400", "9007199254740993.0", "-0"):
        if written in body:
            assert written in shown


@pytest.mark.parametrize("url", [
    "https://[::1/x",
    "https://a.test]/x",
    "https://api.example.test/x?pass\tword=1",
    "https://api.example.test:abc/x",
    "https://api.example.test:99999/x",
    "https://api.example.test/a b",
    "https://\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com/v1/import",
    "https://\u2603.net/",
], ids=["open-bracket", "stray-bracket", "tab", "port-word", "port-range", "space", "fullwidth-host",
        "symbol-host"])
def test_an_address_that_cannot_be_sent_is_refused_before_anyone_is_asked(sent, monkeypatch, url):
    import maverick.safety as safety

    asked: list[dict] = []
    monkeypatch.setattr(safety, "require_operation_consent", lambda *a, **kw: asked.append(kw))
    out = _fetch({"url": url, "method": "POST", "body": "x"})
    assert out.startswith("ERROR:") and "nothing was sent" in out
    assert asked == [] and sent == []


def test_a_large_hidden_value_does_not_stall_the_card(sent, monkeypatch):
    """A huge value under a sensitive key is skipped, not rendered, and the
    card still shows the fields after it."""
    body = '{"token": [' + ",".join(['{"a": 1}'] * 300_000) + '], "to": "drop@evil.example"}'
    shown = _card(monkeypatch, body)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert '"a": 1' not in shown


def test_nothing_after_a_string_too_long_to_show_appears_as_if_it_followed(sent, monkeypatch):
    """A string longer than the preview is shown only in part, and reading
    stops there, so the card never shows a later field after a cut string."""
    body = json.dumps({"text": "\u00e9" * 3000, "to": "drop@evil.example"})
    shown = _card(monkeypatch, body)
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert "drop@evil.example" not in shown


def _real_card(monkeypatch, body, headers=None, url="https://api.example.test/v1/import"):
    """The card a person sees, after the card builder's own checks, and
    checked again as a stored card is."""
    from maverick.approval_cards import validate_approval_card

    cards: list[dict] = []
    _approve_as_human(monkeypatch, cards)
    _fetch({"url": url, "method": "POST", "headers": headers or {}, "body": body})
    (kwargs,) = cards
    validate_approval_card(kwargs["approval_card"])
    summary = kwargs["approval_card"]["parameters"]["summary"]
    # The request is shown in numbered parts; rejoin them to read it whole.
    request = "".join(line.split(": ", 1)[1] for line in summary if line.startswith("Request part "))
    return "\n".join(summary) + "\n" + request


@pytest.mark.parametrize("headers,body", [
    ({"Accept": "*", "User-Agent": "agent", "X-Mirror": "a@b", "X-To": "drop@evil.example"}, "redis://a"),
    ({"X-Mirror": "drop@evil.example"},
     json.dumps({"conn": _AZURE_START, "to": "drop@evil.example", "data": "customer_list", "z": _AZURE_KEY})),
    ({"X-Mirror": "drop@evil.example"},
     '{"cache":"redis://localhost","owner":"ops@corp.example","to":"drop@evil.example","data":"customer_list"}'),
    ({"X-Mirror": "drop@evil.example"}, '["redis://u:p", "q@h", "drop@evil.example", "customer_list"]'),
], ids=["uri-body-to-headers", "azure-across-fields", "uri-across-fields", "uri-across-items"])
def test_the_card_a_person_sees_keeps_every_value(sent, monkeypatch, headers, body):
    shown = _real_card(monkeypatch, body, headers)
    assert "X-Mirror" in shown and "drop@evil.example" in shown and "/v1/import" in shown
    if "customer_list" in body:
        assert "customer_list" in shown


def test_two_header_names_hidden_alike_stay_two_headers(sent, monkeypatch):
    headers = {"AKIAIOSFODNN7EXAMPLE": "forward-to=drop@evil.example",  # pragma: allowlist secret
               "AKIAI44QH8DHBEXAMPLE": "second"}  # pragma: allowlist secret
    shown = _real_card(monkeypatch, "hello", headers)
    assert "drop@evil.example" in shown and "second" in shown
    assert "AKIAIOSFODNN7EXAMPLE" not in shown


@pytest.mark.parametrize("body", [
    '{"password":"hunter2-correct-horse","x":NaN}',  # pragma: allowlist secret
    '{"x":Infinity,"password":"hunter2-correct-horse"}',  # pragma: allowlist secret
    '{"password":"hunter2-correct-horse","x":-Infinity}',  # pragma: allowlist secret
], ids=["nan", "infinity", "negative-infinity"])
def test_json_with_nan_or_infinity_is_still_read_as_json(sent, monkeypatch, body):
    assert "hunter2-correct-horse" not in _card(monkeypatch, body)


_AWS_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # pragma: allowlist secret


@pytest.mark.parametrize("body", [
    "redis://a:b@" + "x" * 5926 + " aws_secret_access_key=" + _AWS_EXAMPLE_SECRET + " and more " + "y" * 3000,
    json.dumps({"note": "redis://a:b@" + "x" * 5926 + " aws_secret_access_key=" + _AWS_EXAMPLE_SECRET
                + " and more " + "y" * 3000}),
], ids=["text", "json-string"])
def test_a_secret_cut_by_the_read_never_reaches_the_card(sent, monkeypatch, body):
    assert _AWS_EXAMPLE_SECRET[:20] not in _card(monkeypatch, body)


@pytest.mark.parametrize("url", [
    "https://api.example.test/upload/redis://a:b@" + "customer_list_" * 40_000,
    "https://api.example.test/upload?q=redis://a:b@" + "customer_list_" * 40_000,
], ids=["path", "query"])
def test_an_address_too_long_to_show_is_refused_by_its_sent_length(sent, monkeypatch, url):
    import maverick.safety as safety

    asked: list[dict] = []
    monkeypatch.setattr(safety, "require_operation_consent", lambda *a, **kw: asked.append(kw))
    out = _fetch({"url": url, "method": "POST", "body": "x"})
    assert out.startswith("ERROR:") and "too long" in out and asked == []


def test_a_long_form_value_is_read_only_as_far_as_the_preview_needs(sent, monkeypatch):
    import maverick.safety.secret_detector as detector

    real, scanned = detector.redact, []
    monkeypatch.setattr(detector, "redact", lambda text: scanned.append(len(text)) or real(text))
    body = "a=" + "-----BEGIN PRIVATE KEY-----" * 40_000
    shown = _card(monkeypatch, body, {"Content-Type": "application/x-www-form-urlencoded"})
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert sum(scanned) < 200_000


_GITHUB_EXAMPLE = "ghp_" + "Ab3" * 12  # pragma: allowlist secret


@pytest.mark.parametrize("url,headers,body", [
    ("https://api.example.test/u?" + _GITHUB_EXAMPLE + "-token=1", {}, "x"),
    ("https://api.example.test/u", {"Content-Type": "application/x-www-form-urlencoded"},
     _GITHUB_EXAMPLE + "-token=1&a=2"),
    ("https://api.example.test/u", {"Content-Type": "application/x-www-form-urlencoded"},
     "note=AKIAIOSFODNN7EXAMPLE%20" + _GITHUB_EXAMPLE),  # pragma: allowlist secret
], ids=["query-name", "form-name", "decoded-next-to-another"])
def test_secrets_in_pair_names_and_decoded_values_are_hidden(sent, monkeypatch, url, headers, body):
    assert _GITHUB_EXAMPLE not in _card(monkeypatch, body, headers, url=url)


_FORM = {"Content-Type": "application/x-www-form-urlencoded"}


@pytest.mark.parametrize("url,headers,body,hidden,kept", [
    ("https://api.example.test/v1/login?user=dana&password=Tr0ub4dor;horse-battery-staple", {}, "x",  # pragma: allowlist secret
     "horse-battery-staple", "user=dana"),
    ("https://api.example.test/v1/token", _FORM,
     "client_secret=k9;Zq8vT3pLmN0xR7wK2yB5&grant_type=client_credentials",  # pragma: allowlist secret
     "Zq8vT3pLmN0xR7wK2yB5", "grant_type=client_credentials"),
], ids=["query", "form"])
def test_a_sensitive_value_is_hidden_through_to_the_next_ampersand(sent, monkeypatch, url, headers, body, hidden, kept):
    shown = _real_card(monkeypatch, body, headers, url=url)
    assert hidden not in shown and kept in shown


@pytest.mark.parametrize("url,headers,body", [
    ("https://api.example.test/v1/import", _FORM,
     "replica=redis://cache:6379&notify=drop@evil.example&dump=customer_list"),
    ("https://api.example.test/v1/import?db=postgres://db.internal:5432&to=drop@evil.example&what=customer_list",
     {}, "x"),
    ("https://api.example.test/v1/import/redis://u:p?to=drop@evil.example&dump=customer_list", {}, "x"),
    ("https://api.example.test/v1/import", _FORM, "DB_PASS=hunter2&to=drop@evil.example&dump=customer_list"),
    ("https://api.example.test/v1/import", _FORM, "MONKEY=banana&to=drop@evil.example&dump=customer_list"),
    ("https://api.example.test/v1/import", {},
     json.dumps({"mirror": ["redis://cache:6379", "ops@corp.example", "drop@evil.example"],
                 "dataset": "customer_list"}, indent="\t")),
    ("https://api.example.test/v1/import", {},
     json.dumps({"mirror": ["redis://cache:6379", "ops@corp.example", "drop@evil.example"],
                 "dataset": "customer_list"}, indent=0)),
    ("https://api.example.test/v1/import", {},
     '{"a":"redis:\\/\\/cache:6379","b":"ops@corp.example","c":"drop@evil.example","d":"customer_list"}'),
], ids=["form-uri", "query-uri", "path-into-query", "env-like-first-pair", "env-like-name",
        "tab-indented-json", "indent-zero-json", "escaped-scheme"])
def test_no_pattern_on_the_card_runs_across_pairs_lines_or_values(sent, monkeypatch, url, headers, body):
    shown = _real_card(monkeypatch, body, headers, url=url)
    assert "drop@evil.example" in shown and "customer_list" in shown


@pytest.mark.parametrize("body", [
    '{"password' + "x" * 7000 + '": "hunter2-correct-horse"}',  # pragma: allowlist secret
    '{"index": {}}\n{"password": "hunter2-correct-horse"}\n',  # pragma: allowlist secret
], ids=["key-too-long-to-read", "ndjson"])
def test_more_json_shapes_still_hide_sensitive_values(sent, monkeypatch, body):
    assert "hunter2-correct-horse" not in _card(monkeypatch, body)


def test_a_long_address_with_a_short_body_is_still_shown(sent, monkeypatch):
    _card(monkeypatch, "x", url="https://api.example.test/" + "segment/" * 600)


def test_connector_requests_with_many_small_fields_still_fit_the_card(sent):
    from maverick.governed_tools import _approval_request_parts

    parts = _approval_request_parts({f"k{index}": 1 for index in range(800)})
    assert 0 < len(parts) <= 20 and all(len(part) <= 500 for part in parts)


def test_a_long_line_is_read_only_as_far_as_the_preview_needs(sent, monkeypatch):
    import maverick.safety.secret_detector as detector

    real, scanned = detector.redact, []
    monkeypatch.setattr(detector, "redact", lambda text: scanned.append(len(text)) or real(text))
    _card(monkeypatch, "A" * 200_000)
    assert sum(scanned) < 50_000


@pytest.mark.parametrize("args", [{"url": 5}, {"url": "https://api.example.test/x", "render": 5}],
                         ids=["url", "render"])
def test_arguments_that_are_not_text_are_refused(sent, args):
    out = _fetch({"method": "POST", "body": "x", **args})
    assert out.startswith("ERROR:") and sent == []


@pytest.mark.parametrize("body", [
    "MONKEY='&to=drop@evil.example&dump=customer_list&note='",
    'MONKEY="&to=drop@evil.example&dump=customer_list&note="',
    "MONKEY=';to=drop@evil.example&dump=customer_list&note='",
], ids=["single-quote", "double-quote", "semicolon"])
def test_a_quoted_env_style_first_pair_hides_only_itself(sent, monkeypatch, body):
    shown = _real_card(monkeypatch, body, _FORM)
    assert "drop@evil.example" in shown and "customer_list" in shown


@pytest.mark.parametrize("url,headers,body", [
    ("https://api.example.test/v1/import", _FORM, "a=" + "b=1;" * 1500),
    ("https://api.example.test/v1/items?f=" + "a=1;" * 1100, {}, "x"),
    ("https://api.example.test/v1/search?" + "&".join(f"f{index}=1" for index in range(800)), {}, "x"),
], ids=["semicolon-form", "semicolon-query", "many-query-pairs"])
def test_many_pairs_or_parts_are_still_shown(sent, monkeypatch, url, headers, body):
    _card(monkeypatch, body, headers, url=url)


def test_a_long_form_body_of_semicolon_parts_stays_small_in_memory(sent, monkeypatch):
    import tracemalloc

    body = "a=" + ";".join(["b=c"] * 400) + ";z=" + "x" * 1_000_000
    tracemalloc.start()
    try:
        shown = _card(monkeypatch, body, _FORM)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert hashlib.sha256(body.encode("utf-8")).hexdigest() in shown
    assert peak < 60_000_000, peak


@pytest.mark.parametrize("args", [{"ids": [7] * 3300}, {"rows": [[1, 2]] * 1200}], ids=["integers", "pairs"])
def test_connector_requests_with_dense_arrays_still_fit_the_card(sent, args):
    from maverick.governed_tools import _approval_request_parts

    parts = _approval_request_parts(args)
    assert 0 < len(parts) <= 20 and all(len(part) <= 500 for part in parts)


@pytest.mark.parametrize("url", ["https://a..example/v1", "https://" + "a" * 64 + ".example/v1"],
                         ids=["empty-label", "long-label"])
def test_a_host_that_cannot_be_encoded_is_refused(sent, url):
    out = _fetch({"url": url, "method": "POST", "body": "x"})
    assert out.startswith("ERROR:") and sent == []


_BEGIN_SPACED = "-----BEGIN  PRIVATE KEY-----"
_END = "-----END PRIVATE KEY-----"


@pytest.mark.parametrize("headers,body", [
    ({"X-Mirror": "drop@evil.example"},
     json.dumps({"a": _BEGIN_SPACED, "to": "drop@evil.example", "dataset": "customer_list", "z": _END})),
    ({"X-Mirror": "drop@evil.example"},
     json.dumps({"a": _BEGIN_SPACED.replace("  ", "\u00a0"), "to": "drop@evil.example",
                 "dataset": "customer_list", "z": _END}, ensure_ascii=False)),
    (dict(_FORM, **{"X-Mirror": "drop@evil.example"}),
     "a=" + _BEGIN_SPACED + "&to=drop@evil.example&dump=customer_list&z=" + _END),
    ({"X-A": _BEGIN_SPACED, "X-Mirror": "drop@evil.example", "X-Z": _END}, "customer_list"),
], ids=["json", "json-no-break-space", "form", "headers"])
def test_a_key_marker_that_forms_only_once_spacing_collapses_hides_only_its_value(sent, monkeypatch, headers, body):
    shown = _real_card(monkeypatch, body, headers)
    assert "drop@evil.example" in shown and "customer_list" in shown


def test_connector_key_markers_that_form_on_the_card_hide_only_their_value(sent):
    from maverick.approval_cards import _label
    from maverick.governed_tools import _approval_request_parts

    parts = _approval_request_parts({"note": _BEGIN_SPACED, "recipient": "drop@evil.example", "z": _END})
    assert "drop@evil.example" in "".join(_label(part, "part") for part in parts)


def test_a_connection_scheme_in_a_long_address_still_fits_the_card(sent, monkeypatch):
    url = ("https://api.example.test/v1/search?" + "&".join(f"f{index}=1" for index in range(900))
           + "&cache=redis://cache.internal")
    _card(monkeypatch, "x", url=url)


@pytest.mark.parametrize("url,headers,body", [
    ("https://api.example.test/u?ghp%5F" + "Ab3" * 12, {}, "x"),
    ("https://api.example.test/u?ghp%5F" + "Ab3" * 12 + "=1", {}, "x"),
    ("https://api.example.test/u", _FORM, "ghp%5F" + "Ab3" * 12 + "=1&a=1"),
], ids=["bare-query-item", "query-name", "form-name"])
def test_percent_encoded_secrets_in_names_are_hidden(sent, monkeypatch, url, headers, body):
    assert "Ab3Ab3Ab3Ab3" not in _card(monkeypatch, body, headers, url=url)


@pytest.mark.parametrize("headers,body", [
    (_FORM, "name=prod-cert&forward_to=drop@evil.example&certificate=" + "QUJD%2B" * 1800),
    ({}, "Send to drop@evil.example\n-----BEGIN PRIVATE KEY-----\n" + ("QUJDREVG" * 8 + "\n") * 180
     + "-----END PRIVATE KEY-----"),
], ids=["form", "text"])
def test_a_preview_keeps_what_comes_before_a_long_hidden_value(sent, monkeypatch, headers, body):
    shown = _card(monkeypatch, body, headers)
    assert "body_sha256" in shown and "drop@evil.example" in shown


def test_a_body_that_fits_with_long_headers_is_still_shown(sent, monkeypatch):
    body = json.dumps({f"field_{index}": index for index in range(150)}, separators=(",", ":"))
    _card(monkeypatch, body, {"Content-Type": "application/json", "Cookie": "session=" + "c" * 4700})


@pytest.mark.parametrize("url,headers,body,kept", [
    ("https://api.example.test/v1/sms", _FORM,
     "To=%2B15551234567&From=%2B15557654321&Body=Meeting+moved+to+3pm.%0AReply+YES+to+confirm.",
     "Body=Meeting+moved+to+3pm.%0AReply+YES+to+confirm."),
    ("https://api.example.test/v1/c", _FORM, "comment=Great++work&city=New+York+&note=a%09b&p=Prix%C2%A0%3A+10",
     "comment=Great++work"),
    ("https://api.example.test/v1/c", _FORM, "first++name=Alice", "first++name=Alice"),
    ("https://api.example.test/v1/s?q=line1%0Aline2&page=2", {}, "x", "q=line1%0Aline2"),
], ids=["encoded-newline", "spacing", "spaced-name", "query-newline"])
def test_ordinary_encoded_spacing_is_shown_as_written(sent, monkeypatch, url, headers, body, kept):
    shown = _real_card(monkeypatch, body, headers, url=url)
    assert kept in shown and "[REDACTED:secret]" not in shown


@pytest.mark.parametrize("headers,body,start", [
    (_FORM, "subject=Quarterly+report&message=" + "We+are+sending+the+report+" * 600, "message=We+are+sending"),
    ({}, "Report: " + "A" * 12_000, "Report: AAAA"),
    ({}, json.dumps({"message": "Report: " + "A" * 12_000}), "message"),
], ids=["form", "text", "json-string"])
def test_a_long_value_still_fills_the_preview(sent, monkeypatch, headers, body, start):
    shown = _card(monkeypatch, body, headers)
    assert start in shown
    preview = shown.split('"body_preview":', 1)[1]
    assert len(preview) > 2_000


def test_a_long_escaped_string_costs_little_memory(sent, monkeypatch):
    import tracemalloc

    body = '"' + "\\n" * 2_000_000 + '"'
    tracemalloc.start()
    try:
        _card(monkeypatch, body)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 60_000_000, peak


@pytest.mark.parametrize("body", [
    "sk-" + "A" * 8970 + "." + "ghp_" + "Q7xR" * 9 + "." + "C" * 20_000,
    "sk-" + "A" * 8767 + "/token=" + "ghp_" + "Q7xR" * 9 + "/" + "y" * 20_000,
], ids=["after-a-stop", "no-stop-near-the-end"])
def test_a_token_cut_by_the_read_never_shows_in_part(sent, monkeypatch, body):
    assert "ghp_Q7xR" not in _card(monkeypatch, body)


def test_a_body_with_escaped_json_and_a_long_address_is_still_shown(sent, monkeypatch):
    url = "https://api.example.test/v1/import?" + "&".join(f"f{index}=v{index}" for index in range(520))
    inner = json.dumps({f"field{index}": f"value {index}" for index in range(60)})
    _card(monkeypatch, json.dumps({"payload": inner}), url=url)


def test_many_strings_that_hide_down_to_markers_are_read_within_a_bound(sent, monkeypatch):
    import maverick.safety.secret_detector as detector

    real, scanned = detector.redact, []
    monkeypatch.setattr(detector, "redact", lambda text: scanned.append(len(text)) or real(text))
    body = json.dumps(["-----BEGIN PRIVATE KEY-----\nA" + "KEY" * 2985] * 200)
    _card(monkeypatch, body)
    assert sum(scanned) < 300_000, sum(scanned)


@pytest.mark.parametrize("body", [
    json.dumps({"password": "hunter2-correct-horse",  # pragma: allowlist secret
                "payload": json.dumps([{"id": index} for index in range(100_000)])}),
    '{"password": "hunter2-correct-horse", "x": "' + '\\"' * 200_001 + '"}',  # pragma: allowlist secret
], ids=["embedded-document", "escaped-quotes"])
def test_a_string_too_long_to_scan_still_reads_the_body_as_json(sent, monkeypatch, body):
    assert "hunter2-correct-horse" not in _card(monkeypatch, body)


def test_a_json_body_declared_as_a_form_is_refused_however_long_its_strings(sent, monkeypatch):
    import maverick.safety as safety

    asked: list[dict] = []
    monkeypatch.setattr(safety, "require_operation_consent", lambda *a, **kw: asked.append(kw))
    body = '{"password": "hunter2-correct-horse", "x": "' + '\\"' * 200_001 + '"}'  # pragma: allowlist secret
    out = _fetch({"url": "https://api.example.test/upload", "method": "POST", "body": body, "headers": _FORM})
    assert out.startswith("ERROR:") and "application/json" in out and asked == []


_DSN_TAIL = "postgres://admin:Sup3rS3cretPassw0rd%21@db.internal/prod"  # pragma: allowlist secret


@pytest.mark.parametrize("headers,body,secret", [
    ({}, "sk-" + "A" * (9000 - len("," + _DSN_TAIL[:-16]) - 3) + "," + _DSN_TAIL + " and more" * 2000,
     "Sup3rS3cretPassw0rd"),
    ({}, json.dumps({"note": "sk-" + "A" * (9000 - len("," + _DSN_TAIL[:-16]) - 3) + "," + _DSN_TAIL
                     + " and more" * 2000}), "Sup3rS3cretPassw0rd"),
    ({}, " " * 7468 + "x" * 1500 + ";db=postgres://admin:hunter2.secret@db.example.com/app;more=" + "y" * 3000,  # pragma: allowlist secret
     "hunter2"),
    (_FORM, "certificate=" + "A" * 8942 + "&backup=postgres%3A%2F%2Fadmin%3AS3cret%21pw%40db.example.com%2Fapp"  # pragma: allowlist secret
     + "&tail=" + "z" * 3000, "S3cret"),
], ids=["text", "json-string", "text-after-spacing", "form"])
def test_a_connection_string_cut_by_the_read_never_shows_its_password(sent, monkeypatch, headers, body, secret):
    assert secret not in _card(monkeypatch, body, headers)


def test_connector_cards_hide_secrets_within_each_value(sent):
    """Governed connector approval cards share the per-value rule."""
    from maverick.governed_tools import _approval_request_parts

    parts = "\n".join(_approval_request_parts({
        "note": _AZURE_START + "x", "to": "drop@evil.example", "z": _AZURE_KEY,
        "replica": "redis://u:p@cache",  # pragma: allowlist secret
    }))
    assert "drop@evil.example" in parts and "u:p@" not in parts


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
