"""Event-trigger poll engine: cursor-based dedup, payload flattening, and the
built-in http_json source (with an injected fetch -- no network)."""
from __future__ import annotations

import pytest
from maverick import automation_events as ev


def test_first_poll_is_baseline_only():
    # Newest-first feed; empty cursor -> record newest id, fire nothing.
    items = [{"id": "3"}, {"id": "2"}, {"id": "1"}]
    r = ev.diff_new_items(items, cursor="", id_field="id")
    assert r.events == [] and ev._decode_cursor(r.cursor, "feed") == "3"


def test_only_items_after_cursor_fire_oldest_first():
    items = [{"id": "5"}, {"id": "4"}, {"id": "3"}, {"id": "2"}, {"id": "1"}]
    r = ev.diff_new_items(items, cursor="3", id_field="id")
    assert [e["id"] for e in r.events] == ["4", "5"]   # oldest-first
    assert ev._decode_cursor(r.cursor, "feed") == "5"


def test_no_new_items_keeps_cursor():
    items = [{"id": "3"}, {"id": "2"}, {"id": "1"}]
    r = ev.diff_new_items(items, cursor="3", id_field="id")
    assert r.events == [] and ev._decode_cursor(r.cursor, "feed") == "3"


def test_nested_fields_flatten_for_params():
    items = [{"id": "2", "issue": {"title": "boom", "labels": ["a", "b"]}}, {"id": "1"}]
    r = ev.diff_new_items(items, cursor="1", id_field="id")
    ev0 = r.events[0]
    assert ev0["issue.title"] == "boom"
    assert ev0["issue.labels"] == "a, b"


def test_dotted_id_field():
    items = [{"meta": {"id": "b"}}, {"meta": {"id": "a"}}]
    r = ev.diff_new_items(items, cursor="a", id_field="meta.id")
    assert ev._decode_cursor(r.cursor, "feed") == "b" and len(r.events) == 1


def test_event_burst_is_bounded():
    items = [{"id": str(i)} for i in range(100, 0, -1)]  # 100 newest-first
    r = ev.diff_new_items(items, cursor="1", id_field="id")
    assert len(r.events) <= ev._MAX_EVENTS


def test_burst_over_cap_drains_oldest_first_without_loss():
    # 40 new items since cursor "0"; the cap is 25. The oldest 25 must fire this
    # poll and the cursor must stop at the newest FIRED item so the remaining 15
    # drain on the next poll -- no item is skipped.
    items = [{"id": str(i)} for i in range(40, 0, -1)]  # 40..1, newest-first
    first = ev.diff_new_items(items, cursor="0", id_field="id")
    assert [e["id"] for e in first.events] == [str(i) for i in range(1, 26)]  # 1..25
    assert ev._decode_cursor(first.cursor, "feed") == "25"
    # Next poll continues from the cursor: the remaining 26..40 fire, none lost.
    second = ev.diff_new_items(items, cursor=first.cursor, id_field="id")
    assert [e["id"] for e in second.events] == [str(i) for i in range(26, 41)]
    assert ev._decode_cursor(second.cursor, "feed") == "40"


def test_http_json_source_with_injected_fetch(monkeypatch):
    monkeypatch.setattr(
        ev, "_http_get_json",
        lambda url, headers=None, timeout=15.0: {"data": [{"id": "9", "who": "acme"}]})
    r = ev.HttpJsonSource().poll(
        {"url": "http://x/api", "items_path": "data", "id_field": "id"}, cursor="8")
    assert r.events[0]["who"] == "acme" and ev._decode_cursor(r.cursor, "feed") == "9"


@pytest.mark.parametrize("source", [ev.HttpJsonSource, ev.RssSource])
@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["8.8.8.8", "10.0.0.5"]])
def test_event_pollers_reject_private_dns_even_when_private_fetch_is_enabled(monkeypatch, source, addresses):
    import httpx

    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [
        (2, 1, 6, "", (address, 0)) for address in addresses
    ])
    monkeypatch.setattr(httpx, "HTTPTransport", lambda **kwargs: pytest.fail("network transport constructed"))
    with pytest.raises(ev.EventSourceError, match="blocked by SSRF guard"):
        source().poll({"url": "https://feed.example/data"}, cursor="")


def test_event_pagination_rechecks_public_dns_for_each_page(monkeypatch):
    import httpx

    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    addresses = iter(("8.8.8.8", "10.0.0.5"))
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [
        (2, 1, 6, "", (next(addresses), 0))
    ])
    requests = []

    def response(request):
        requests.append(request)
        return httpx.Response(200, json={"items": [], "next": "/page2"})

    monkeypatch.setattr(httpx, "HTTPTransport", lambda **kwargs: httpx.MockTransport(response))
    with pytest.raises(ev.EventSourceError, match="blocked by SSRF guard"):
        ev.HttpJsonSource().poll({"url": "https://feed.example/page1", "items_path": "items",
                                 "next_path": "next", "max_pages": 2}, cursor="")
    assert len(requests) == 1


def test_http_json_rejects_large_content_length(monkeypatch):
    class _Resp:
        status_code = 200
        headers = {"content-length": str(ev._MAX_HTTP_JSON_BYTES + 1)}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def iter_bytes(self):
            yield b"{}"

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def stream(self, method, url, headers=None):
            return _Resp()

    monkeypatch.setattr("maverick.tools._ssrf.safe_client", lambda url, **kw: _Client())
    with pytest.raises(ev.EventSourceError, match="byte limit"):
        ev._http_get_json("https://x/feed")


def test_http_json_rejects_stream_over_byte_limit(monkeypatch):
    class _Resp:
        status_code = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def iter_bytes(self):
            yield b"["
            yield b"x" * ev._MAX_HTTP_JSON_BYTES

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def stream(self, method, url, headers=None):
            return _Resp()

    monkeypatch.setattr("maverick.tools._ssrf.safe_client", lambda url, **kw: _Client())
    with pytest.raises(ev.EventSourceError, match="byte limit"):
        ev._http_get_json("https://x/feed")

def test_http_json_requires_url():
    with pytest.raises(ev.EventSourceError):
        ev.HttpJsonSource().poll({}, cursor="")


def test_http_json_rejects_non_array(monkeypatch):
    monkeypatch.setattr(ev, "_http_get_json", lambda url, **k: {"data": {"not": "a list"}})
    with pytest.raises(ev.EventSourceError):
        ev.HttpJsonSource().poll({"url": "http://x", "items_path": "data"}, cursor="")


_RSS = """<?xml version="1.0"?><rss><channel>
  <item><guid>b</guid><title>Newer</title><link>http://x/b</link></item>
  <item><guid>a</guid><title>Older</title><link>http://x/a</link></item>
</channel></rss>"""


def test_rss_source_parses_and_dedups(monkeypatch):
    monkeypatch.setattr(ev, "_http_get_text", lambda url, headers=None, timeout=15.0: _RSS)
    r = ev.RssSource().poll({"url": "http://x/feed"}, cursor="a")   # 'a' already seen
    assert ev._decode_cursor(r.cursor, "feed") == "b" and len(r.events) == 1
    assert r.events[0]["title"] == "Newer" and r.events[0]["id"] == "b"


def test_rss_refuses_doctype_entity(monkeypatch):
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "boom">]><rss></rss>'
    monkeypatch.setattr(ev, "_http_get_text", lambda url, headers=None, timeout=15.0: evil)
    with pytest.raises(ev.EventSourceError):
        ev.RssSource().poll({"url": "http://x"}, cursor="1")


def test_oauth_http_json_uses_a_vaulted_bearer_token(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
    from maverick import oauth_vault
    oauth_vault.get_vault().put("github", {"access_token": "T0K3N", "expires_in": 3600})
    seen = {}

    def _fake(url, headers=None, timeout=15.0):
        seen["auth"] = (headers or {}).get("Authorization")
        return {"data": [{"id": "9", "who": "acme"}]}
    monkeypatch.setattr(ev, "_http_get_json", _fake)
    r = ev.OAuthHttpJsonSource().poll(
        {"provider": "github", "url": "https://api.github.com/api", "items_path": "data", "id_field": "id"},
        cursor="8")
    assert seen["auth"] == "Bearer T0K3N"
    assert r.events[0]["who"] == "acme" and ev._decode_cursor(r.cursor, "feed") == "9"


def test_oauth_source_errors_when_vault_off(monkeypatch):
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "0")
    with pytest.raises(ev.EventSourceError):
        ev.OAuthHttpJsonSource().poll({"provider": "acme", "url": "https://x"}, cursor="")


def test_oauth_source_requires_provider(monkeypatch):
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
    with pytest.raises(ev.EventSourceError):
        ev.OAuthHttpJsonSource().poll({"url": "https://x"}, cursor="")


def test_oauth_refresher_falls_back_to_preset(monkeypatch):
    # A trigger config that names a preset provider (no explicit token_url) still
    # gets a working refresher, built from the preset's token endpoint + env creds.
    monkeypatch.setenv("SLACK_OAUTH_CLIENT_ID", "cid-1")
    monkeypatch.setenv("SLACK_OAUTH_CLIENT_SECRET", "shh")
    seen = {}
    monkeypatch.setattr(
        "maverick.tools.oauth_helper._post_form",
        lambda url, data: seen.update(url=url, data=data) or {"access_token": "AT9"},
    )
    refresher = ev._oauth_refresher({"provider": "slack"})   # no token_url/client_id
    assert refresher is not None
    assert refresher({"refresh_token": "RT"})["access_token"] == "AT9"
    assert seen["url"] == "https://slack.com/api/oauth.v2.access"


def test_oauth_refresher_none_for_unknown_provider(monkeypatch):
    monkeypatch.delenv("SLACK_OAUTH_CLIENT_ID", raising=False)
    # unknown provider + no explicit endpoints -> no refresher (stored token used as-is)
    assert ev._oauth_refresher({"provider": "totally-unknown"}) is None


@pytest.mark.parametrize("override", [
    {"token_url": "https://attacker.example/token"},
    {"client_id": "attacker-client"}, {"client_secret_env": "HOST_SECRET"},
])
def test_oauth_refresher_rejects_trigger_credential_overrides(override):
    with pytest.raises(ev.EventSourceError, match="overrides"):
        ev._oauth_refresher({"provider": "slack", **override})


@pytest.mark.parametrize("url", ["https://attacker.example/api", "https://api.github.com.attacker.example/",
                                  "http://api.github.com/", "https://api.github.com:444/"])
def test_oauth_source_refuses_wrong_destination_before_vault_access(monkeypatch, url):
    monkeypatch.setattr(ev, "_oauth_bearer", lambda config: pytest.fail("vault accessed"))
    with pytest.raises(ev.EventSourceError, match="approved endpoint"):
        ev.OAuthHttpJsonSource().poll({"provider": "github", "url": url}, cursor="")


def test_github_issues_source_dedups_by_number_and_drops_prs(monkeypatch):
    feed = [
        {"number": 12, "title": "newer issue"},
        {"number": 11, "title": "a PR", "pull_request": {"url": "x"}},
        {"number": 10, "title": "older issue"},
    ]
    monkeypatch.setattr(ev, "_http_get_json", lambda url, headers=None, timeout=15.0: feed)
    r = ev.GithubIssuesSource().poll({"owner": "o", "repo": "r"}, cursor="10")
    assert [e["number"] for e in r.events] == ["12"]   # PR + already-seen excluded
    assert ev._decode_cursor(r.cursor, "feed") == "12"


def test_github_issues_requires_owner_repo():
    with pytest.raises(ev.EventSourceError):
        ev.GithubIssuesSource().poll({"owner": "o"}, cursor="")


def test_registry_and_unknown_source():
    assert "http_json" in ev.available_sources()
    assert "rss" in ev.available_sources()
    assert "oauth_http_json" in ev.available_sources()
    assert "github_issues" in ev.available_sources()
    with pytest.raises(ev.EventSourceError):
        ev.get_source("nope")


def test_enabled_env_flag(monkeypatch):
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "1")
    assert ev.enabled() is True
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "0")
    assert ev.enabled() is False
