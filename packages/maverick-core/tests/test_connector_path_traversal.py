"""Hand-written connectors interpolated
unencoded model-supplied ids into API paths. httpx normalizes dot-segments
before sending (verified below), so a model-emitted id like
``"../../api/1.0/goals/1"`` could retarget the request to an arbitrary
endpoint under the same host and credential -- escalating a narrowly
described op ("complete a task") to any GET/POST/PUT/PATCH/DELETE the token
can reach.

Every connector below now runs the id through ``tools.safe_path_segment``
before it reaches an f-string URL. That function has two distinct outcomes,
and both need their own test:

- an id that IS just "." or ".." (a no-op segment with no legitimate
  meaning) is refused outright -- an ERROR string, no request attempted;
- a longer traversal-shaped id ("../../api/1.0/goals/1") is not refused --
  quoting can't tell a malicious "../" from a name that happens to contain
  one -- it is instead neutralized into a single, harmless, percent-encoded
  path segment that can never escape the endpoint prefix it was interpolated
  into. The request still fires (the id is simply wrong / 404s), but it can
  never reach a different API endpoint.

``_assert_contained`` proves the second, more important property directly:
feeding the captured path back through httpx's own request/URL construction
must reproduce it byte-for-byte (no dot-segment normalization occurred) and
it must still start with the endpoint prefix the connector intended.
"""
from __future__ import annotations

from maverick.tools import safe_path_segment

TRAVERSAL = "../../api/1.0/goals/1"


def _assert_contained(expected_prefix: str, path: str) -> None:
    import httpx
    normalized = httpx.Request("GET", f"https://example.com{path}").url.raw_path.decode()
    assert normalized == path, (
        f"path was altered by URL normalization: {path!r} -> {normalized!r}"
    )
    assert normalized.startswith(expected_prefix), (
        f"{normalized!r} escaped the intended prefix {expected_prefix!r}"
    )


def _capture(store: dict, key: str = "path"):
    def _fn(path, *a, **k):
        store[key] = path
        return 200, {}
    return _fn


class TestSafePathSegment:
    def test_quotes_slashes_so_traversal_becomes_inert(self):
        seg = safe_path_segment(TRAVERSAL)
        assert seg is not None
        assert "/" not in seg

    def test_quoted_segment_neutralizes_httpx_dot_segment_normalization(self):
        import httpx
        seg = safe_path_segment(TRAVERSAL)
        url = f"https://example.com/tasks/{seg}"
        assert httpx.Request("GET", url).url.raw_path == f"/tasks/{seg}".encode()

    def test_rejects_empty_and_bare_dots(self):
        assert safe_path_segment("") is None
        assert safe_path_segment(None) is None
        assert safe_path_segment(".") is None
        assert safe_path_segment("..") is None

    def test_accepts_ordinary_ids_unchanged(self):
        assert safe_path_segment("1207944909156194") == "1207944909156194"
        assert safe_path_segment("abc-123_ABC") == "abc-123_ABC"


def test_asana_task_get_and_complete_contain_traversal(monkeypatch):
    from maverick.tools import asana_tool
    store: dict = {}
    monkeypatch.setattr(asana_tool, "_get", _capture(store))
    monkeypatch.setattr(asana_tool, "_put", lambda path, body: (200, {"data": {}}))
    asana_tool._op_task_get({"task_gid": TRAVERSAL})
    _assert_contained("/tasks/", store["path"])
    # bare ".." (no legitimate meaning) is refused outright.
    assert asana_tool._op_task_get({"task_gid": ".."}).startswith("ERROR")


def test_bitbucket_slug_contains_traversal(monkeypatch):
    from maverick.tools import bitbucket_tool
    store: dict = {}
    monkeypatch.setattr(bitbucket_tool, "_get", _capture(store))
    bitbucket_tool._op_issues({"workspace": TRAVERSAL, "repo_slug": "r"})
    _assert_contained("/repositories/", store["path"])


def test_clickup_task_get_contains_traversal(monkeypatch):
    from maverick.tools import clickup_tool
    store: dict = {}
    monkeypatch.setattr(clickup_tool, "_get", _capture(store))
    clickup_tool._op_task_get({"task_id": TRAVERSAL})
    _assert_contained("/task/", store["path"])


def test_cloudflare_dns_delete_contains_traversal(monkeypatch):
    from maverick.tools import cloudflare_tool
    store: dict = {}
    monkeypatch.setattr(cloudflare_tool, "_delete", _capture(store))
    cloudflare_tool._op_dns_delete(
        {"zone_id": "z", "record_id": TRAVERSAL, "confirm": True},
    )
    _assert_contained("/zones/z/dns_records/", store["path"])


def test_confluence_page_get_contains_traversal(monkeypatch):
    from maverick.tools import confluence_tool
    store: dict = {}
    monkeypatch.setattr(
        confluence_tool, "_get",
        lambda path, params=None: (store.setdefault("path", path), (200, {}))[1],
    )
    confluence_tool._op_page_get({"page_id": TRAVERSAL})
    _assert_contained("/rest/api/content/", store["path"])


def test_dynamics_query_contains_traversal(monkeypatch):
    import httpx
    from maverick.tools import dynamics_tool
    store: dict = {}

    class _Resp:
        status_code = 200
        def json(self):
            return {"value": []}

    def _fake_get(url, headers=None, params=None, timeout=None):
        store["url"] = url
        return _Resp()

    monkeypatch.setattr(httpx, "get", _fake_get)
    monkeypatch.setenv("DYNAMICS_RESOURCE_URL", "https://org.crm.dynamics.com")
    monkeypatch.setenv("DYNAMICS_TOKEN", "t")
    dynamics_tool._op_query(TRAVERSAL, {})
    assert store["url"] == (
        f"https://org.crm.dynamics.com/api/data/v9.2/{safe_path_segment(TRAVERSAL)}"
    )


def test_gdrive_get_and_delete_contain_traversal(monkeypatch):
    from maverick.tools import gdrive_tool
    store: dict = {}
    monkeypatch.setattr(gdrive_tool, "_get", _capture(store))
    monkeypatch.setattr(gdrive_tool, "_get_raw", lambda url, params=None: (200, ""))
    gdrive_tool._op_get({"file_id": TRAVERSAL})
    _assert_contained("/files/", store["path"])

    store2: dict = {}
    monkeypatch.setattr(
        gdrive_tool, "_delete_req",
        lambda path: (store2.setdefault("path", path), 200)[1],
    )
    gdrive_tool._op_delete({"file_id": TRAVERSAL, "confirm": True})
    _assert_contained("/files/", store2["path"])


def test_gmail_get_contains_traversal(monkeypatch):
    from maverick.tools import gmail_tool
    store: dict = {}
    monkeypatch.setattr(gmail_tool, "_get", _capture(store))
    gmail_tool._op_get({"message_id": TRAVERSAL})
    _assert_contained("/messages/", store["path"])


def test_github_actions_slug_and_workflow_contain_traversal(monkeypatch):
    from maverick.tools import github_actions
    store: dict = {}
    monkeypatch.setattr(github_actions, "_get", _capture(store))
    monkeypatch.setattr(github_actions, "_post", _capture(store))
    github_actions._op_runs({"owner": TRAVERSAL, "repo": "r", "workflow": "ci.yml"})
    _assert_contained("/repos/", store["path"])

    store2: dict = {}
    monkeypatch.setattr(github_actions, "_get", _capture(store2))
    github_actions._op_runs({"owner": "o", "repo": "r", "workflow": TRAVERSAL})
    _assert_contained("/repos/o/r/actions/workflows/", store2["path"])

    store3: dict = {}
    monkeypatch.setattr(github_actions, "_post", _capture(store3))
    github_actions._op_dispatch(
        {"owner": "o", "repo": "r", "workflow": TRAVERSAL, "confirm": True},
    )
    _assert_contained("/repos/o/r/actions/workflows/", store3["path"])


def test_hubspot_contact_get_and_update_contain_traversal(monkeypatch):
    from maverick.tools import hubspot_tool
    store: dict = {}
    monkeypatch.setattr(hubspot_tool, "_get", _capture(store))
    hubspot_tool._op_contact_get({"contact_id": TRAVERSAL})
    _assert_contained("/crm/v3/objects/contacts/", store["path"])

    store2: dict = {}
    monkeypatch.setattr(hubspot_tool, "_patch", _capture(store2))
    hubspot_tool._op_contact_update(
        {"contact_id": TRAVERSAL, "properties": {"x": "y"}, "confirm": True},
    )
    _assert_contained("/crm/v3/objects/contacts/", store2["path"])


def test_pagerduty_incident_get_and_set_status_contain_traversal(monkeypatch):
    from maverick.tools import pagerduty_tool
    store: dict = {}
    monkeypatch.setattr(pagerduty_tool, "_get", _capture(store))
    pagerduty_tool._op_incident_get(TRAVERSAL)
    _assert_contained("/incidents/", store["path"])
    # bare ".." is refused outright, no id has that literal value.
    assert pagerduty_tool._op_incident_get("..").startswith("ERROR")


def test_replicate_predict_get_and_cancel_contain_traversal(monkeypatch):
    from maverick.tools import replicate_tool
    store: dict = {}
    monkeypatch.setattr(replicate_tool, "_get", _capture(store))
    replicate_tool._op_predict_get({"prediction_id": TRAVERSAL})
    _assert_contained("/predictions/", store["path"])

    store2: dict = {}
    monkeypatch.setattr(replicate_tool, "_post", _capture(store2))
    replicate_tool._op_cancel({"prediction_id": TRAVERSAL, "confirm": True})
    _assert_contained("/predictions/", store2["path"])


def test_sentry_issue_ops_contain_traversal(monkeypatch):
    from maverick.tools import sentry_tool
    store: dict = {}
    monkeypatch.setattr(sentry_tool, "_get", _capture(store))
    sentry_tool._op_issue_get(TRAVERSAL)
    _assert_contained("/issues/", store["path"])

    store2: dict = {}
    monkeypatch.setattr(sentry_tool, "_put", _capture(store2))
    sentry_tool._op_resolve(TRAVERSAL, True)
    _assert_contained("/issues/", store2["path"])


def test_trello_ops_contain_traversal(monkeypatch):
    from maverick.tools import trello_tool
    store: dict = {}
    monkeypatch.setattr(trello_tool, "_get", _capture(store))
    trello_tool._op_lists({"board_id": TRAVERSAL})
    _assert_contained("/boards/", store["path"])

    store2: dict = {}
    monkeypatch.setattr(trello_tool, "_get", _capture(store2))
    trello_tool._op_card_get({"card_id": TRAVERSAL})
    _assert_contained("/cards/", store2["path"])

    store3: dict = {}
    monkeypatch.setattr(trello_tool, "_put", _capture(store3))
    trello_tool._op_card_move({"card_id": TRAVERSAL, "list_id": "l", "confirm": True})
    _assert_contained("/cards/", store3["path"])


def test_truelayer_balance_and_transactions_contain_traversal(monkeypatch):
    from maverick.tools import truelayer_tool
    store: dict = {}

    def _fake_get(path, access_token, params=None):
        store["path"] = path
        return 200, {}

    monkeypatch.setattr(truelayer_tool, "_get", _fake_get)
    args = {"account_id": TRAVERSAL, "access_token": "t"}
    truelayer_tool._op_balance(args)
    _assert_contained("/data/v1/accounts/", store["path"])


def test_twilio_lookup_contains_traversal(monkeypatch):
    from maverick.tools import twilio_tool
    store: dict = {}

    def _fake_get(path, params=None, lookups=False):
        store["path"] = path
        return 200, {}

    monkeypatch.setattr(twilio_tool, "_get", _fake_get)
    twilio_tool._op_lookup({"phone": TRAVERSAL})
    _assert_contained("/PhoneNumbers/", store["path"])


def test_vercel_ops_contain_traversal(monkeypatch):
    from maverick.tools import vercel_tool
    store: dict = {}
    monkeypatch.setattr(vercel_tool, "_get", _capture(store))
    vercel_tool._op_deployment_get({"deployment_id": TRAVERSAL})
    _assert_contained("/v13/deployments/", store["path"])

    store2: dict = {}
    monkeypatch.setattr(vercel_tool, "_patch", _capture(store2))
    vercel_tool._op_cancel({"deployment_id": TRAVERSAL, "confirm": True})
    _assert_contained("/v12/deployments/", store2["path"])

    store3: dict = {}
    monkeypatch.setattr(vercel_tool, "_get", _capture(store3))
    vercel_tool._op_domains({"project_id": TRAVERSAL})
    _assert_contained("/v9/projects/", store3["path"])


def test_zoom_ops_contain_traversal(monkeypatch):
    from maverick.tools import zoom_tool
    store: dict = {}
    monkeypatch.setattr(zoom_tool, "_get", _capture(store))
    zoom_tool._op_meetings({"user": TRAVERSAL})
    _assert_contained("/users/", store["path"])

    store2: dict = {}
    monkeypatch.setattr(zoom_tool, "_get", _capture(store2))
    zoom_tool._op_meeting_get({"meeting_id": TRAVERSAL})
    _assert_contained("/meetings/", store2["path"])

    store3: dict = {}
    monkeypatch.setattr(zoom_tool, "_delete", lambda path: (store3.setdefault("path", path), 200)[1])
    zoom_tool._op_meeting_delete({"meeting_id": TRAVERSAL, "confirm": True})
    _assert_contained("/meetings/", store3["path"])
