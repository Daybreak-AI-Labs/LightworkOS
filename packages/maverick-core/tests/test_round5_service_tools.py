"""Service boundaries and bounded reads for tool calls."""
from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace

import pytest


def test_youtube_uses_modern_fetch_and_raw_data(monkeypatch):
    from maverick.tools import youtube

    called = []
    entries = [{"text": "current transcript", "start": 0.0, "duration": 1.0}]

    class API:
        def fetch(self, video_id, languages):
            called.append((video_id, languages))
            return SimpleNamespace(to_raw_data=lambda: entries)

    monkeypatch.setitem(sys.modules, "youtube_transcript_api", SimpleNamespace(YouTubeTranscriptApi=API))
    assert youtube._fetch_transcript("dQw4w9WgXcQ", "fr") == entries
    assert called == [("dQw4w9WgXcQ", ["fr", "en"])]


def test_search_api_candidates_require_the_requested_host(monkeypatch):
    from maverick.tools import learn

    records, previews = [], []
    discovery = SimpleNamespace(
        probe_openapi_spec=lambda _: None,
        discover_openapi_spec=lambda **_: "https://untrusted.example/openapi.json",
        record=lambda *args, **kwargs: records.append(args),
    )

    async def run_tool(name, _args):
        if name == "web_search":
            return "search result"
        previews.append(name)
        return "GET /data"

    agent = SimpleNamespace(name="fixture", tools=SimpleNamespace(all=lambda: [
        SimpleNamespace(name="web_search"), SimpleNamespace(name="openapi_runner")]), _run_tool=run_tool)
    blackboard = SimpleNamespace(post=lambda *_: None)
    monkeypatch.setattr("maverick.tenant.egress.egress_allowed", lambda *_: True)
    for args in ({}, {"base_url": "https://requested.example"}):
        out = asyncio.run(learn._op_find_api(agent, blackboard, discovery, args, "catalog"))
        assert "https://untrusted.example/openapi.json" in out
        assert records == [] and previews == []
    out = asyncio.run(learn._op_find_api(
        agent, blackboard, discovery, {"base_url": "https://untrusted.example"}, "catalog"))
    assert records and previews == ["openapi_runner"] and "Found" in out


@pytest.mark.parametrize("base_url,spec_url,reason", [
    ("http://api.example", "http://api.example/openapi.json", "https"),
    ("https://api.example", "https://api.example:8443/openapi.json", "port"),
    ("https://api.example", "https://other.example/openapi.json", "host was not the requested host"),
    ("", "https://api.example/openapi.json", "no base_url"),
])
def test_unverified_api_candidate_says_what_is_wrong(monkeypatch, base_url, spec_url, reason):
    from maverick.tools import learn

    discovery = SimpleNamespace(probe_openapi_spec=lambda _: spec_url,
                                discover_openapi_spec=lambda **_: spec_url, record=lambda *a, **k: None)

    async def run_tool(_name, _args):
        return "search result"

    agent = SimpleNamespace(name="fixture", tools=SimpleNamespace(all=lambda: [
        SimpleNamespace(name="web_search")]), _run_tool=run_tool)
    monkeypatch.setattr("maverick.tenant.egress.egress_allowed", lambda *_: True)
    out = asyncio.run(learn._op_find_api(
        agent, SimpleNamespace(post=lambda *_: None), discovery, {"base_url": base_url}, "catalog"))
    assert out.startswith("Unverified OpenAPI candidate") and reason in out
    if reason != "host was not the requested host":
        assert "host was not the requested host" not in out


def test_robots_multiple_agents_and_allow_rules(monkeypatch):
    from maverick.tools import _ssrf, http_fetch

    body = "User-agent: Maverick\nUser-agent: OtherBot\nAllow: /private/public\nDisallow: /private\n"
    fetched = []
    monkeypatch.setattr(_ssrf, "safe_get", lambda url, **_: fetched.append(url) or SimpleNamespace(status_code=200, text=body))
    assert not http_fetch._check_robots("https://example.com/private/data")
    assert http_fetch._check_robots("https://example.com/private/public")
    assert fetched == ["https://example.com/robots.txt"] * 2


@pytest.mark.parametrize("body", [
    "User-agent: *\nAllow: /\nDisallow: /private\n",
    "User-agent: *\nDisallow: /private\nAllow: /\n",
])
def test_robots_most_specific_rule_wins_in_either_order(monkeypatch, body):
    from maverick.tools import _ssrf, http_fetch

    monkeypatch.setattr(_ssrf, "safe_get", lambda url, **_: SimpleNamespace(status_code=200, text=body))
    assert not http_fetch._check_robots("https://example.com/private/data")
    assert http_fetch._check_robots("https://example.com/public/data")


def test_robots_equal_length_tie_goes_to_allow(monkeypatch):
    from maverick.tools import _ssrf, http_fetch

    body = "User-agent: *\nDisallow: /page\nAllow: /page\n"
    monkeypatch.setattr(_ssrf, "safe_get", lambda url, **_: SimpleNamespace(status_code=200, text=body))
    assert http_fetch._check_robots("https://example.com/page")


def test_mongodb_database_is_operator_selected(monkeypatch):
    from maverick.tools import mongodb_tool as mongo

    accessed = []

    class Client:
        def __getitem__(self, name):
            accessed.append(name)
            return "configured database"

    monkeypatch.setattr(mongo, "_config", lambda: ("mongodb://example.test", "app"))
    monkeypatch.setattr(mongo, "_client", Client)
    assert mongo._db_for({"db": "admin"})[1].startswith("ERROR")
    assert accessed == []
    assert mongo._db_for({"db": "app"}) == ("configured database", None)
    monkeypatch.setattr(mongo, "_config", lambda: ("mongodb://example.test", ""))
    assert mongo._db_for({"db": "app"})[1].startswith("ERROR")


def test_mongodb_database_falls_back_to_uri_default(monkeypatch):
    from maverick.tools import mongodb_tool as mongo

    accessed = []

    class Client:
        def __getitem__(self, name):
            accessed.append(name)
            return name

    monkeypatch.setattr(mongo, "_client", Client)
    monkeypatch.setattr(mongo, "_config", lambda: ("mongodb://u:p@h1:27017,h2/app%2Ddb?authSource=admin", ""))
    assert mongo._db_for({}) == ("app-db", None)
    assert mongo._db_for({"db": "app-db"}) == ("app-db", None)
    assert mongo._db_for({"db": "admin"})[1].startswith("ERROR")
    for uri in ("mongodb://h1", "mongodb://h1/", "mongodb://h1/?authSource=admin"):
        monkeypatch.setattr(mongo, "_config", lambda uri=uri: (uri, ""))
        error = mongo._db_for({"db": "app"})[1]
        assert error.startswith("ERROR") and "MONGODB_URI" in error
    assert accessed == ["app-db", "app-db"]


@pytest.mark.parametrize("limit,batch", [(25, 25), (1000, 100)])
def test_mongodb_find_batches_up_to_100_documents(monkeypatch, limit, batch):
    from maverick.tools import mongodb_tool as mongo

    seen = {}

    class Cursor:
        def batch_size(self, size):
            seen["batch"] = size
            return self

        def limit(self, size):
            seen["limit"] = size
            return iter([{"n": 1}])

    database = {"items": SimpleNamespace(find=lambda _flt: Cursor())}
    monkeypatch.setattr(mongo, "_db_for", lambda _args: (database, None))
    out = mongo._op_find({"collection": "items", "limit": limit})
    assert seen == {"batch": batch, "limit": limit} and '"n":1' in out.replace(" ", "")


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_mongodb_empty_write_filter_never_dispatches(monkeypatch, operation):
    from maverick.tools import mongodb_tool as mongo

    calls = []

    class Database:
        def __getitem__(self, name):
            calls.append(name)
            return SimpleNamespace(
                update_many=lambda *_args, **_kwargs: SimpleNamespace(matched_count=1, modified_count=1, upserted_id=None),
                delete_many=lambda *_args: SimpleNamespace(deleted_count=1))

    monkeypatch.setattr(mongo, "_db_for", lambda _: (Database(), None))
    out = getattr(mongo, f"_op_{operation}")({"collection": "records", "filter": {}, "set_": {"status": "new"}, "confirm": True})
    assert out.startswith("ERROR") and "filter" in out
    assert calls == []


def test_mongodb_find_stops_reading_at_output_limit(monkeypatch):
    from maverick.tools import mongodb_tool as mongo

    pulled, prefetched, closed = [], [], []

    class Cursor:
        batch_count = 101

        def batch_size(self, n):
            self.batch_count = n
            return self

        def limit(self, _n):
            return self

        def __iter__(self):
            for start in range(0, 1000, self.batch_count):
                batch = range(start, min(start + self.batch_count, 1000))
                prefetched.extend(batch)
                for i in batch:
                    pulled.append(i)
                    yield {"data": "x" * 2000}

        def close(self):
            closed.append(True)

    class Database:
        def __getitem__(self, _):
            return SimpleNamespace(find=lambda _: Cursor())

    monkeypatch.setattr(mongo, "_db_for", lambda _: (Database(), None))
    out = mongo._op_find({"collection": "records", "limit": 1000})
    assert "truncated" in out and len(out) < 3100
    assert len(pulled) == 2 and closed == [True]
    assert prefetched == list(range(100))  # one bounded batch, not all 1000


def test_serial_refuses_virtual_consoles():
    from maverick.tools.serial_tool import _valid_port

    for port in ("/dev/tty1", "/dev/ttyprintk", "/dev/ttyUSB0\n", "/dev/ttySfoo"):
        assert not _valid_port(port)
    for port in ("/dev/ttyS0", "/dev/ttyUSB1", "/dev/ttyACM2", "/dev/cu.usb-1", "COM4", "/dev/serial/by-id/device-1"):
        assert _valid_port(port)


@pytest.mark.parametrize("operation", ["write", "read", "query"])
def test_serial_bounds_both_read_and_write_timeouts(monkeypatch, operation):
    from maverick.tools import serial_tool as serial

    seen = []

    class Serial:
        def __init__(self, port, baud, timeout=None):
            self.timeout = timeout
            self.write_timeout = None

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def write(self, payload):
            seen.append((self.timeout, self.write_timeout))
            return len(payload)

        def read(self, _):
            seen.append((self.timeout, self.write_timeout))
            return b"ok"

    monkeypatch.setitem(sys.modules, "serial", SimpleNamespace(Serial=Serial))
    out = getattr(serial, f"_op_{operation}")({"port": "/dev/ttyUSB0", "data": "x", "timeout": 10**9})
    assert "ERROR" not in out and seen
    assert all(0 < read <= 5 and read == write for read, write in seen)
    for invalid in (-1, float("inf"), float("nan")):
        with pytest.raises(ValueError):
            serial._timeout({"timeout": invalid})


def test_serial_admits_onboard_uarts_and_keeps_zero_timeout_default(tmp_path, monkeypatch):
    from maverick.tools import serial_tool as serial

    for port in ("/dev/ttyAMA0", "/dev/ttyTHS1", "/dev/ttymxc0", "/dev/ttyO1", "/dev/ttyGS0",
                 "/dev/ttyS0", "/dev/serial0", "/dev/serial1"):
        assert serial._valid_port(port), port
    regular = tmp_path / "ttyS0"
    regular.write_text("not a device")
    for port in ("/dev/null", "/dev/tty1", "/dev/ttyAMA", "/dev/serial/../sda", "/dev/serial0/x",
                 str(regular), "/dev/../etc/passwd"):
        assert not serial._valid_port(port), port
    # A device-named path that resolves out of /dev (or to a regular file) is refused.
    monkeypatch.setattr(serial.os.path, "lexists", lambda path: True)
    monkeypatch.setattr(serial.os.path, "realpath", lambda path: str(regular))
    assert not serial._valid_port("/dev/serial0")
    assert not serial._valid_port("/dev/serial/by-id/usb-foo")
    monkeypatch.undo()
    assert serial._timeout({"timeout": 0}) == 1.0


@pytest.mark.parametrize("parent_case", ["success", "absent", "ambiguous", "malformed"])
def test_shopify_refund_requires_successful_parent(monkeypatch, parent_case):
    from maverick.tools import shopify_tool as shopify

    posted = []
    rows = [{"id": 1, "kind": "authorization", "status": "success", "currency": "USD", "gateway": "test"},
            {"id": 2, "kind": "sale", "status": "failure", "currency": "USD", "gateway": "test"}]
    if parent_case != "absent":
        rows.append({"id": 3, "kind": "capture", "status": "success", "currency": "USD", "gateway": "test"})
    if parent_case == "ambiguous":
        rows.append({"id": 4, "kind": "sale", "status": "success", "currency": "USD", "gateway": "test"})
    if parent_case == "malformed":
        rows[-1]["id"] = None
    class Client(SimpleNamespace):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    client = Client(
        get=lambda _: SimpleNamespace(status_code=200, json=lambda: {"transactions": rows}),
        post=lambda _url, json: posted.append(json) or SimpleNamespace(status_code=200, json=lambda: {"refund": {"id": 7}}),
    )
    monkeypatch.setattr(shopify, "_client", lambda: ("example.myshopify.com", client))
    out = shopify._op_refund_create(10, 500, "USD", True)
    if parent_case == "success":
        assert posted[0]["refund"]["transactions"] == [{"parent_id": 3, "gateway": "test", "amount": "5.00", "kind": "refund", "currency": "USD"}]
        assert "refunded 7" in out
    else:
        assert out.startswith("ERROR") and posted == []


def test_linear_team_and_state_lookup_follow_cursors(monkeypatch):
    from maverick.tools import linear

    calls = []

    def post(query, variables=None):
        variables = variables or {}
        calls.append((query, variables))
        second = variables.get("after") == "page-2"
        page = {"hasNextPage": not second, "endCursor": None if second else "page-2"}
        if "query Teams" in query:
            return {"teams": {"nodes": [{"id": "team-1", "key": "ENG"}] if second else [], "pageInfo": page}}
        if "query IssueState" in query:
            return {"issue": {"team": {"id": "team-1", "states": {"nodes": [{"id": "state-1", "name": "Done"}] if second else [], "pageInfo": page}}}}
        assert variables == {"id": "ENG-1", "sid": "state-1"}
        return {"issueUpdate": {"success": True}}

    monkeypatch.setattr(linear, "_post", post)
    assert linear._resolve_team_id("ENG") == "team-1"
    assert linear._update_status("ENG-1", "Done") == "updated ENG-1 -> Done"
    assert [variables.get("after") for _, variables in calls] == [None, "page-2", None, "page-2", None]
    monkeypatch.setattr(linear, "_post", lambda *_: {"teams": {
        "nodes": [], "pageInfo": {"hasNextPage": True, "endCursor": "stalled"}}})
    with pytest.raises(RuntimeError, match="incomplete"):
        linear._resolve_team_id("ENG")


def test_ocr_hf_requires_operator_enablement_before_read_or_send(monkeypatch, tmp_path):
    from maverick.tools import _ssrf, ocr

    monkeypatch.setenv("HUGGINGFACE_API_TOKEN", "synthetic-token")  # pragma: allowlist secret -- synthetic OCR credential
    monkeypatch.delenv("OCR_BACKEND", raising=False)
    monkeypatch.setattr("maverick.enterprise.enterprise_enabled", lambda: False)
    sent = []
    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def post(self, _url, **kwargs):
            sent.append(kwargs["content"])
            return SimpleNamespace(status_code=200, json=lambda: [{"generated_text": "OCR result"}])

    monkeypatch.setattr(_ssrf, "safe_client", lambda *_args, **_kwargs: Client())
    path = tmp_path / "image.png"
    path.write_bytes(b"private image")
    out = ocr._run_hf(str(path), "test/model")
    assert "OCR_BACKEND" in out and sent == []
    monkeypatch.setenv("OCR_BACKEND", "hf")
    from maverick.budget import Budget

    # A paid hosted call is charged to a run budget; one is passed here.
    assert ocr._run_hf(str(path), "test/model", budget=Budget()) == "OCR result"
    assert sent == [b"private image"]
