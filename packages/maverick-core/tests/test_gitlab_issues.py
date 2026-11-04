"""Tests for the gitlab_issues tool. No network calls."""
from __future__ import annotations

from maverick.tools import gitlab_issues as gli


def test_missing_op_errors():
    assert gli.gitlab_issues().fn({}).startswith("ERROR: op is required")


def test_list_requires_project_id():
    out = gli.gitlab_issues().fn({"op": "list"})
    assert out.startswith("ERROR")
    assert "project_id is required" in out


def test_list_requires_token(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    out = gli.gitlab_issues().fn({"op": "list", "project_id": "42"})
    assert out.startswith("ERROR: set GITLAB_TOKEN")


def test_create_requires_title(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "t")
    out = gli.gitlab_issues().fn({"op": "create", "project_id": "42"})
    assert out.startswith("ERROR")
    assert "requires title" in out


def test_url_builders_encode_project_path():
    base = "https://gitlab.com"
    # A group/path project id must be URL-encoded.
    url = gli._list_url(base, "group/repo", "opened", 25)
    assert "projects/group%2Frepo/issues?" in url
    assert "state=opened" in url
    assert gli._get_url(base, "42", 7).endswith("/projects/42/issues/7")
    assert gli._create_url(base, "42").endswith("/projects/42/issues")


def test_parse_list_and_issue():
    items = [{"iid": 3, "state": "opened", "title": "hello"}]
    assert "hello" in gli._parse_list(items)
    assert gli._parse_list([]) == "no issues"
    d = {
        "iid": 5,
        "title": "Bug",
        "state": "opened",
        "author": {"username": "dev"},
        "web_url": "https://gitlab.com/g/r/-/issues/5",
        "description": "body",
    }
    out = gli._parse_issue(d)
    assert "#5" in out and "Bug" in out and "dev" in out and "body" in out


def test_create_posts_when_token_present(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    seen = {}

    def fake_post(url, body):
        seen["url"], seen["body"] = url, body
        return 201, {"iid": 9, "web_url": "https://gitlab.com/g/r/-/issues/9"}

    monkeypatch.setattr(gli, "_http_post_json", fake_post)
    out = gli.gitlab_issues().fn(
        {"op": "create", "project_id": "g/r", "title": "T", "body": "B"}
    )
    assert "created #9" in out
    assert "projects/g%2Fr/issues" in seen["url"]
    assert seen["body"] == {"title": "T", "description": "B"}
    # PRIVATE-TOKEN header carries the PAT.
    assert gli._headers()["PRIVATE-TOKEN"] == "tok"


def test_tool_is_not_parallel_safe():
    assert gli.gitlab_issues().parallel_safe is False


# --- redirect credential-leak regression -----------------------------------
import http.server  # noqa: E402
import threading  # noqa: E402

from maverick.tools import gitlab_issues as _gli_redir  # noqa: E402


class _RecordingHandler(http.server.BaseHTTPRequestHandler):
    received_headers: dict = {}

    def do_GET(self):  # noqa: N802
        type(self).received_headers = {k.lower(): v for k, v in self.headers.items()}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"[]")

    def log_message(self, *a):  # silence
        pass


def _make_server(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def test_cross_host_redirect_strips_private_token(monkeypatch):
    """A 302 to a different host must NOT forward the PRIVATE-TOKEN PAT."""
    sink = _make_server(_RecordingHandler)
    sink_port = sink.server_address[1]
    # Use a different hostname (localhost vs 127.0.0.1) so the host check trips.
    sink_url = f"http://localhost:{sink_port}/leaked"

    class _RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", sink_url)
            self.end_headers()

        def log_message(self, *a):
            pass

    redir = _make_server(_RedirectHandler)
    try:
        monkeypatch.setenv("GITLAB_TOKEN", "SECRET-PAT-123")
        url = f"http://127.0.0.1:{redir.server_address[1]}/start"
        code, _ = _gli_redir._http_get_json(url)
        assert code == 200
        got = _RecordingHandler.received_headers
        assert "private-token" not in got, got
    finally:
        sink.shutdown()
        redir.shutdown()
