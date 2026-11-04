"""Tests for the github_repo_search tool. No network calls."""
from __future__ import annotations

from maverick.tools import github_repo_search as ghs


def test_missing_query_errors():
    out = ghs.github_repo_search().fn({"op": "repos", "query": "  "})
    assert out.startswith("ERROR")
    assert "query is required" in out


def test_unknown_op_errors():
    out = ghs.github_repo_search().fn({"op": "nope", "query": "x"})
    assert out.startswith("ERROR: unknown op")


def test_code_op_requires_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    out = ghs.github_repo_search().fn({"op": "code", "query": "addNote"})
    assert out.startswith("ERROR: set GITHUB_TOKEN")


def test_build_url_repos_and_code():
    repo_url = ghs._build_url("repos", "tetris language:python", 5)
    assert repo_url.startswith("https://api.github.com/search/repositories?")
    assert "q=tetris+language%3Apython" in repo_url
    assert "per_page=5" in repo_url
    code_url = ghs._build_url("code", "addNote", 200)
    assert code_url.startswith("https://api.github.com/search/code?")
    # per_page is clamped to 100.
    assert "per_page=100" in code_url


def test_parse_repos_sample():
    data = {
        "items": [
            {"full_name": "a/b", "stargazers_count": 12, "description": "hi"},
            {"full_name": "c/d", "stargazers_count": 0, "description": None},
        ]
    }
    out = ghs._parse_repos(data)
    assert "a/b" in out and "★12" in out
    assert "c/d" in out
    assert ghs._parse_repos({"items": []}) == "no repositories"


def test_parse_code_sample():
    data = {
        "items": [
            {"path": "src/x.py", "repository": {"full_name": "a/b"}},
        ]
    }
    out = ghs._parse_code(data)
    assert "a/b" in out and "src/x.py" in out
    assert ghs._parse_code({"items": []}) == "no code matches"


def test_parse_repos_tolerates_nondict_items():
    # A malformed / hostile search response whose `items` carries null or
    # non-dict elements must not raise: _parse_repos runs OUTSIDE _run's
    # try/except, so an uncaught AttributeError there crashes the whole tool.
    assert ghs._parse_repos({"items": [None, "x", 1, []]}) == "no repositories"
    out = ghs._parse_repos(
        {"items": [None, {"full_name": "a/b", "stargazers_count": 3}]}
    )
    assert "a/b" in out


def test_parse_code_tolerates_nondict_items_and_repository():
    assert ghs._parse_code({"items": [None, "x", 1]}) == "no code matches"
    # repository as a non-dict (string) must not crash either.
    out = ghs._parse_code({"items": [{"path": "p.py", "repository": "notdict"}]})
    assert "p.py" in out


def test_run_survives_nondict_items(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setattr(ghs, "_http_get_json", lambda url: (200, {"items": [None]}))
    out = ghs.github_repo_search().fn({"op": "repos", "query": "foo"})
    assert out == "no repositories"
    out = ghs.github_repo_search().fn({"op": "code", "query": "foo"})
    assert out == "no code matches"


def test_run_uses_token_header(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok123")
    captured = {}

    def fake_get(url):
        captured["url"] = url
        return 200, {"items": [{"full_name": "a/b", "stargazers_count": 1}]}

    monkeypatch.setattr(ghs, "_http_get_json", fake_get)
    out = ghs.github_repo_search().fn({"op": "repos", "query": "foo"})
    assert "a/b" in out
    assert "/search/repositories" in captured["url"]
    # The Bearer header is built from the env token.
    assert ghs._headers()["Authorization"] == "Bearer tok123"


# --- redirect credential-leak regression -----------------------------------
import http.server  # noqa: E402
import threading  # noqa: E402

from maverick.tools import github_repo_search as _ghs_redir  # noqa: E402


class _GhsRecordingHandler(http.server.BaseHTTPRequestHandler):
    received_headers: dict = {}

    def do_GET(self):  # noqa: N802
        type(self).received_headers = {k.lower(): v for k, v in self.headers.items()}
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def _ghs_make_server(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_cross_host_redirect_strips_authorization(monkeypatch):
    """A 302 to a different host must NOT forward the Bearer GITHUB_TOKEN."""
    sink = _ghs_make_server(_GhsRecordingHandler)
    sink_url = f"http://localhost:{sink.server_address[1]}/leaked"

    class _Redir(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", sink_url)
            self.end_headers()

        def log_message(self, *a):
            pass

    redir = _ghs_make_server(_Redir)
    try:
        monkeypatch.setenv("GITHUB_TOKEN", "SECRET-GH-456")
        url = f"http://127.0.0.1:{redir.server_address[1]}/start"
        code, _ = _ghs_redir._http_get_json(url)
        assert code == 200
        got = _GhsRecordingHandler.received_headers
        assert "authorization" not in got, got
    finally:
        sink.shutdown()
        redir.shutdown()
