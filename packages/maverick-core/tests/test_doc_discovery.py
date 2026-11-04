"""Doc discovery: find the SOW/contract/DPA in connected sources, fail-open."""
from __future__ import annotations

import pytest
from maverick import doc_discovery
from maverick.config import reset_config_cache

GRAPH_SEARCH_PAYLOAD = {
    "value": [{"hitsContainers": [{"hits": [
        {"summary": "…Acme CRM DPA…",
         "resource": {"id": "d1", "name": "Acme CRM — DPA (signed).pdf",
                      "webUrl": "https://sp/x", "size": 1234,
                      "file": {"mimeType": "application/pdf"},
                      "parentReference": {"driveId": "drv"}}},
        {"summary": "",
         "resource": {"id": "d2", "name": "Holiday calendar.pdf",
                      "webUrl": "https://sp/y", "size": 99,
                      "file": {"mimeType": "application/pdf"},
                      "parentReference": {"driveId": "drv"}}},
    ]}]}],
}

SLACK_SEARCH_PAYLOAD = {
    "ok": True,
    "files": {"matches": [
        {"id": "F1", "name": "Acme CRM contract.docx",
         "permalink": "https://slack/f1", "mimetype": "application/msword",
         "size": 10, "url_private_download": "https://slack/dl/f1"},
    ]},
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in ("MSGRAPH_ACCESS_TOKEN", "MSGRAPH_BASE_URL",
                "SLACK_SEARCH_TOKEN", "SLACK_BOT_TOKEN", "SLACK_BASE_URL",
                "GDRIVE_ACCESS_TOKEN", "GDRIVE_BASE_URL",
                "MAVERICK_ASSESS_DISCOVERY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    reset_config_cache()
    yield
    reset_config_cache()


class TestCreds:
    def test_unconfigured_source_is_none(self):
        assert doc_discovery._creds("msgraph") is None

    def test_env_token_with_default_base(self, monkeypatch):
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
        base, token = doc_discovery._creds(
            "msgraph", allow_ambient_credentials=True,
        )
        assert token == "tok"
        assert base == "https://graph.microsoft.com/v1.0"

    def test_env_token_is_not_ambient_without_explicit_opt_in(self, monkeypatch):
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "operator-global-token")
        assert doc_discovery._creds("msgraph") is None
        assert doc_discovery.configured_sources() == []

    def test_authenticated_saved_connection_requires_https(self, monkeypatch):
        from maverick import connections

        monkeypatch.setattr(
            connections,
            "resolve",
            lambda source, *, principal=None: (
                "http://documents.example/graph",
                "alice-saved-token",
            ),
        )
        assert doc_discovery._creds(
            "msgraph",
            principal="user:alice",
        ) is None

    def test_env_base_override(self, monkeypatch):
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
        monkeypatch.setenv("MSGRAPH_BASE_URL", "http://127.0.0.1:9/graph-sim/")
        base, _ = doc_discovery._creds(
            "msgraph", allow_ambient_credentials=True,
        )
        assert base == "http://127.0.0.1:9/graph-sim"

    def test_configured_sources_respects_config_order(self, monkeypatch):
        monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb")  # pragma: allowlist secret
        assert doc_discovery.configured_sources(
            allow_ambient_credentials=True,
        ) == ["slack"]


class TestTransportGuard:
    def test_enterprise_egress_denial_precedes_transport(self, monkeypatch):
        from maverick import enterprise
        from maverick.tools import _ssrf

        called = []
        monkeypatch.setattr(
            enterprise,
            "enterprise_egress_denial",
            lambda url, *, tool: "host is not allowlisted",
        )
        monkeypatch.setattr(
            _ssrf,
            "safe_client",
            lambda *args, **kwargs: called.append((args, kwargs)),
        )
        with pytest.raises(PermissionError, match="egress"):
            doc_discovery._guarded_client("https://documents.example/file")
        assert called == []

    def test_url_userinfo_is_never_forwarded(self):
        with pytest.raises(ValueError, match="credentials"):
            doc_discovery._guarded_client(
                "https://alice:secret@documents.example/file",  # pragma: allowlist secret
            )

    def test_cross_origin_redirect_drops_authorization(self, monkeypatch):
        calls = []

        class Response:
            def __init__(self, status, headers, body=b""):
                self.status_code = status
                self.headers = headers
                self._body = body

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def raise_for_status(self):
                return None

            def iter_bytes(self):
                yield self._body

        responses = {
            "https://graph.example/content": Response(
                302,
                {"location": "https://cdn.example/signed-download"},
            ),
            "https://cdn.example/signed-download": Response(
                200,
                {"content-type": "application/pdf"},
                b"document",
            ),
        }

        class Client:
            def __init__(self, url):
                self.url = url

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def stream(self, method, url, *, headers):
                calls.append((method, url, dict(headers)))
                return responses[self.url]

        monkeypatch.setattr(
            doc_discovery,
            "_guarded_client",
            lambda url, **kwargs: Client(url),
        )
        data, mime = doc_discovery._download(
            "https://graph.example/content",
            "caller-token",
            100,
        )
        assert (data, mime) == (b"document", "application/pdf")
        assert calls == [
            (
                "GET",
                "https://graph.example/content",
                {"Authorization": "Bearer caller-token"},
            ),
            ("GET", "https://cdn.example/signed-download", {}),
        ]

    def test_https_redirect_downgrade_stops_before_second_request(self, monkeypatch):
        calls = []

        class Response:
            status_code = 302
            headers = {"location": "http://cdn.example/plaintext-download"}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

        class Client:
            def __init__(self, url):
                self.url = url

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def stream(self, method, url, *, headers):
                calls.append((method, url, dict(headers)))
                return Response()

        monkeypatch.setattr(
            doc_discovery,
            "_guarded_client",
            lambda url, **kwargs: Client(url),
        )
        with pytest.raises(PermissionError, match="downgrade"):
            doc_discovery._download(
                "https://graph.example/content",
                "caller-token",
                100,
            )
        assert calls == [(
            "GET",
            "https://graph.example/content",
            {"Authorization": "Bearer caller-token"},
        )]


class TestDiscover:
    def test_parses_ranks_and_dedupes_msgraph(self, monkeypatch):
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
        monkeypatch.setattr(doc_discovery, "_post",
                            lambda url, token, body: (200, GRAPH_SEARCH_PAYLOAD))
        hits = doc_discovery.discover(
            "Acme CRM", allow_ambient_credentials=True,
        )
        assert [h.doc_id for h in hits] == ["d1", "d2"]
        top = hits[0]
        assert top.source == "msgraph"
        assert top.ref == {"drive_id": "drv"}
        # DPA + subject tokens outrank the unrelated calendar.
        assert top.score > hits[1].score

    def test_multiple_sources_merge(self, monkeypatch):
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "t1")
        monkeypatch.setenv("SLACK_BOT_TOKEN", "t2")  # pragma: allowlist secret
        monkeypatch.setattr(doc_discovery, "_post",
                            lambda url, token, body: (200, GRAPH_SEARCH_PAYLOAD))
        monkeypatch.setattr(doc_discovery, "_get",
                            lambda url, token, params=None, **kw:
                            (200, SLACK_SEARCH_PAYLOAD))
        hits = doc_discovery.discover(
            "Acme CRM", allow_ambient_credentials=True,
        )
        assert {h.source for h in hits} == {"msgraph", "slack"}

    def test_erroring_source_contributes_nothing(self, monkeypatch):
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "t1")
        monkeypatch.setenv("SLACK_BOT_TOKEN", "t2")  # pragma: allowlist secret

        def boom(url, token, body):
            raise RuntimeError("graph is down")

        monkeypatch.setattr(doc_discovery, "_post", boom)
        monkeypatch.setattr(doc_discovery, "_get",
                            lambda url, token, params=None, **kw:
                            (200, SLACK_SEARCH_PAYLOAD))
        hits = doc_discovery.discover(
            "Acme CRM", allow_ambient_credentials=True,
        )
        assert [h.source for h in hits] == ["slack"]

    def test_no_sources_returns_empty(self):
        assert doc_discovery.discover(
            "Acme CRM", allow_ambient_credentials=True,
        ) == []

    def test_empty_subject_returns_empty(self, monkeypatch):
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
        assert doc_discovery.discover(
            "   ", allow_ambient_credentials=True,
        ) == []

    def test_env_kill_switch(self, monkeypatch):
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
        monkeypatch.setenv("MAVERICK_ASSESS_DISCOVERY", "0")
        reset_config_cache()
        assert doc_discovery.discover(
            "Acme CRM", allow_ambient_credentials=True,
        ) == []

    def test_requested_sources_cannot_widen_the_operator_allowlist(
            self, monkeypatch, tmp_path):
        # Operator allows only gdrive; Slack creds exist anyway. A request
        # asking for slack must search NOTHING -- the body filters within the
        # allowlist, it never widens it.
        cfg = tmp_path / "config.toml"
        cfg.write_text('[assessments]\nsources = ["gdrive"]\n',
                       encoding="utf-8")
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
        monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb")  # pragma: allowlist secret
        reset_config_cache()
        called = []
        monkeypatch.setattr(doc_discovery, "_get",
                            lambda *a, **kw: called.append(a) or
                            (200, SLACK_SEARCH_PAYLOAD))
        assert doc_discovery.discover(
            "Acme CRM",
            sources=["slack"],
            allow_ambient_credentials=True,
        ) == []
        assert called == []


@pytest.fixture()
def _doc_server():
    """A local server standing in for a tenant: any /drives/... path returns
    100 bytes of 'pdf'."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"x" * 100
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # noqa: D102 -- silence test noise
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class TestFetch:
    def test_unconfigured_source_raises(self):
        with pytest.raises(ValueError):
            doc_discovery.fetch("msgraph", "d1")

    def test_streaming_size_cap_enforced(self, monkeypatch, _doc_server):
        # Product traffic must keep the SSRF guard's localhost denial. This
        # fixture deliberately supplies a test-only transport to the in-process
        # fake tenant instead of weakening that policy with an env escape hatch.
        import httpx

        monkeypatch.setattr(
            doc_discovery,
            "_guarded_client",
            lambda url, **kwargs: httpx.Client(**kwargs),
        )
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
        monkeypatch.setenv("MSGRAPH_BASE_URL", _doc_server)
        data, mime = doc_discovery.fetch(
            "msgraph", "d1", {"drive_id": "drv"}, max_bytes=100,
            allow_ambient_credentials=True,
        )
        assert (len(data), mime) == (100, "application/pdf")
        # One byte under the body size: the stream aborts mid-download.
        with pytest.raises(ValueError):
            doc_discovery.fetch(
                "msgraph", "d1", {"drive_id": "drv"}, max_bytes=99,
                allow_ambient_credentials=True,
            )

    def test_path_segments_cannot_repoint_the_request(self, monkeypatch,
                                                      _doc_server):
        seen = {}
        monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
        monkeypatch.setenv("MSGRAPH_BASE_URL", _doc_server)

        def spy(url, token, max_bytes):
            seen["url"] = url
            return b"", "application/pdf"

        monkeypatch.setattr(doc_discovery, "_download", spy)
        doc_discovery.fetch(
            "msgraph",
            "../me/messages?",
            {"drive_id": "drv/../"},
            allow_ambient_credentials=True,
        )
        # Every "/" and "?" inside the ids is percent-encoded: the values stay
        # single path segments and cannot proxy an arbitrary Graph GET.
        assert seen["url"].endswith(
            "/drives/drv%2F..%2F/items/..%2Fme%2Fmessages%3F/content")

    def test_slack_download_url_is_tenant_locked(self, monkeypatch):
        monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb")  # pragma: allowlist secret
        # A client-supplied ref pointing anywhere else must be refused --
        # otherwise the attach endpoint is an SSRF proxy carrying the token.
        for evil in ("http://169.254.169.254/latest/meta-data/",
                     "https://attacker.example/steal",
                     "ftp://files.slack.com/x"):
            with pytest.raises(ValueError, match="outside the configured"):
                doc_discovery.fetch(
                    "slack",
                    "F1",
                    {"download_url": evil},
                    allow_ambient_credentials=True,
                )

    def test_resolve_mime_infers_office_docs_from_octet_stream(self):
        rm = doc_discovery.resolve_mime
        # Graph's /content commonly serves Office files as octet-stream; the
        # allowlist would reject that, so the filename wins in that case.
        assert rm("Acme SOW.docx", "application/octet-stream") == (
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document")
        assert rm("dpa.pdf", "") == "application/pdf"
        # A specific source mime is trusted as-is (parameters stripped).
        assert rm("x.bin", "application/pdf; charset=x") == "application/pdf"
        # Nothing to infer: the honest fallback stands (and store() decides).
        assert rm("mystery", "application/octet-stream") == \
            "application/octet-stream"

    def test_resolve_mime_infers_office_docs_without_office_entries_in_the_host_database(
            self, monkeypatch):
        # A Windows runner's registry had no Office types, so mimetypes could
        # not infer them. A database holding only the built-in types must
        # still resolve the document types the module handles.
        import mimetypes

        builtin_only = mimetypes.MimeTypes(filenames=(), strict=True)
        assert builtin_only.guess_type("Acme SOW.docx")[0] is None
        monkeypatch.setattr(mimetypes, "guess_type", builtin_only.guess_type)
        rm = doc_discovery.resolve_mime
        assert rm("Acme SOW.DOCX", "application/octet-stream") == (
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document")
        assert rm("Budget.xlsx", "application/octet-stream") == (
            "application/vnd.openxmlformats-officedocument"
            ".spreadsheetml.sheet")
        assert rm("Board.pptx", "application/octet-stream") == (
            "application/vnd.openxmlformats-officedocument"
            ".presentationml.presentation")
        assert rm("legacy.doc", "application/octet-stream") == "application/msword"
        assert rm("dpa.pdf", "application/octet-stream") == "application/pdf"
        # epub is a document package the attachment layer accepts, so it is
        # inferred here too rather than left to the host database.
        assert rm("book.epub", "application/octet-stream") == "application/epub+zip"
        assert rm("mystery", "application/octet-stream") == \
            "application/octet-stream"

    def test_slack_allows_tenant_hosts(self):
        ok = doc_discovery._slack_url_allowed
        base = "https://slack.com/api"
        assert ok("https://files.slack.com/files-pri/T1-F1/dl", base)
        assert ok("https://slack.com/x", base)
        assert not ok("https://notslack.com/x", base)
        assert not ok("https://evilslack.com/x", base)
        # Base override (tests / simulated tenant): same host allowed, http ok.
        assert ok("http://127.0.0.1:8892/dl", "http://127.0.0.1:8892/slack-sim")
        assert not ok("http://127.0.0.2:8892/dl",
                      "http://127.0.0.1:8892/slack-sim")
