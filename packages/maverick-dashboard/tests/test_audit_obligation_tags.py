"""The audit page makes a compiled obligation visible on the row it decided."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _prep(monkeypatch, tmp_path, events):
    from maverick import audit, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()

    class _Log:
        signing_enabled = False

        def tail(self, n, day=None, *, report=None):
            if report is not None:
                report.finished = True
                report.events = len(events)
            return list(events)

    monkeypatch.setattr(audit, "default_audit_log", lambda: _Log())
    from maverick.audit import export

    def recorded_events(**kwargs):
        yield from events
        if kwargs.get("report") is not None:
            kwargs["report"].finished = True
            kwargs["report"].events = len(events)

    monkeypatch.setattr(export, "iter_audit_events", recorded_events)


def test_denial_rows_link_their_obligation_and_tool_calls_list_what_was_checked(
        monkeypatch, tmp_path):
    from maverick_dashboard.app import app
    _prep(monkeypatch, tmp_path, [
        {"ts": 1_767_225_601.0, "kind": "governance_denied", "agent": "finance-0",
         "tool": "wire_transfer", "rule": "deny_actions",
         "obligation_id": "gdpr-art32-outbound-transfer", "regulation": "GDPR",
         "article": "Art. 32"},
        {"ts": 1_767_225_602.0, "kind": "tool_call", "agent": "worker-0", "name": "sql_query",
         "obligations_checked": ["gdpr-art17-erasure-governed-path"]},
    ])
    r = TestClient(app, base_url="http://127.0.0.1").get("/audit")
    assert r.status_code == 200, r.text
    body = r.text
    assert '<a href="/compliance/obligations">gdpr-art32-outbound-transfer</a>' in body
    assert 'class="aud-kv aud-obligation"' in body
    assert "Art. 32" in body and "GDPR" in body
    # A list of checked obligations renders as text, not as a JSON blob.
    assert "gdpr-art17-erasure-governed-path" in body
    assert "[&#34;gdpr-art17" not in body and '["gdpr-art17' not in body


def test_rows_without_obligations_render_exactly_as_before(monkeypatch, tmp_path):
    from maverick_dashboard.app import app
    _prep(monkeypatch, tmp_path, [
        {"ts": 1_767_225_601.0, "kind": "tool_call", "agent": "worker-0", "name": "read_file"},
    ])
    body = TestClient(app, base_url="http://127.0.0.1").get("/audit").text
    assert "aud-obligation" not in body.split("<tbody>", 1)[1]
    assert "Used a tool" in body
    assert "Read file" not in body  # generated tool names can contain private text
