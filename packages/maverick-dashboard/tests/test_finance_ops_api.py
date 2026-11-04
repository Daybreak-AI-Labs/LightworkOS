"""Finance command center: "Check separation of duties" runs the same kernel
check as ``maverick finance lint-sod`` and answers in plain sentences."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import static_url

ORIGIN = {"Origin": "http://127.0.0.1"}
CHECK = "/api/v1/finance/sod-check"


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    main = re.sub(r"<[^>]+>", " ", main)
    return _html.unescape(re.sub(r"\s+", " ", main))


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()


def _as(monkeypatch, role: str, who: str) -> None:
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def test_check_runs_the_command_check_and_reports_plainly(client):
    from click.testing import CliRunner
    from maverick.cli import main
    from maverick.finance.sod_linter import lint_finance_roster

    packs, conflicts = lint_finance_roster()
    assert packs and not conflicts
    r = client.get(CHECK)
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["ok"] is True and body["teams"] == len(packs) and body["findings"] == []
    assert body["summary"] == (f"No problems found. All {len(packs)} finance AI teams keep recording, "
                               "approving, moving money and reconciling apart.")
    # The command and the button agree, word for word in the technical view.
    cli = CliRunner().invoke(main, ["finance", "lint-sod"])
    assert cli.exit_code == 0
    assert body["technical"] == [cli.output.strip()]


def test_workspace_packs_are_checked_and_conflicts_read_as_sentences(client, tmp_path):
    domains = tmp_path / "domains"
    domains.mkdir()
    (domains / "finance_payments_desk.toml").write_text(
        'name = "finance_payments_desk"\n'
        'description = "One desk that stages and releases payments"\n'
        'allow_tools = ["stage_payment_batch", "release_payment"]\n',
        encoding="utf-8")
    body = client.get(CHECK).json()
    assert body["ok"] is False
    assert body["summary"].startswith("1 problem found across ")
    assert body["findings"] == [{
        "team": "Finance payments desk",
        "sentence": ("This team can both move money (release payment) and record entries "
                     "(stage payment batch). These duties must sit with different teams."),
    }]
    assert body["technical"][0].startswith("SoD CONFLICT: compartment 'finance_payments_desk'")
    for finding in body["findings"]:
        assert "_" not in finding["team"] + finding["sentence"]


def test_check_needs_the_same_permission_as_the_finance_command_center(client, monkeypatch):
    _as(monkeypatch, "viewer", "user:vic")
    assert client.get(CHECK).status_code == 403
    assert client.get("/finance/board").status_code == 403
    _as(monkeypatch, "operator", "user:olga")
    assert client.get(CHECK).status_code == 200


def test_finance_command_center_offers_the_button(client):
    page = client.get("/finance/board")
    assert page.status_code == 200
    assert 'id="fb-sod-check"' in page.text
    assert "Check separation of duties" in visible_text(page.text)
    assert f'<script src="{static_url("lightwork-finance-sod-check.js")}"></script>' in page.text
    script = client.get("/static/lightwork-finance-sod-check.js")
    assert script.status_code == 200
    assert script.headers["content-type"].startswith("application/javascript")
    card = page.text.split('id="fb-t-sod"', 1)[1].split("</section>", 1)[0]
    for word in ("lint", "SoD", "maverick", "roster", "compartment", "HTTP"):
        assert word not in visible_text('<main id="content">' + card + "</main>"), word
