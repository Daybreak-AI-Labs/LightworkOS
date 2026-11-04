"""The plan approval shows the plan's steps and its outside actions."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def test_plan_approval_card_lists_steps_and_outside_actions(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.approval_cards import encode_approval_detail
    from maverick.plan_review import plan_card
    from maverick.world_model import WorldModel

    card = plan_card(41, ["Match invoices to purchase orders", "Email the supplier about the missing receipt"],
                     "send_email", {"to": "supplier@example.com"}, ["read_file", "send_email", "http_fetch"], 2.5)
    approval_id = WorldModel(tmp_path / "world.db").create_approval(
        "confirm_plan", risk="high", scope="task 41", detail=encode_approval_detail(card), provenance="plan")
    from maverick_dashboard.app import app

    text = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/approvals").text
    row = re.search(rf'<article class="approval-item" data-id="{approval_id}".*?</article>', text, flags=re.DOTALL)
    assert row is not None
    html = row.group(0)
    assert "Plan to check before the task acts" in html
    for line in ("Step 1: Match invoices to purchase orders", "Step 2: Email the supplier about the missing receipt",
                 "First outside action: send an email to supplier@example.com",
                 "Later in this task it can also: open web pages or call outside services.", "If you reject, nothing runs"):
        assert line in html, line
    assert "compatibility caller" not in html and 'data-action="approve" disabled' not in html
