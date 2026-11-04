"""The dashboard and maintained clients share one checked-in wire contract."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_dashboard_client_contracts_match_current_server_models():
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_dashboard_contracts.py"), "--check"],
        cwd=ROOT, check=True,
    )


def test_shared_replay_fixture_matches_server_contract():
    from maverick_dashboard.api_schemas import GoalEventsResponse

    fixture = json.loads((ROOT / "apps/client-contract-tests/contracts/goal-events-v1.json").read_text())
    pages = [GoalEventsResponse.model_validate(item) for item in fixture["pages"]]
    waiting = GoalEventsResponse.model_validate(fixture["waiting"])
    assert pages[0].has_more and not pages[0].terminal
    assert pages[1].terminal and not pages[1].has_more
    assert [event.id for page in pages for event in page.events] == [1, 2, 3]
    assert waiting.needs_input and not waiting.terminal and waiting.open_question_ids == [17]
