"""Native preview transport must not infer an employee or reserve budget."""
import json

from click.testing import CliRunner
from maverick import budget_guidance
from maverick.cli import main


def test_cli_preview_uses_local_policy_without_identity(monkeypatch):
    seen = []
    def preview(**kwargs):
        seen.append(kwargs)
        return {"effective": {"max_dollars": 2, "max_wall_seconds": 30}, "available": True}
    monkeypatch.setattr(budget_guidance, "preview", preview)
    result = CliRunner().invoke(main, ["budget-preview", "--json", "--max-dollars", "5", "--max-wall-seconds", "90"])
    assert result.exit_code == 0
    assert json.loads(result.output)["effective"]["max_dollars"] == 2
    assert seen == [{"principal": None, "max_dollars": 5.0, "max_wall_seconds": 90.0}]


def test_cli_preview_disabled_is_visible(monkeypatch):
    def disabled(**kwargs):
        raise ValueError("Budget preview disabled by administrator")
    monkeypatch.setattr(budget_guidance, "preview", disabled)
    result = CliRunner().invoke(main, ["budget-preview", "--json"])
    assert result.exit_code != 0
    assert "disabled by administrator" in result.output
