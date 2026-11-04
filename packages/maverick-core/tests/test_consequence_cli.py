"""`maverick record-outcome` feeds a real downstream outcome to a past episode."""
from __future__ import annotations

from click.testing import CliRunner
from maverick import consequence as cq
from maverick.cli import main


def test_record_outcome_cli(tmp_path, monkeypatch):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    monkeypatch.setattr("maverick.consequence.shared", lambda: store)

    res = CliRunner().invoke(
        main, ["record-outcome", "1", "7", "1.0", "--kind", "invoice_paid"])
    assert res.exit_code == 0, res.output
    assert "recorded outcome" in res.output
    assert store.resolve(1, 7) == 1.0


def test_record_outcome_clamps_and_defaults(tmp_path, monkeypatch):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    monkeypatch.setattr("maverick.consequence.shared", lambda: store)
    res = CliRunner().invoke(main, ["record-outcome", "2", "3", "5.0"])  # clamps to 1.0
    assert res.exit_code == 0
    assert store.resolve(2, 3) == 1.0
