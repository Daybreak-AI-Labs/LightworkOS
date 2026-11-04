"""Back-test harness: prior filed returns -> honest draft-vs-filed accuracy.

The contract these tests pin: an in-scope return that the engine computes
exactly matches; a wrong line is caught with its dollar delta; and a return
carrying out-of-scope income is excluded from the accuracy metric rather than
counted as a miss (so the headline number is trustworthy).
"""
from __future__ import annotations

import json

from maverick import tax_backtest as bt
from maverick import tax_prep as t
from maverick.cli import main


def _draft(**kw):
    wp = t.Workpaper(filing_status=kw.pop("filing_status", "single"),
                     dependents_under_17=kw.pop("dependents", 0),
                     docs=kw.pop("docs"))
    return wp, t.compute_first_pass(wp)


def _filed_from_draft(client, status, draft):
    return bt.FiledReturn(
        client=client, filing_status=status,
        total_income=draft.total_income, taxable_income=draft.taxable_income,
        tax_after_credits=draft.tax_after_credits,
        federal_withholding=draft.federal_withholding, balance=draft.balance)


class TestDiffAndScope:
    def test_in_scope_return_matches_its_own_draft(self):
        wp, draft = _draft(docs=[t.SourceDoc("W-2", "Acme", wages=80000.0,
                                             federal_withholding=9000.0)])
        d = bt.diff_return(_filed_from_draft("alice", "single", draft),
                           draft, wp)
        assert d.in_scope and d.matched() and d.max_abs_delta == 0.0

    def test_wrong_line_is_caught_with_its_delta(self):
        wp, draft = _draft(docs=[t.SourceDoc("W-2", "Acme", wages=80000.0,
                                             federal_withholding=9000.0)])
        filed = _filed_from_draft("bob", "single", draft)
        filed.tax_after_credits -= 500.0           # a $500 engine miss
        d = bt.diff_return(filed, draft, wp)
        assert d.in_scope and not d.matched()
        assert d.max_abs_delta == 500.0

    def test_out_of_scope_income_doc_excluded_from_accuracy(self):
        wp, draft = _draft(docs=[
            t.SourceDoc("W-2", "x", wages=50000.0),
            t.SourceDoc("1099-NEC", "gig", nonemployee_comp=20000.0)])
        filed = bt.FiledReturn("carol", "single", 70000.0, 54250.0,
                               7000.0, 5000.0, 2000.0)
        d = bt.diff_return(filed, draft, wp)
        assert not d.in_scope
        assert any("1099-NEC" in r for r in d.out_of_scope_reasons)

    def test_itemized_and_bad_status_are_out_of_scope(self):
        wp, draft = _draft(docs=[t.SourceDoc("W-2", "x", wages=50000.0)])
        itemized = bt.FiledReturn("d", "single", 50000.0, 0, 0, 0, 0,
                                  itemized=True)
        assert not bt.diff_return(itemized, draft, wp).in_scope
        wp2, draft2 = _draft(filing_status="mfs",
                             docs=[t.SourceDoc("W-2", "x", wages=50000.0)])
        bad = bt.FiledReturn("e", "mfs", 50000.0, 0, 0, 0, 0)
        assert not bt.diff_return(bad, draft2, wp2).in_scope


class TestBatchReport:
    def test_accuracy_counts_only_in_scope(self):
        wp, draft = _draft(docs=[t.SourceDoc("W-2", "a", wages=80000.0,
                                             federal_withholding=9000.0)])
        good = bt.diff_return(_filed_from_draft("a", "single", draft),
                              draft, wp)
        bad_filed = _filed_from_draft("b", "single", draft)
        bad_filed.balance += 999.0
        bad = bt.diff_return(bad_filed, draft, wp)
        oos = bt.ReturnDiff("c", in_scope=False,
                            out_of_scope_reasons=["itemized"])
        rep = bt.BatchReport([good, bad, oos])
        assert len(rep.in_scope) == 2 and len(rep.out_of_scope) == 1
        assert rep.accuracy == 0.5                 # 1 of 2 in-scope matched
        assert "OUT OF SCOPE" in bt.render_backtest(rep)
        assert "Δ $999.00" in bt.render_backtest(rep)


class TestBacktestJson:
    def test_backtest_dict_is_serializable_and_complete(self):
        wp, draft = _draft(docs=[t.SourceDoc("W-2", "a", wages=80000.0,
                                             federal_withholding=9000.0)])
        good = bt.diff_return(_filed_from_draft("a", "single", draft), draft, wp)
        oos = bt.ReturnDiff("b", in_scope=False,
                            out_of_scope_reasons=["itemized"])
        data = bt.backtest_dict(bt.BatchReport([good, oos]))
        import json
        json.dumps(data)
        assert data["accuracy"] == 1.0 and data["in_scope"] == 1
        assert data["returns"][0]["matched"] is True
        assert data["returns"][1]["in_scope"] is False


class TestBacktestCli:
    def test_dir_runner_and_cli(self, tmp_path):
        # Build one in-scope case (filed == what the engine computes) and one
        # out-of-scope case (carries a 1099-NEC).
        alice = tmp_path / "alice"
        alice.mkdir()
        (alice / "w2.txt").write_text(
            "Form W-2 Wage and Tax Statement 2025\n"
            "Box 1 Wages, tips: $80,000.00\n"
            "Box 2 Federal income tax withheld: $9,000.00\n", encoding="utf-8")
        _, draft = _draft(docs=[t.SourceDoc("W-2", "a", wages=80000.0,
                                            federal_withholding=9000.0)])
        (alice / "filed.json").write_text(json.dumps({
            "client": "alice", "filing_status": "single",
            "filed": {"total_income": draft.total_income,
                      "taxable_income": draft.taxable_income,
                      "tax_after_credits": draft.tax_after_credits,
                      "federal_withholding": draft.federal_withholding,
                      "balance": draft.balance}}), encoding="utf-8")
        carol = tmp_path / "carol"
        carol.mkdir()
        (carol / "nec.txt").write_text(
            "Form 1099-NEC 2025\nBox 1 Nonemployee compensation: $20,000.00\n",
            encoding="utf-8")
        (carol / "filed.json").write_text(json.dumps({
            "client": "carol", "filing_status": "single",
            "filed": {"total_income": 20000, "taxable_income": 4250,
                      "tax_after_credits": 425, "federal_withholding": 0,
                      "balance": 425}}), encoding="utf-8")

        report = bt.run_backtest_dir(tmp_path)
        assert len(report.in_scope) == 1 and report.accuracy == 1.0
        assert len(report.out_of_scope) == 1

        from click.testing import CliRunner
        res = CliRunner().invoke(main, ["tax", "backtest", str(tmp_path)])
        assert res.exit_code == 0
        assert "In-scope accuracy   : 100.0%" in res.output
        assert "carol" in res.output            # listed out of scope
