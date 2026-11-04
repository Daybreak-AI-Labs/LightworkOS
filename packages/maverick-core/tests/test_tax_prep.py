"""Tax preparation pipeline: docs in -> cited first-pass draft 1040 out.

The computation tests are checked against hand-computed TY2025 returns
(One Big Beautiful Bill Act figures) -- if a constant or the bracket math
drifts, these fail with the exact dollar delta. The suite tests hold the
tax_ packs to the same read-only safety envelope as every other suite.
"""
from __future__ import annotations

import os

import pytest
from click.testing import CliRunner
from maverick import tax_prep
from maverick.cli import main
from maverick.domain import builtin_dir, load_domains
from maverick.tax_prep import (
    SourceDoc,
    Workpaper,
    classify,
    compute_first_pass,
    extract,
    missing_items,
    render_review_package,
)

W2_TEXT = """Form W-2 Wage and Tax Statement 2025
Employer: Acme Corp  EIN 12-3456789
Box 1 Wages, tips, other compensation: $85,000.00
Box 2 Federal income tax withheld: $9,000.00
Box 15 State: PA  Employer's state ID: 1234-5678
Box 17 State income tax: $2,609.50
"""

INT_TEXT = """Form 1099-INT 2025
Payer: First Bank
Box 1 Interest income: $412.33
Box 4 Federal income tax withheld: $0.00
"""

NEC_TEXT = """Form 1099-NEC 2025
Payer: Gig Platform LLC
Box 1 Nonemployee compensation: $6,500.00
"""


class TestClassifyExtract:
    def test_classify_the_common_forms(self):
        assert classify(W2_TEXT) == "W-2"
        assert classify(INT_TEXT) == "1099-INT"
        assert classify(NEC_TEXT) == "1099-NEC"
        assert classify("Schedule K-1 Partner's Share of Income") == "K-1"
        assert classify("grocery receipt") == "UNKNOWN"

    def test_classify_the_flagged_only_forms(self):
        # Specific 1098 variants must NOT fall through to the mortgage 1098.
        assert classify("Form 1098-T Tuition Statement") == "1098-T"
        assert classify("Form 1098-E Student Loan Interest") == "1098-E"
        assert classify("Form 1098 Mortgage Interest Statement") == "1098"
        assert classify("Form 1099-R Distributions From Pensions") == "1099-R"
        assert classify("Form SSA-1099 Social Security Benefit") == "SSA-1099"
        assert classify("Form 1099-G Unemployment Compensation") == "1099-G"
        assert classify("Form 1099-B Proceeds From Broker") == "1099-B"

    def test_extract_w2_boxes_with_provenance(self):
        doc = extract(W2_TEXT, label="W-2 — Acme Corp")
        assert doc.doc_type == "W-2"
        assert doc.wages == 85000.0
        assert doc.federal_withholding == 9000.0
        assert doc.state == "PA"            # box 15, validated state code
        assert doc.state_withholding == 2609.50
        assert doc.raw_excerpt.startswith("Form W-2")

    def test_extract_interest_and_nec(self):
        assert extract(INT_TEXT).interest == 412.33
        assert extract(NEC_TEXT).nonemployee_comp == 6500.0


class TestExtractionHardening:
    """Regression tests for silent-wrong-number extraction failures -- each
    would corrupt a return without erroring."""

    def test_title_line_year_is_not_read_as_the_amount(self):
        # "Form 1099-INT Interest Income 2025" must not yield 2025 as interest;
        # the scan skips the bare year and lands on the real box line.
        txt = ("Form 1099-INT Interest Income  2025\n"
               "Payer: Big Bank N.A.\n"
               "Box 1 Interest income: $1,240.00\n")
        assert extract(txt).interest == 1240.0
        dtxt = ("Form 1099-DIV Ordinary Dividends 2025\n"
                "Box 1a Ordinary dividends: $3,015.50\n")
        assert extract(dtxt).ordinary_dividends == 3015.50

    def test_box_label_is_word_bounded_not_a_prefix(self):
        # "box 1" must not latch onto "box 10".."box 19" (and "box 2" not onto
        # "box 20".."box 29"); both previously extracted 0.
        wtxt = ("W-2 Wage and Tax Statement\n"
                "Box 10 Dependent care benefits: $5,000.00\n"
                "Box 1 Wages: $80,000.00\n")
        assert extract(wtxt).wages == 80000.0
        ftxt = ("W-2 Wage and Tax Statement\n"
                "Box 1 Wages, tips: $80,000.00\n"
                "Box 20 Locality name: $0.00\n"
                "Box 2 Federal income tax withheld: $9,000.00\n")
        assert extract(ftxt).federal_withholding == 9000.0

    def test_negative_sign_is_preserved_not_flipped(self):
        # A leading minus was silently dropped, turning a loss into income.
        txt = "1099-DIV Dividends\nBox 1a Ordinary dividends: -$500.00\n"
        assert extract(txt).ordinary_dividends == -500.0

    def test_qualified_dividends_box_1b_is_read_separately_from_box_1a(self):
        txt = ("Form 1099-DIV Dividends and Distributions 2025\n"
               "Box 1a Total ordinary dividends: $3,000.00\n"
               "Box 1b Qualified dividends: $2,400.00\n"
               "Box 4 Federal income tax withheld: $0.00\n")
        doc = extract(txt)
        assert doc.ordinary_dividends == 3000.0
        assert doc.qualified_dividends == 2400.0
        # No box 1b on the form: nothing is invented.
        only_1a = "1099-DIV Dividends\nBox 1a Ordinary dividends: $3,000.00\n"
        assert extract(only_1a).qualified_dividends == 0.0

    def test_bare_unformatted_year_skipped_but_real_money_kept(self):
        # The one input we intentionally skip is a bare year-range integer;
        # formatted money ($/comma/cents) at the same magnitude is kept.
        assert extract("1099-INT\nBox 1 Interest income: $2,025.00\n").interest \
            == 2025.0
        assert extract("1099-INT\nBox 1 Interest income: 2,025\n").interest \
            == 2025.0

    def test_amount_on_the_line_after_the_label(self):
        # PDF text exports put the box label and its value on separate lines.
        ml = ("Form W-2 Wage and Tax Statement 2025\n"
              "Box 1 Wages, tips, other compensation\n"
              "85,000.00\n"
              "Box 2 Federal income tax withheld\n"
              "9,000.00\n")
        d = extract(ml, label="w2")
        assert d.wages == 85000.0 and d.federal_withholding == 9000.0

    def test_next_line_fallback_rejects_a_bare_box_number(self):
        # The next-line fallback only accepts money-formatted values, so an
        # unformatted integer (e.g. the next box's number) is never grabbed.
        bare = ("Form W-2 Wage and Tax Statement 2025\n"
                "Box 1 Wages, tips\n"
                "85000\n")
        assert extract(bare, label="w2").wages == 0.0


class TestExtractionBreadth:
    """Carried figures from the broader document set are extracted onto the
    workpaper for the preparer -- but never summed into the v1 computation."""

    def test_new_doc_types_extract_their_headline_figure(self):
        assert extract("Form 1098 Mortgage Interest Statement 2025\n"
                       "Box 1 Mortgage interest received: $14,200.00\n"
                       ).mortgage_interest == 14200.0
        assert extract("Form 1099-R Distributions From Pensions 2025\n"
                       "Box 1 Gross distribution: $40,000.00\n"
                       "Box 2a Taxable amount: $38,000.00\n"
                       ).retirement_taxable == 38000.0
        assert extract("Form SSA-1099 Social Security Benefit 2025\n"
                       "Box 5 Net benefits: $28,800.00\n"
                       ).social_security == 28800.0
        assert extract("Form 1099-G Certain Government Payments 2025\n"
                       "Box 1 Unemployment compensation: $9,500.00\n"
                       ).unemployment == 9500.0
        assert extract("Form 1098-E Student Loan Interest 2025\n"
                       "Box 1 Student loan interest: $1,800.00\n"
                       ).student_loan_interest == 1800.0

    def test_carried_figures_are_cited_and_excluded_from_income(self):
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("W-2", "Acme", wages=60000.0),
            extract("Form 1098 Mortgage Interest 2025\n"
                    "Box 1 Mortgage interest received: $14,200.00\n",
                    label="1098-Bank"),
        ])
        draft = compute_first_pass(wp)
        assert draft.total_income == 60000.0          # mortgage NOT summed in
        assert ("Mortgage interest (1098 box 1)", 14200.0, "1098-Bank") \
            in draft.carried
        pkg = render_review_package(draft)
        assert "CARRIED FIGURES" in pkg and "14,200.00" in pkg


class TestExtractionConfidence:
    def test_classified_doc_with_no_headline_figure_forces_review(self):
        # A 1099-INT that classified but whose box-1 figure did not read:
        # confidence drops and the completeness check names it for review.
        d = extract("Form 1099-INT Interest Income 2025\nPayer: First Bank\n")
        assert d.doc_type == "1099-INT"
        assert d.confidence == 0.3 and d.review_required is True
        wp = Workpaper(filing_status="single", docs=[d])
        assert any("LOW EXTRACTION CONFIDENCE" in i
                   for i in compute_first_pass(wp).open_items)

    def test_zero_wage_w2_keeps_its_specific_message(self):
        # W-2 with no wages stays on its dedicated message, not the generic
        # confidence one (both mean "verify the document").
        d = extract("Form W-2 Wage and Tax Statement 2025\nEmployer: X\n")
        assert d.confidence == 0.3
        items = missing_items(Workpaper(filing_status="single", docs=[d]))
        assert any("no box-1 wages" in i for i in items)

    def test_clean_doc_is_full_confidence(self):
        d = extract("Form W-2 Wage and Tax Statement 2025\n"
                    "Box 1 Wages, tips: $50,000.00\n")
        assert d.confidence == 1.0 and d.review_required is False

    def test_unknown_doc_is_zero_confidence(self):
        d = extract("grocery receipt")
        assert d.confidence == 0.0 and d.review_required is True


class TestDuplicateDetection:
    """A re-uploaded document double-counts income -- the engine must flag
    likely duplicates while leaving genuine multi-source returns alone."""

    _W2 = ("Form W-2 Wage and Tax Statement 2025\n"
           "Box 1 Wages, tips: $85,000.00\n"
           "Box 2 Federal income tax withheld: $9,000.00\n")

    def test_duplicate_upload_is_flagged(self):
        wp = Workpaper(filing_status="single", docs=[
            extract(self._W2, label="w2.txt"),
            extract(self._W2, label="w2_copy.txt")])
        assert any("DUPLICATE" in i for i in compute_first_pass(wp).open_items)

    def test_two_distinct_w2s_are_not_flagged_and_sum(self):
        w2b = ("Form W-2 Wage and Tax Statement 2025\n"
               "Box 1 Wages, tips: $40,000.00\n"
               "Box 2 Federal income tax withheld: $3,000.00\n")
        wp = Workpaper(filing_status="single", docs=[
            extract(self._W2, label="job1"), extract(w2b, label="job2")])
        draft = compute_first_pass(wp)
        assert not any("DUPLICATE" in i for i in draft.open_items)
        assert draft.total_income == 125000.0

    def test_empty_unparsed_docs_are_not_grouped(self):
        wp = Workpaper(filing_status="single",
                       docs=[SourceDoc("UNKNOWN", "a"), SourceDoc("UNKNOWN", "b")])
        assert not any("DUPLICATE" in i for i in missing_items(wp))


class TestGarbageInputHandling:
    """Bad inputs must never silently produce a wrong number."""

    def test_negative_dependents_cannot_invent_a_credit_or_inflate_tax(self):
        neg = compute_first_pass(Workpaper(
            filing_status="single", dependents_under_17=-2,
            docs=[SourceDoc("W-2", "a", wages=50000.0)]))
        zero = compute_first_pass(Workpaper(
            filing_status="single", dependents_under_17=0,
            docs=[SourceDoc("W-2", "a", wages=50000.0)]))
        assert neg.child_tax_credit == 0.0
        assert neg.tax_after_credits == zero.tax_after_credits

    def test_negative_extracted_figure_is_flagged(self):
        d = compute_first_pass(Workpaper(
            filing_status="single",
            docs=[SourceDoc("W-2", "a", wages=-5000.0)]))
        assert any("NEGATIVE" in i for i in d.open_items)


class TestSeniorDeductionAndPayments:
    """The additional standard deduction (65+/blind), estimated payments, and
    the payments-sanity flag -- accuracy improvements for common real returns
    (especially the retirees whose SSA-1099/1099-R the engine now extracts)."""

    def test_additional_standard_deduction_for_age_and_blindness(self):
        # single 65+: $15,750 + $2,000
        d = compute_first_pass(Workpaper(
            filing_status="single", taxpayer_65_or_older=True,
            docs=[SourceDoc("W-2", "a", wages=50000.0)]))
        assert d.standard_deduction == 17750.0
        # mfj, 3 boxes (both 65+, one blind): $31,500 + 3 * $1,600
        d2 = compute_first_pass(Workpaper(
            filing_status="mfj", taxpayer_65_or_older=True,
            spouse_65_or_older=True, taxpayer_blind=True,
            docs=[SourceDoc("W-2", "a", wages=120000.0)]))
        assert d2.standard_deduction == 31500.0 + 3 * 1600.0

    def test_single_does_not_count_spouse_boxes(self):
        # spouse flags are ignored when not MFJ
        d = compute_first_pass(Workpaper(
            filing_status="single", spouse_65_or_older=True,
            spouse_blind=True, docs=[SourceDoc("W-2", "a", wages=50000.0)]))
        assert d.standard_deduction == 15750.0

    def test_65_plus_flags_the_uncomputed_obbba_senior_deduction(self):
        d = compute_first_pass(Workpaper(
            filing_status="single", taxpayer_65_or_older=True,
            docs=[SourceDoc("W-2", "a", wages=50000.0)]))
        assert any("OBBBA senior" in i for i in d.open_items)

    def test_prior_year_overpayment_reduces_the_balance(self):
        docs = [SourceDoc("W-2", "a", wages=60000.0, federal_withholding=5000.0)]
        base = compute_first_pass(Workpaper(filing_status="single",
                                            docs=list(docs)))
        applied = compute_first_pass(Workpaper(
            filing_status="single", prior_year_overpayment=1500.0,
            docs=list(docs)))
        assert round(base.balance - applied.balance, 2) == 1500.0
        assert "Prior-yr overpayment" in render_review_package(applied)

    def test_estimated_payments_reduce_the_balance(self):
        docs = [SourceDoc("W-2", "a", wages=60000.0, federal_withholding=5000.0)]
        base = compute_first_pass(Workpaper(filing_status="single",
                                            docs=list(docs)))
        withest = compute_first_pass(Workpaper(
            filing_status="single", estimated_payments=3000.0,
            docs=list(docs)))
        assert round(base.balance - withest.balance, 2) == 3000.0
        assert "Estimated payments" in render_review_package(withest)

    def test_payments_exceeding_income_is_flagged(self):
        d = compute_first_pass(Workpaper(
            filing_status="single",
            docs=[SourceDoc("W-2", "a", wages=5000.0,
                            federal_withholding=9000.0)]))
        assert any("exceed total income" in i for i in d.open_items)

    def test_bundle_without_additional_table_still_applies_it(self):
        # A constants bundle predating the field must not silently drop the
        # senior deduction -- the built-in table is the fallback.
        import copy
        old = copy.deepcopy(tax_prep.TY2025)
        del old["additional_standard_deduction"]
        d = compute_first_pass(Workpaper(
            filing_status="single", taxpayer_65_or_older=True,
            docs=[SourceDoc("W-2", "a", wages=50000.0)]), constants=old)
        assert d.standard_deduction == 17750.0


class TestFilingStatusNormalization:
    def test_uppercase_filing_status_is_honored_not_silently_single(self):
        # "MFJ" must compute as MFJ ($31,500 std deduction), not fall back to
        # single ($15,750) -- agents build Workpapers directly, bypassing the
        # CLI's click.Choice gate.
        for raw in ("MFJ", "mfj", "  Mfj "):
            d = compute_first_pass(
                Workpaper(filing_status=raw, docs=[SourceDoc("W-2", "a",
                          wages=100000.0)]))
            assert d.standard_deduction == 31500.0, raw
            assert not any("not supported" in i for i in d.open_items), raw

    def test_genuinely_unsupported_status_still_flagged(self):
        # mfs / qualifying-widow are real statuses outside the v1 scope: they
        # are flagged (and fall back), never silently miscomputed.
        d = compute_first_pass(
            Workpaper(filing_status="MFS", docs=[SourceDoc("W-2", "a",
                      wages=100000.0)]))
        assert any("not supported" in i for i in d.open_items)
        assert tax_prep.normalize_filing_status("MFJ") == "mfj"


class TestFirstPassComputation:
    def test_single_w2_only_hand_computed(self):
        # Single, $85,000 wages, $9,000 withheld. Std deduction 15,750 ->
        # taxable 69,250. Tax: 1,192.50 + 4,386.00 + 22%*20,775 = 10,149.00.
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("W-2", "W-2 — Acme", wages=85000.0,
                      federal_withholding=9000.0),
        ])
        d = compute_first_pass(wp)
        assert d.taxable_income == 69250.0
        assert d.tax_before_credits == 10149.0
        assert d.balance == 1149.0  # owes
        assert d.open_items == []

    def test_mfj_with_kids_refund_hand_computed(self):
        # MFJ, $120,000 wages, $11,000 withheld, 2 kids. Std 31,500 ->
        # taxable 88,500. Tax: 2,385 + 12%*64,650 = 10,143. CTC 4,400 ->
        # 5,743 after credits; refund 5,257.
        wp = Workpaper(filing_status="mfj", dependents_under_17=2, docs=[
            SourceDoc("W-2", "W-2 — A", wages=70000.0,
                      federal_withholding=6000.0),
            SourceDoc("W-2", "W-2 — B", wages=50000.0,
                      federal_withholding=5000.0),
        ])
        d = compute_first_pass(wp)
        assert d.tax_before_credits == 10143.0
        assert d.child_tax_credit == 4400.0
        assert d.balance == -5257.0  # refund

    def test_ctc_phaseout_hand_computed(self):
        # MFJ, $412,500 income: $12,500 over the 400k start -> 13 units of
        # $50 = $650 off the $4,400 credit. Taxable 381,000 -> tax 77,134.
        wp = Workpaper(filing_status="mfj", dependents_under_17=2, docs=[
            SourceDoc("W-2", "W-2 — Exec", wages=412500.0),
        ])
        d = compute_first_pass(wp)
        assert d.tax_before_credits == 77134.0
        assert d.child_tax_credit == 4400.0 - 650.0

    def test_ctc_capped_at_tax_never_negative(self):
        wp = Workpaper(filing_status="hoh", dependents_under_17=3, docs=[
            SourceDoc("W-2", "W-2", wages=25000.0),
        ])
        d = compute_first_pass(wp)
        assert d.child_tax_credit == d.tax_before_credits
        assert d.tax_after_credits == 0.0

    def test_interest_and_dividends_roll_into_income(self):
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("W-2", "W-2", wages=50000.0),
            SourceDoc("1099-INT", "INT", interest=400.0),
            SourceDoc("1099-DIV", "DIV", ordinary_dividends=600.0),
        ])
        d = compute_first_pass(wp)
        assert d.total_income == 51000.0
        descs = [desc for desc, _, _ in d.lines]
        assert any("interest" in s.lower() for s in descs)
        assert any("dividends" in s.lower() for s in descs)


class TestStateFirstPass:
    def _wp(self, state="", wages=85000.0, state_wh=2609.50, status="single"):
        from maverick.tax_prep import Workpaper as WP
        return WP(filing_status=status, state=state, docs=[
            SourceDoc("W-2", "W-2 — Acme", wages=wages,
                      state="PA" if not state else state,
                      state_withholding=state_wh),
        ])

    def test_pa_flat_hand_computed(self):
        # PA: flat 3.07% on income, no standard deduction.
        # 85,000 * .0307 = 2,609.50 -- exactly the withholding: zero balance.
        from maverick.tax_prep import compute_state_first_pass, infer_state
        wp = self._wp()
        assert infer_state(wp) == "PA"      # auto-detected from W-2 box 15
        sd = compute_state_first_pass(wp, "PA")
        assert sd.computed and sd.tax == 2609.50 and sd.balance == 0.0

    def test_az_flat_with_federal_matching_deduction(self):
        # AZ: 2.5% after the federal-matching std deduction.
        # (85,000 - 15,750) * .025 = 1,731.25.
        from maverick.tax_prep import compute_state_first_pass
        sd = compute_state_first_pass(self._wp(state="AZ"), "AZ")
        assert sd.computed and sd.state_taxable == 69250.0
        assert sd.tax == 1731.25

    def test_co_taxes_federal_taxable_income(self):
        # CO: 4.4% of federal taxable income: 69,250 * .044 = 3,047.00.
        from maverick.tax_prep import compute_state_first_pass
        sd = compute_state_first_pass(self._wp(state="CO"), "CO")
        assert sd.computed and sd.tax == 3047.00

    def test_no_tax_state_refunds_any_withholding(self):
        from maverick.tax_prep import compute_state_first_pass
        sd = compute_state_first_pass(self._wp(state="TX", state_wh=100.0), "TX")
        assert sd.computed and sd.tax == 0.0 and sd.balance == -100.0

    def test_graduated_state_is_an_explicit_handoff_not_a_guess(self):
        from maverick.tax_prep import compute_state_first_pass
        sd = compute_state_first_pass(self._wp(state="CA"), "CA")
        assert sd.computed is False
        assert sd.withholding == 2609.50    # the known figure still tallied
        joined = "\n".join(sd.open_items)
        assert "PREPARER MUST COMPLETE" in joined
        assert "cch_axcess" in joined and "gosystem_tax" in joined

    def test_graduated_state_computes_from_a_loaded_bracket_table(self):
        # When a (signed-bundle) graduated table is present, the engine
        # computes marginal state tax; with no table the state hands off.
        import copy

        from maverick.tax_prep import compute_state_first_pass
        const = copy.deepcopy(tax_prep.STATE_TY2025)
        const["graduated"] = {"NY": {"basis": "agi",
            "brackets": [(20000, 0.04), (None, 0.06)],
            "deduction": {"single": 8000.0, "mfj": 16000.0, "hoh": 8000.0}}}
        wp = Workpaper(filing_status="single", state="NY", docs=[
            SourceDoc("W-2", "a", wages=50000.0, state="NY",
                      state_withholding=2000.0)])
        sd = compute_state_first_pass(wp, "NY", constants=const)
        # taxable 42,000 -> 20,000*.04 + 22,000*.06 = 2,120
        assert sd.computed and sd.state_taxable == 42000.0 and sd.tax == 2120.0
        assert sd.rate == 0.0            # marginal: no single rate
        assert sd.balance == 120.0       # 2,120 - 2,000 withheld
        pkg = render_review_package(compute_first_pass(wp), sd)
        assert "State tax (graduated)" in pkg
        # Same state with no table loaded -> handoff
        assert compute_state_first_pass(wp, "NY").computed is False

    def test_multi_state_withholding_flagged(self):
        from maverick.tax_prep import Workpaper as WP
        from maverick.tax_prep import compute_state_first_pass
        wp = WP(filing_status="single", docs=[
            SourceDoc("W-2", "W-2 — A", wages=50000.0, state="PA",
                      state_withholding=1535.0),
            SourceDoc("W-2", "W-2 — B", wages=20000.0, state="NJ",
                      state_withholding=400.0),
        ])
        sd = compute_state_first_pass(wp, "PA")
        assert sd.withholding == 1535.0     # NJ's 400 not credited to PA
        assert any("NJ" in i and "multi-state" in i for i in sd.open_items)

    def test_unknown_state_asks_for_it(self):
        from maverick.tax_prep import compute_state_first_pass
        wp = self._wp()
        wp.docs[0].state = ""
        sd = compute_state_first_pass(wp, "")
        assert sd.computed is False
        assert any("resident state not determined" in i for i in sd.open_items)


class TestMissingItems:
    def test_out_of_scope_docs_become_preparer_open_items(self):
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("1099-NEC", "NEC — Gig", nonemployee_comp=6500.0),
            SourceDoc("K-1", "K-1 — Fund LP"),
            SourceDoc("1098", "1098 — Mortgage Co"),
            SourceDoc("UNKNOWN", "mystery.txt"),
        ])
        joined = "\n".join(missing_items(wp))
        assert "Schedule C" in joined and "Schedule E" in joined
        assert "itemizing" in joined
        assert "unclassified" in joined

    def test_judgment_docs_are_flagged_never_computed(self):
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("1099-R", "R — Fidelity"),
            SourceDoc("SSA-1099", "SSA"),
            SourceDoc("1099-G", "G — State"),
            SourceDoc("1099-B", "B — Broker"),
            SourceDoc("1098-T", "T — University"),
        ])
        joined = "\n".join(missing_items(wp))
        for needle in ("rollover", "taxability worksheet", "unemployment",
                       "Schedule D", "education credits"):
            assert needle in joined, needle
        # and none of them leak into the federal computation
        assert compute_first_pass(wp).total_income == 0.0

    def test_qualified_dividends_are_flagged_not_silently_taxed_at_ordinary_rates(self):
        """The first pass taxes all of box 1a at ordinary rates. A client with
        qualified dividends (box 1b) therefore gets an overstated estimate, so
        the preparer must be told to apply the qualified-dividend worksheet."""
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("W-2", "W-2 — Acme", wages=50000.0),
            SourceDoc("1099-DIV", "DIV — Broker", ordinary_dividends=3000.0,
                      qualified_dividends=2400.0),
        ])
        items = compute_first_pass(wp).open_items
        flagged = [i for i in items if "DIV — Broker" in i and "qualified" in i.lower()]
        assert len(flagged) == 1, items
        assert "$2,400.00" in flagged[0]
        assert "ordinary rates" in flagged[0]
        assert "may be too high" in flagged[0]
        assert "Qualified Dividends and Capital Gain Tax Worksheet" in flagged[0]
        assert "PREPARER MUST" in flagged[0]
        # The computation itself is unchanged and stays conservative: all of
        # box 1a is still in income.
        assert compute_first_pass(wp).total_income == 53000.0

    def test_dividends_without_a_box_1b_still_ask_the_preparer_to_confirm(self):
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("1099-DIV", "DIV", ordinary_dividends=600.0)])
        flagged = [i for i in missing_items(wp) if "qualified" in i.lower()]
        assert len(flagged) == 1, flagged
        assert "no box 1b" in flagged[0]

    def test_no_qualified_dividend_item_without_dividends(self):
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("W-2", "a", wages=50000.0),
            SourceDoc("1099-INT", "INT", interest=400.0)])
        assert not any("qualified" in i.lower() for i in missing_items(wp))

    def test_dividend_forms_differing_only_in_box_1b_are_not_duplicates(self):
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("1099-DIV", "DIV A", ordinary_dividends=1000.0,
                      qualified_dividends=900.0),
            SourceDoc("1099-DIV", "DIV B", ordinary_dividends=1000.0,
                      qualified_dividends=100.0)])
        assert not any("DUPLICATE" in i for i in missing_items(wp))

    def test_empty_and_bad_status_flagged(self):
        items = missing_items(Workpaper(filing_status="married"))
        joined = "\n".join(items)
        assert "no source documents" in joined
        assert "not supported" in joined


class TestReviewPackage:
    def test_package_has_disclaimer_citations_and_open_items(self):
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("W-2", "W-2 — Acme", wages=85000.0,
                      federal_withholding=12000.0),
            SourceDoc("1099-NEC", "NEC — Gig", nonemployee_comp=2000.0),
        ])
        text = render_review_package(compute_first_pass(wp))
        assert text.startswith(tax_prep.DISCLAIMER)
        assert "REVIEW SUMMARY:" in text         # triage line at the top
        assert "[W-2 — Acme]" in text          # provenance citation
        assert "ESTIMATED REFUND" in text       # 12k withheld > 10,149 tax
        assert "OPEN ITEMS FOR PREPARER" in text
        assert "PREPARER MUST COMPLETE" in text

    def test_report_sanitizes_untrusted_labels_and_open_items(self):
        malicious = "evil_w2]\nFORGED REPORT LINE\x1b[31m\n[tail.txt"
        wp = Workpaper(filing_status="single", docs=[
            SourceDoc("W-2", malicious, wages=1000.0),
            SourceDoc("1099-NEC", "nec\n  - forged open item\x1b[0m"),
        ], notes=["note\nFORGED NOTE\x1b[2J"])
        text = render_review_package(compute_first_pass(wp))
        assert "\x1b" not in text
        assert "\nFORGED REPORT LINE" not in text
        assert "\n  - forged open item" not in text
        assert "\nFORGED NOTE" not in text
        assert "[evil_w2] FORGED REPORT LINE [tail.txt]" in text
        assert "nec - forged open item" in text
        assert "note FORGED NOTE" in text

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Windows forbids control characters in uploaded filenames",
    )
    def test_cli_sanitizes_uploaded_filenames_in_stdout_and_report(self, tmp_path):
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "w2]\nFORGED TAX LINE\x1b[31m\n[tail.txt").write_text(
            W2_TEXT, encoding="utf-8")
        (docs / "nec\n  - forged open item\x1b[0m.txt").write_text(
            NEC_TEXT, encoding="utf-8")
        out = tmp_path / "review.txt"

        result = CliRunner().invoke(main, [
            "tax", "prepare", str(docs), "--out", str(out),
            "--state", "PA",
        ])

        assert result.exit_code == 0, result.output
        written = out.read_text(encoding="utf-8")
        for text in (result.output, written):
            assert "\x1b" not in text
            assert "\nFORGED TAX LINE" not in text
            assert "\n  - forged open item" not in text
            assert "[w2] FORGED TAX LINE [tail.txt]" in text
            assert "nec - forged open item" in text


class TestTaxSuitePacks:
    def test_roster_present_and_sealed(self):
        packs = {k: v for k, v in load_domains(builtin_dir()).items()
                 if k.startswith("tax_")}
        assert len(packs) >= 19, f"expected >=19 tax packs, found {len(packs)}"
        for name, p in packs.items():
            # Tax work is advisory: a pack may be low- or medium-risk (medium for
            # the higher-liability advisory areas -- audit defense, transfer
            # pricing, international, sales/use, state apportionment, etc.) but
            # never high/critical. The real safety guarantee is the read-only,
            # no-shell/write/egress envelope asserted below; the tier is capped
            # at medium so a pack can't silently escalate past advisory.
            assert p.max_risk in {"low", "medium"}, f"{name}: risk={p.max_risk!r}"
            assert len(p.persona.strip()) >= 200, f"{name}: thin persona"
            assert p.compartment.startswith("tax_"), name
            cap = p.capability(f"agent:{name}")
            assert "shell" in p.deny_tools and "write_file" in p.deny_tools
            for dangerous in ("shell", "write_file", "code_exec"):
                assert cap.permits(dangerous) is False, f"{name}: {dangerous}"
            # Confidentiality invariant, enforced by CORPUS (not by pack name so a
            # new pack can't slip past): a tax pack is EITHER a client-data pack
            # -- reads the client `tax` corpus, no web egress, so taxpayer data
            # can never leave -- OR a web-research pack on the `tax_law` firm
            # library with no client corpus and no read_file. The two must never
            # co-locate: client data + web egress is an exfiltration path.
            if p.knowledge_sources == ["tax_law"]:   # web-research class
                assert cap.permits("web_search") is True, name
                assert cap.permits("read_file") is False, name
            else:                                     # client-data class
                assert p.knowledge_sources == ["tax"], name
                assert cap.permits("read_file") is True, name
                for egress in ("web_search", "browser"):
                    assert cap.permits(egress) is False, f"{name}: {egress}"

    def test_law_watch_has_the_inverse_seal(self):
        # The one pack with web access is the one pack with NO client data:
        # it monitors IRS/state guidance against the firm's tax-law library,
        # and never touches the client-document corpus.
        p = load_domains(builtin_dir())["tax_law_watch"]
        cap = p.capability("agent:tax_law_watch")
        assert cap.permits("web_search") is True
        assert cap.permits("knowledge_search") is True
        assert cap.permits("read_file") is False
        assert "read_file" in p.deny_tools
        assert p.knowledge_sources == ["tax_law"]   # not the client corpus
        assert "constants" in p.persona and "signed" in p.persona

    def test_suite_registered_with_discipline(self):
        from maverick.domain import suite_for
        from maverick.domain_discipline import discipline_for
        assert suite_for("tax_workpaper_assembler") == "tax"
        block = discipline_for("tax_workpaper_assembler")
        assert "Tax preparation discipline" in block
        assert "never" in block.lower()


class TestTaxEngineConnectors:
    """CCH Axcess + Thomson Reuters GoSystem: the firm's authoritative tax
    engines. Write connectors exist (confirm-gated, high risk); the tax_
    packs get GET-only LOW read seats for return/e-file status."""

    def _tools(self):
        from maverick.tools.enterprise_connectors import enterprise_connectors
        return {t.name: t for t in enterprise_connectors()}

    def test_registered_with_read_seats(self):
        from maverick.tools.enterprise_connectors import (
            ENTERPRISE_CONNECTOR_NAMES,
            READ_CONNECTOR_NAMES,
            READ_CONNECTOR_RISKS,
        )
        for vendor in ("cch_axcess", "gosystem_tax"):
            assert vendor in ENTERPRISE_CONNECTOR_NAMES
            assert f"{vendor}_read" in READ_CONNECTOR_NAMES
            assert READ_CONNECTOR_RISKS[f"{vendor}_read"] == "low"

    def test_read_seats_are_get_only_low_risk_and_path_limited(self):
        from maverick.safety.tool_risk import tool_risk
        tools = self._tools()
        blocked_paths = {
            "cch_axcess": "/api/DocumentService/v1.0/clients/123/documents",
            "gosystem_tax": "/returns/2025/client/123/full-return",
        }
        for vendor in ("cch_axcess", "gosystem_tax"):
            seat = tools[f"{vendor}_read"]
            assert seat.input_schema["properties"]["op"]["enum"] == ["get"]
            assert tool_risk(f"{vendor}_read") == "low"
            out = seat.fn({"op": "post", "path": "/api/x", "confirm": True})
            assert "read-only" in out
            out = seat.fn({"op": "get", "path": blocked_paths[vendor]})
            assert "read path is not allowed" in out
            # the write connector stays auto-classified high (submission/
            # modification of returns never reachable from a low pack)
            assert tool_risk(vendor) == "high"

    def test_missing_creds_fail_loudly_naming_the_envs(self, monkeypatch):
        for env in ("CCH_AXCESS_BASE_URL", "CCH_AXCESS_TOKEN"):
            monkeypatch.delenv(env, raising=False)
        out = self._tools()["cch_axcess"].fn({"op": "get", "path": "/api/x"})
        assert "ERROR" in out
        assert "CCH_AXCESS_BASE_URL" in out and "CCH_AXCESS_TOKEN" in out

    def test_cch_subscription_key_prompted_by_the_wizard_catalog(self):
        from maverick.tools.enterprise_connectors import connector_catalog
        entry = next(e for e in connector_catalog() if e["name"] == "cch_axcess")
        assert ("CCH_AXCESS_SUBSCRIPTION_KEY", True) in entry["env"]

    def test_status_packs_can_reach_the_read_seats(self):
        packs = load_domains(builtin_dir())
        for name in ("tax_efile_status", "tax_prior_year_compare",
                     "tax_season_ops", "tax_intake_checklist"):
            cap = packs[name].capability(f"agent:{name}")
            assert cap.permits("cch_axcess_read") is True, name
            assert cap.permits("gosystem_tax_read") is True, name
            assert cap.permits("cch_axcess") is False, name   # write seat
            assert cap.permits("gosystem_tax") is False, name


class TestJsonOutput:
    def test_review_package_dict_is_serializable_and_complete(self):
        wp = Workpaper(filing_status="single", estimated_payments=1000.0,
                       docs=[SourceDoc("W-2", "a", wages=80000.0,
                                       federal_withholding=9000.0)])
        draft = compute_first_pass(wp)
        from maverick.tax_prep import compute_state_first_pass, review_package_dict
        state = compute_state_first_pass(wp, "PA")
        data = review_package_dict(draft, state)
        import json
        json.dumps(data)                                   # must serialize
        assert data["federal"]["total_income"] == 80000.0
        assert data["federal"]["estimated_payments"] == 1000.0
        assert data["state"]["state"] == "PA"
        assert data["is_draft"] is True

    def test_cli_json_format_emits_valid_json(self, tmp_path):
        (tmp_path / "w2.txt").write_text(W2_TEXT, encoding="utf-8")
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "prepare", str(tmp_path),
            "--filing-status", "single", "--format", "json"])
        assert res.exit_code == 0, res.output
        import json
        data = json.loads(res.stdout)
        assert data["federal"]["total_income"] == 85000.0
        assert "constants" in data

    def test_cli_json_format_keeps_out_status_off_stdout(self, tmp_path):
        (tmp_path / "w2.txt").write_text(W2_TEXT, encoding="utf-8")
        out = tmp_path / "review.json"
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "prepare", str(tmp_path),
            "--filing-status", "single", "--format", "json",
            "--out", str(out)])
        assert res.exit_code == 0, res.output
        import json
        data = json.loads(res.stdout)
        assert data["federal"]["total_income"] == 85000.0
        assert json.loads(out.read_text(encoding="utf-8"))["constants"]
        assert "Wrote review package" in res.stderr

    def test_cli_json_format_keeps_update_status_off_stdout(
            self, tmp_path, monkeypatch):
        (tmp_path / "w2.txt").write_text(W2_TEXT, encoding="utf-8")
        from maverick import tax_constants
        monkeypatch.setattr(tax_constants, "check_for_update",
                            lambda: ("applied", "test constants updated"))
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "prepare", str(tmp_path),
            "--filing-status", "single", "--format", "json"])
        assert res.exit_code == 0, res.output
        import json
        assert json.loads(res.stdout)["federal"]["total_income"] == 85000.0
        assert "[tax] test constants updated" in res.stderr


class TestTaxPrepareCli:
    def test_docs_folder_to_review_package(self, tmp_path):
        (tmp_path / "w2_acme.txt").write_text(W2_TEXT, encoding="utf-8")
        (tmp_path / "int_bank.txt").write_text(INT_TEXT, encoding="utf-8")
        (tmp_path / "nec_gig.txt").write_text(NEC_TEXT, encoding="utf-8")
        out = tmp_path / "review.txt"
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "prepare", str(tmp_path),
            "--filing-status", "single", "--out", str(out),
        ])
        assert res.exit_code == 0, res.output
        assert "DRAFT FORM 1040" in res.output
        assert "[w2_acme.txt]" in res.output          # cited to the upload
        assert "Schedule C" in res.output              # NEC flagged, not computed
        # State auto-detected from W-2 box 15 and computed (PA flat).
        assert "DRAFT PA STATE RETURN" in res.output
        assert "State tax (flat 3.07%)" in res.output
        assert out.read_text(encoding="utf-8").startswith(tax_prep.DISCLAIMER)

    def test_state_override_beats_autodetect(self, tmp_path):
        (tmp_path / "w2.txt").write_text(W2_TEXT, encoding="utf-8")
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "prepare", str(tmp_path),
            "--state", "CA",
        ])
        assert res.exit_code == 0, res.output
        assert "DRAFT CA STATE RETURN" in res.output
        assert "PREPARER MUST COMPLETE" in res.output  # graduated: handed off

    def test_empty_folder_is_an_open_item_not_a_crash(self, tmp_path):
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "prepare", str(tmp_path),
        ])
        assert res.exit_code == 0, res.output
        assert "no source documents provided" in res.output
