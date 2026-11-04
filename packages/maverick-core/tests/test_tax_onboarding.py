"""Firm onboarding: profile in -> honest pilot-readiness verdict out.

Pins the contract: states sort into computed vs handed-off vs invalid, the
document taxonomy resolves or blocks, and blockers (must fix) stay separate
from warnings (fine to pilot).
"""
from __future__ import annotations

from maverick import tax_onboarding as ob
from maverick.cli import main


class TestResolveDocType:
    def test_alias_then_canonical_then_unknown(self):
        aliases = {"Wage Statement": "W-2", "Interest Form": "1099-INT"}
        assert ob.resolve_doc_type("wage statement", aliases) == "W-2"
        assert ob.resolve_doc_type("W-2") == "W-2"          # canonical exact
        assert ob.resolve_doc_type("grocery receipt") == "UNKNOWN"

    def test_alias_to_invalid_type_does_not_resolve(self):
        assert ob.resolve_doc_type("X", {"X": "NOPE"}) == "UNKNOWN"


class TestReadiness:
    def test_states_sorted_into_computed_handoff_invalid(self):
        rep = ob.assess_readiness(ob.FirmProfile(
            name="F", states=["PA", "TX", "CA", "ZZ"]))
        assert rep.computed_states == ["PA", "TX"]      # flat + no-tax
        assert rep.handoff_states == ["CA"]             # graduated
        assert rep.invalid_states == ["ZZ"]
        assert not rep.ready_to_pilot                   # ZZ is a blocker

    def test_clean_profile_is_ready_to_pilot(self):
        rep = ob.assess_readiness(ob.FirmProfile(
            name="Clean", states=["PA", "FL"], roster_size=500,
            constants_channel_configured=True,
            doc_aliases={"Wage Statement": "W-2"}))
        assert rep.ready_to_pilot
        assert rep.resolved_aliases == {"Wage Statement": "W-2"}
        assert not rep.warnings                          # all conditions met
        assert "READY TO PILOT" in ob.render_readiness(rep)

    def test_unmapped_alias_is_a_blocker(self):
        rep = ob.assess_readiness(ob.FirmProfile(
            name="F", states=["PA"], roster_size=1,
            constants_channel_configured=True,
            doc_aliases={"Mystery": "NOT-A-TYPE"}))
        assert not rep.ready_to_pilot
        assert rep.unresolved_aliases == {"Mystery": "NOT-A-TYPE"}

    def test_graduated_state_and_no_constants_are_warnings_not_blockers(self):
        rep = ob.assess_readiness(ob.FirmProfile(
            name="F", states=["PA", "CA"], roster_size=10))
        assert rep.ready_to_pilot                        # warnings don't block
        assert any("CA" in w for w in rep.warnings)
        assert any("signed-constants" in w for w in rep.warnings)

    def test_forms_handled_are_classified_by_engine_coverage(self):
        rep = ob.assess_readiness(ob.FirmProfile(
            name="F", states=["PA"], roster_size=1,
            constants_channel_configured=True,
            forms_handled=["W-2", "1099-INT", "K-1", "Crypto 1099-DA"]))
        assert rep.forms_extracted == ["W-2", "1099-INT"]
        assert rep.forms_flagged == ["K-1"]              # classified, not computed
        assert rep.forms_unrecognized == ["Crypto 1099-DA"]
        assert rep.ready_to_pilot                         # unrecognized = warning
        assert "Forms coverage" in ob.render_readiness(rep)
        assert any("not recognized" in w for w in rep.warnings)


class TestOnboardCli:
    def test_cli_loads_toml_and_exits_nonzero_on_blockers(self, tmp_path):
        prof = tmp_path / "firm.toml"
        prof.write_text(
            '[firm]\n'
            'name = "Smith & Co"\n'
            'states = ["PA", "ZZ"]\n'
            'roster_size = 100\n'
            'constants_channel_configured = true\n',
            encoding="utf-8")
        from click.testing import CliRunner
        res = CliRunner().invoke(main, ["tax", "onboard", str(prof)])
        assert res.exit_code != 0                        # ZZ blocks
        assert "Smith & Co" in res.output
        assert "invalid state code(s): ZZ" in res.output

    def test_cli_ready_firm_exits_zero(self, tmp_path):
        prof = tmp_path / "firm.toml"
        prof.write_text(
            '[firm]\n'
            'name = "Clean CPAs"\n'
            'states = ["PA", "FL"]\n'
            'roster_size = 100\n'
            'constants_channel_configured = true\n',
            encoding="utf-8")
        from click.testing import CliRunner
        res = CliRunner().invoke(main, ["tax", "onboard", str(prof)])
        assert res.exit_code == 0
        assert "READY TO PILOT" in res.output
