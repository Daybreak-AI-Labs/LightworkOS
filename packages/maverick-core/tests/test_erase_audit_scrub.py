"""`maverick erase` must scrub the subject from the audit log too.

GDPR Art. 17: erase already wiped world-model rows + attachment files and
recorded a hashed erase event, but it never scrubbed the user's PII from
the audit NDJSON -- so goal/turn text the agent logged survived the
"erasure". erase now calls audit.scrub_user().
"""
import os


def test_erase_calls_audit_scrub_user(tmp_path, monkeypatch):
    os.environ.pop("MAVERICK_DB", None)
    import maverick.audit as audit_mod
    from click.testing import CliRunner
    from maverick import cli as cli_mod
    from maverick.world_model import WorldModel

    scrub_calls: list = []
    monkeypatch.setattr(
        audit_mod, "scrub_user",
        lambda channel, user_id, **kw: (scrub_calls.append((channel, user_id)) or (2, 5)),
    )
    # Don't write a real audit file when erase records its event.
    monkeypatch.setattr(audit_mod, "record", lambda kind, **payload: None)

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    conv_id = wm.get_or_create_conversation("telegram", "u123").id
    gid = wm.create_goal("hello")
    wm.append_turn(conv_id, "user", "hi there", goal_id=gid)
    wm.close()

    result = CliRunner().invoke(
        cli_mod.main,
        ["--db", str(db), "erase", "--channel", "telegram",
         "--user", "u123", "--yes"],
    )
    assert result.exit_code == 0, result.output
    # The audit NDJSON scrub ran for exactly this subject...
    assert ("telegram", "u123") in scrub_calls
    # ...and the count is surfaced to the operator.
    assert "2 audit event(s) scrubbed" in result.output
