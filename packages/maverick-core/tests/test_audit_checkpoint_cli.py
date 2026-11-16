"""CLI wiring for independent live audit-tip checkpoints."""
from __future__ import annotations

import hashlib
import time

import pytest
from click.testing import CliRunner

pytest.importorskip("cryptography")

from maverick.audit import signing  # noqa: E402
from maverick.audit.events import AuditEvent  # noqa: E402
from maverick.audit.writer import AuditLog  # noqa: E402
from maverick.cli import main  # noqa: E402


def _isolated_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(signing, "KEY_DIR", signing._LEGACY_KEY_DIR)
    from maverick.paths import data_dir

    audit_dir = data_dir("audit")
    log = AuditLog(audit_dir, sign=True)
    assert log.record(
        AuditEvent(ts=time.time(), kind="tool_call", payload={"tool": "read"})
    )
    return audit_dir


def test_checkpoint_publish_then_verify(tmp_path, monkeypatch):
    _isolated_home(monkeypatch, tmp_path)
    checkpoints = tmp_path / "external-checkpoints"
    runner = CliRunner()

    published = runner.invoke(
        main,
        [
            "audit",
            "checkpoint",
            "publish",
            "--checkpoint-dir",
            str(checkpoints),
        ],
    )
    assert published.exit_code == 0, published.output
    assert "published" in published.output

    verified = runner.invoke(
        main,
        [
            "audit",
            "checkpoint",
            "verify",
            "--checkpoint-dir",
            str(checkpoints),
            "--minimum-sequence",
            "1",
        ],
    )
    assert verified.exit_code == 0, verified.output
    assert "independent audit checkpoints intact" in verified.output
    assert "assurance incomplete" in verified.output


def test_checkpoint_verify_fails_without_commitment(tmp_path, monkeypatch):
    _isolated_home(monkeypatch, tmp_path)
    checkpoints = tmp_path / "external-checkpoints"
    checkpoints.mkdir()

    result = CliRunner().invoke(
        main,
        [
            "audit",
            "checkpoint",
            "verify",
            "--checkpoint-dir",
            str(checkpoints),
        ],
    )

    assert result.exit_code == 1, result.output
    assert "checkpoint_missing" in result.output


def test_checkpoint_verify_reports_external_assurance_only_when_fully_pinned(
    tmp_path,
    monkeypatch,
):
    _isolated_home(monkeypatch, tmp_path)
    checkpoints = tmp_path / "external-checkpoints"
    runner = CliRunner()
    published = runner.invoke(
        main,
        [
            "audit",
            "checkpoint",
            "publish",
            "--checkpoint-dir",
            str(checkpoints),
        ],
    )
    assert published.exit_code == 0, published.output
    checkpoint = next(checkpoints.glob("audit-checkpoint-*.ndjson"))
    digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    public_key = next(iter(signing.trusted_audit_public_keys().values()))

    result = runner.invoke(
        main,
        [
            "audit",
            "checkpoint",
            "verify",
            "--checkpoint-dir",
            str(checkpoints),
            "--minimum-sequence",
            "1",
            "--minimum-digest",
            digest,
            "--pubkey",
            public_key,
        ],
    )

    assert result.exit_code == 0, result.output
    assert "externally pinned" in result.output
    assert "assurance incomplete" not in result.output


def test_checkpoint_cli_surfaces_invalid_key_as_controlled_error(
    tmp_path,
    monkeypatch,
):
    _isolated_home(monkeypatch, tmp_path)
    checkpoints = tmp_path / "external-checkpoints"

    result = CliRunner().invoke(
        main,
        [
            "audit",
            "checkpoint",
            "publish",
            "--checkpoint-dir",
            str(checkpoints),
            "--pubkey",
            "not-hex",
        ],
    )

    assert result.exit_code == 1, result.output
    assert "Error:" in result.output
    assert "valid hex" in result.output
    assert "Traceback" not in result.output


def test_erase_then_new_checkpoint_fails_an_older_pin_until_it_is_retained(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(signing, "KEY_DIR", signing._LEGACY_KEY_DIR)
    from maverick.paths import data_dir

    day = "2000-01-01"
    closed = signing.AuditSigner(data_dir("audit") / f"{day}.ndjson")
    assert closed.write({"kind": "tool_call", "channel": "telegram", "user_id": "alice"})
    assert closed.write({"kind": "tool_call", "tool": "read"})
    assert signing.ensure_anchors(data_dir("audit")) == 1
    checkpoints = tmp_path / "external-checkpoints"
    runner = CliRunner()
    base = ["--checkpoint-dir", str(checkpoints)]

    def digest(sequence: int) -> str:
        path = checkpoints / f"audit-checkpoint-{sequence:020d}.ndjson"
        return hashlib.sha256(path.read_bytes()).hexdigest()

    first = runner.invoke(main, ["audit", "checkpoint", "publish", "--day", day, *base])
    assert first.exit_code == 0, first.output
    pinned = digest(1)
    erased = runner.invoke(main, [
        "erase", "--channel", "telegram", "--user", "alice", "--yes", *base,
    ])
    assert erased.exit_code == 0, erased.output
    assert "1 audit event(s) scrubbed" in erased.output

    replaced = runner.invoke(main, [
        "audit", "checkpoint", "publish", "--day", day, *base,
        "--supersede-digest", pinned, "--lifecycle-reason", "gdpr_reanchor",
    ])
    assert replaced.exit_code == 0, replaced.output

    stale = runner.invoke(main, [
        "audit", "checkpoint", "verify", *base,
        "--minimum-sequence", "1", "--minimum-digest", pinned,
    ])
    assert stale.exit_code == 1, stale.output
    assert "superseded_after_pin" in stale.output and "1 of 2 rows" in stale.output
    # On a copy without the world database the erasure cannot be looked up:
    # that is "not checked", never "no record", and no database is created.
    missing = tmp_path / "copy" / "world.db"
    copy = runner.invoke(main, [
        "--db", str(missing), "audit", "checkpoint", "verify", *base,
        "--minimum-sequence", "1", "--minimum-digest", pinned,
    ])
    assert copy.exit_code == 1, copy.output
    assert "superseded_erase_record_unchecked" in copy.output
    assert "superseded_without_erase_record" not in copy.output
    assert not missing.exists()
    retained = runner.invoke(main, [
        "audit", "checkpoint", "verify", *base,
        "--minimum-sequence", "2", "--minimum-digest", digest(2),
    ])
    assert retained.exit_code == 0, retained.output


def test_publishing_without_an_erase_record_is_recorded_first(tmp_path, monkeypatch):
    import json

    import maverick.audit as audit_pkg
    from maverick.audit import AuditRefused
    from maverick.audit.erase import scrub_user

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr(signing, "KEY_DIR", signing._LEGACY_KEY_DIR)
    from maverick.paths import data_dir

    day = "2000-01-01"
    audit_dir = data_dir("audit")
    closed = signing.AuditSigner(audit_dir / f"{day}.ndjson")
    assert closed.write({"kind": "tool_call", "channel": "telegram", "user_id": "alice"})
    assert closed.write({"kind": "tool_call", "tool": "read"})
    assert signing.ensure_anchors(audit_dir) == 1
    checkpoints = tmp_path / "external-checkpoints"
    runner = CliRunner()
    base = ["--checkpoint-dir", str(checkpoints)]
    from maverick.world_model import WorldModel

    WorldModel(tmp_path / "world.db").close()  # the installation's, with no erase records
    cli = ["--db", str(tmp_path / "world.db"), "audit", "checkpoint"]
    assert runner.invoke(main, [*cli, "publish", "--day", day, *base]).exit_code == 0
    pinned = hashlib.sha256(next(checkpoints.glob("*.ndjson")).read_bytes()).hexdigest()
    # An erasure from before erase records existed: the day changed, no record.
    assert scrub_user("telegram", "alice", audit_dir=audit_dir)[0] == 1
    override = [
        *cli, "publish", "--day", day, *base, "--supersede-digest", pinned,
        "--lifecycle-reason", "gdpr_reanchor", "--without-erase-record",
    ]

    def refuse(kind, **payload):
        raise AuditRefused("refused")

    with monkeypatch.context() as patch:
        patch.setattr(audit_pkg, "audit_event", refuse)
        refused = runner.invoke(main, override)
    assert refused.exit_code != 0 and "nothing was published" in refused.output
    assert len(list(checkpoints.glob("audit-checkpoint-*.ndjson"))) == 1

    published = runner.invoke(main, override)
    assert published.exit_code == 0, published.output
    rows = [
        json.loads(line)
        for path in audit_dir.glob("*.ndjson")
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    (trace,) = [row for row in rows
                if row.get("action") == "audit_checkpoint_publish_without_erase_record"]
    assert trace["kind"] == "control_plane_action" and trace["actor"].startswith("cli")
    assert (trace["day"], trace["replaces_sequence"], trace["sequence"]) == (day, 1, 2)

    stale = runner.invoke(main, [
        *cli, "verify", *base, "--minimum-sequence", "1", "--minimum-digest", pinned,
    ])
    assert stale.exit_code == 1, stale.output
    assert "superseded_without_erase_record" in stale.output
    assert "published without" in stale.output


def test_a_person_is_erased_from_a_day_an_earlier_version_already_erased(tmp_path, monkeypatch):
    # What an upgrade finds: a checkpointed day, erased once by a version that
    # stored no erase record, its checkpoint never replaced. A second person
    # in that day must still be erasable, and each next step must be named.
    from maverick.audit.erase import scrub_user

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(signing, "KEY_DIR", signing._LEGACY_KEY_DIR)
    from maverick.paths import data_dir

    day = "2000-01-01"
    audit_dir = data_dir("audit")
    day_file = audit_dir / f"{day}.ndjson"
    closed = signing.AuditSigner(day_file)
    for person in ("alice", "bob"):
        assert closed.write({"kind": "tool_call", "channel": "telegram", "user_id": person})
    assert closed.write({"kind": "tool_call", "tool": "read"})
    assert signing.ensure_anchors(audit_dir) == 1
    checkpoints = data_dir("audit-checkpoints")  # a folder the erase compares with
    runner = CliRunner()
    base = ["--checkpoint-dir", str(checkpoints)]
    assert runner.invoke(main, ["audit", "checkpoint", "publish", "--day", day, *base]).exit_code == 0
    pinned = hashlib.sha256(next(checkpoints.glob("*.ndjson")).read_bytes()).hexdigest()
    assert scrub_user("telegram", "alice", audit_dir=audit_dir)[0] == 1  # as the base did

    erased = runner.invoke(main, ["erase", "--channel", "telegram", "--user", "bob", "--yes"])
    assert erased.exit_code == 0, erased.output
    assert "1 audit event(s) scrubbed" in erased.output
    assert "bob" not in day_file.read_text(encoding="utf-8")
    assert "backup" not in erased.output

    # Neither erasure vouches for that checkpoint, so replacing it is the
    # override, and the refusal says so before anything else.
    replace = [
        "audit", "checkpoint", "publish", "--day", day, *base,
        "--supersede-digest", pinned, "--lifecycle-reason", "gdpr_reanchor",
    ]
    refused = runner.invoke(main, replace)
    assert refused.exit_code != 0
    assert "--without-erase-record" in refused.output
    assert "maverick erase --checkpoint-dir" not in refused.output
    assert runner.invoke(main, [*replace, "--without-erase-record"]).exit_code == 0
    stale = runner.invoke(main, [
        "audit", "checkpoint", "verify", *base,
        "--minimum-sequence", "1", "--minimum-digest", pinned,
    ])
    assert stale.exit_code == 1 and "superseded_without_erase_record" in stale.output


def test_retire_prints_what_to_retain_and_a_pinned_check_says_what_to_look_at(
    tmp_path,
    monkeypatch,
):
    import json

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(signing, "KEY_DIR", signing._LEGACY_KEY_DIR)
    from maverick.paths import data_dir

    day = "2000-01-01"
    audit_dir = data_dir("audit")
    day_file = audit_dir / f"{day}.ndjson"
    assert signing.AuditSigner(day_file).write({"kind": "tool_call", "tool": "read"})
    assert signing.ensure_anchors(audit_dir) == 1
    checkpoints = tmp_path / "external-checkpoints"
    runner = CliRunner()
    base = ["--checkpoint-dir", str(checkpoints)]
    assert runner.invoke(main, ["audit", "checkpoint", "publish", "--day", day, *base]).exit_code == 0
    first = checkpoints / f"audit-checkpoint-{1:020d}.ndjson"
    pinned = hashlib.sha256(first.read_bytes()).hexdigest()
    record = json.loads(first.read_text(encoding="utf-8"))
    day_file.unlink()
    assert signing.record_retention_purge(
        audit_dir, [{"day": day, "row_count": record["row_count"], "tip_hash": record["tip_hash"]}])

    retired = runner.invoke(main, [
        "audit", "checkpoint", "retire", *base,
        "--supersede-digest", pinned, "--lifecycle-reason", "retention_purge",
    ])
    assert retired.exit_code == 0, retired.output
    second = checkpoints / f"audit-checkpoint-{2:020d}.ndjson"
    newest = hashlib.sha256(second.read_bytes()).hexdigest()
    assert f"retain externally: sequence=2 sha256={newest}" in retired.output

    stale = runner.invoke(main, [
        "audit", "checkpoint", "verify", *base,
        "--minimum-sequence", "1", "--minimum-digest", pinned,
    ])
    assert stale.exit_code == 1, stale.output
    assert "retired_after_pin" in stale.output
    assert "a retention purge you expected" in stale.output
    assert runner.invoke(main, [
        "audit", "checkpoint", "verify", *base,
        "--minimum-sequence", "2", "--minimum-digest", newest,
    ]).exit_code == 0


def test_an_erase_whose_record_cannot_be_stored_says_so_and_keeps_no_lock(tmp_path, monkeypatch):
    import threading

    import maverick.erasure_receipts as receipts
    from maverick.audit.erase import scrub_user

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(signing, "KEY_DIR", signing._LEGACY_KEY_DIR)
    from maverick.paths import data_dir

    audit_dir = data_dir("audit")
    day_file = audit_dir / "2000-01-01.ndjson"
    closed = signing.AuditSigner(day_file)
    for person in ("alice", "bob"):
        assert closed.write({"kind": "tool_call", "channel": "telegram", "user_id": person})
    assert signing.ensure_anchors(audit_dir) == 1

    def store_is_down(*args, **kwargs):
        raise receipts.ErasureReceiptError("store is down")

    monkeypatch.setattr(receipts, "persist_audit_erase_record", store_is_down)
    erased = CliRunner().invoke(main, ["erase", "--channel", "telegram", "--user", "alice", "--yes"])

    # The person is gone, and the run does not pass as complete without its record.
    assert "alice" not in day_file.read_text(encoding="utf-8")
    assert erased.exit_code == 1, erased.output
    assert "erasure incomplete" in erased.output and "audit_erase_record" in erased.output
    # The next erasure, from another thread, is not left waiting.
    done: list[int] = []
    other = threading.Thread(
        target=lambda: done.append(scrub_user("telegram", "bob", audit_dir=audit_dir)[0]))
    other.start()
    other.join(10)
    assert done == [1]
