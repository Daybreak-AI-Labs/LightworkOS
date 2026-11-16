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
    erased = runner.invoke(main, ["erase", "--channel", "telegram", "--user", "alice", "--yes"])
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
    retained = runner.invoke(main, [
        "audit", "checkpoint", "verify", *base,
        "--minimum-sequence", "2", "--minimum-digest", digest(2),
    ])
    assert retained.exit_code == 0, retained.output
