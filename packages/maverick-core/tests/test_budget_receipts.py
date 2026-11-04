"""Cryptographic budget receipts: mint/verify roundtrip, tamper detection,
hash-chained append-only ledger, missing-key refusal. Offline and
deterministic — the world model is faked and the clock injected.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass

import pytest
from maverick import budget_receipts as br
from maverick.file_lock import private_path_is_restricted

KEY = "test-receipt-key"


def _make_shared_directory(path):
    path.mkdir(mode=0o777)
    if os.name == "nt":
        subprocess.run(
            ["icacls", str(path), "/grant", "*S-1-1-0:(OI)(CI)RX"],
            check=True,
            capture_output=True,
            text=True,
        )
    else:
        path.chmod(0o755)
    assert not private_path_is_restricted(path, 0o700)


def _security_snapshot(path):
    if os.name == "nt":
        import maverick.file_lock as file_lock

        return file_lock._windows_private_sddl(path)[0]
    return path.stat().st_mode & 0o777


@dataclass
class FakeEpisode:
    """Mirrors maverick.world_model.EpisodeSpend's spend fields."""

    id: int
    goal_id: int
    started_at: float
    ended_at: float | None
    outcome: str | None
    cost_dollars: float
    input_tokens: int
    output_tokens: int
    tool_calls: int


class FakeWorld:
    def __init__(self, episodes):
        self._episodes = list(episodes)

    def list_episodes(self, limit=50, goal_id=None):
        eps = [e for e in self._episodes if goal_id is None or e.goal_id == goal_id]
        return eps[:limit]


def _world():
    return FakeWorld([
        FakeEpisode(1, 7, 100.0, 160.0, "ok", 1.25, 1000, 200, 3),
        FakeEpisode(2, 7, 200.0, 260.0, "ok", 0.75, 500, 100, 2),
        FakeEpisode(3, 9, 300.0, 360.0, "ok", 99.0, 9, 9, 9),  # other goal
    ])


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_RECEIPT_KEY", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "nonexistent.toml"))


# --- mint / verify ----------------------------------------------------------

def test_mint_verify_roundtrip(tmp_path):
    path = tmp_path / "receipts.jsonl"
    line = br.mint(_world(), 7, KEY, path=path, clock=lambda: 999.0)
    assert br.verify(line, KEY) == br.VALID
    payload = json.loads(line)["payload"]
    assert payload["goal_id"] == 7
    assert payload["total_dollars"] == 2.0          # 1.25 + 0.75; goal 9 excluded
    assert payload["in_tokens"] == 1500
    assert payload["out_tokens"] == 300
    assert payload["tool_calls"] == 5
    assert payload["started_at"] == 100.0
    assert payload["ended_at"] == 260.0
    assert payload["minted_at"] == 999.0
    assert payload["prev_receipt_hash"] is None     # genesis


def test_custom_ledger_requires_private_parent_without_mutating_it(tmp_path):
    shared = tmp_path / "shared"
    _make_shared_directory(shared)
    unrelated = shared / "team-file.txt"
    unrelated.write_text("keep-access", encoding="utf-8")
    before = _security_snapshot(shared)
    path = shared / "receipts.jsonl"

    with pytest.raises(PermissionError, match="must already be private"):
        br.mint(_world(), 7, KEY, path=path)

    assert _security_snapshot(shared) == before
    assert not private_path_is_restricted(shared, 0o700)
    assert unrelated.read_text(encoding="utf-8") == "keep-access"
    assert not path.exists()
    assert not (shared / "receipts.jsonl.lock").exists()


def test_budget_caps_embedded_from_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[budget]\nmax_dollars = 5.0\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    line = br.mint(_world(), 7, KEY, path=tmp_path / "r.jsonl")
    assert json.loads(line)["payload"]["budget_caps"] == {"max_dollars": 5.0}


def test_tampered_receipt_is_invalid(tmp_path):
    line = br.mint(_world(), 7, KEY, path=tmp_path / "r.jsonl")
    doctored = json.loads(line)
    doctored["payload"]["total_dollars"] = 0.01     # shave the bill
    assert br.verify(json.dumps(doctored), KEY) == br.INVALID


def test_wrong_key_is_invalid(tmp_path):
    line = br.mint(_world(), 7, KEY, path=tmp_path / "r.jsonl")
    assert br.verify(line, "some-other-key") == br.INVALID


@pytest.mark.parametrize("blob", ["not json", "[]", '{"payload": 3}', '{"sig": "x"}'])
def test_malformed_receipts(blob):
    assert br.verify(blob, KEY) == br.MALFORMED


# --- key resolution ---------------------------------------------------------

def test_mint_refuses_without_key(tmp_path):
    with pytest.raises(br.ReceiptKeyMissing, match="MAVERICK_RECEIPT_KEY"):
        br.mint(_world(), 7, path=tmp_path / "r.jsonl")


def test_key_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_RECEIPT_KEY", "env-key")
    line = br.mint(_world(), 7, path=tmp_path / "r.jsonl")
    assert br.verify(line, "env-key") == br.VALID


def test_key_env_wins_over_config(monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[safety]\nreceipt_key = "config-key"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert br.resolve_key() == "config-key"
    monkeypatch.setenv("MAVERICK_RECEIPT_KEY", "env-key")
    assert br.resolve_key() == "env-key"


# --- chain ------------------------------------------------------------------

def test_chain_append_and_verify(tmp_path):
    path = tmp_path / "receipts.jsonl"
    for goal in (7, 9, 7):
        br.mint(_world(), goal, KEY, path=path)
    report = br.verify_chain(path, KEY)
    assert report.ok and report.count == 3 and report.broken_at is None
    # Each receipt embeds the hash of the line before it.
    lines = path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])["payload"]["prev_receipt_hash"]
    assert second == br._receipt_hash(lines[0])


def test_chain_break_on_edited_middle_line(tmp_path):
    path = tmp_path / "receipts.jsonl"
    for goal in (7, 9, 7):
        br.mint(_world(), goal, KEY, path=path)
    lines = path.read_text(encoding="utf-8").splitlines()
    doctored = json.loads(lines[1])
    doctored["payload"]["total_dollars"] = 0.0
    lines[1] = json.dumps(doctored, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = br.verify_chain(path, KEY)
    assert not report.ok and report.broken_at == 1
    assert "INVALID" in report.reason


def test_chain_break_on_deleted_line(tmp_path):
    path = tmp_path / "receipts.jsonl"
    for goal in (7, 9, 7):
        br.mint(_world(), goal, KEY, path=path)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]                                     # vanish the middle receipt
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = br.verify_chain(path, KEY)
    assert not report.ok and report.broken_at == 1
    assert "chain link" in report.reason


def test_chain_break_on_reordered_lines(tmp_path):
    path = tmp_path / "receipts.jsonl"
    for goal in (7, 9):
        br.mint(_world(), goal, KEY, path=path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    assert br.verify_chain(path, KEY).broken_at == 0


def test_empty_chain_is_ok(tmp_path):
    report = br.verify_chain(tmp_path / "absent.jsonl", KEY)
    assert report.ok and report.count == 0


def test_chain_file_mode_0600(tmp_path):
    from maverick.file_lock import private_path_is_restricted

    path = tmp_path / "receipts.jsonl"
    br.mint(_world(), 7, KEY, path=path)
    assert private_path_is_restricted(path)
    assert private_path_is_restricted(path.parent, 0o700)


# --- render -----------------------------------------------------------------

def test_render_human_readable(tmp_path):
    line = br.mint(_world(), 7, KEY, path=tmp_path / "r.jsonl")
    out = br.render(line)
    assert "goal=7" in out and "$2.0000" in out and "(genesis)" in out
    assert br.render("garbage") == "budget receipt: MALFORMED"


def test_chain_break_on_truncated_tail(tmp_path):
    # Backward links stay self-consistent after dropping the LAST receipts;
    # the high-water anchor is what catches a shaved tail.
    path = tmp_path / "receipts.jsonl"
    for goal in (7, 9, 7, 9, 7):
        br.mint(_world(), goal, KEY, path=path)
    assert br.verify_chain(path, KEY).ok
    lines = path.read_text(encoding="utf-8").splitlines()
    # Drop the two newest (e.g. most expensive) receipts.
    path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    report = br.verify_chain(path, KEY)
    assert not report.ok
    assert report.count == 3
    assert "truncated" in report.reason


def test_truncation_plus_deleted_head_is_audited_not_silently_healed(tmp_path, monkeypatch):
    # The cheapest tamper: drop the newest (priciest) receipts AND delete the
    # high-water anchor sidecar so the truncation becomes invisible. mint()
    # can't recover the true prior floor from a deleted file, but it must no
    # longer be a silent no-op rebaseline -- it has to leave a trace.
    import maverick.audit
    from maverick.audit import EventKind
    calls = []
    monkeypatch.setattr(maverick.audit, "record",
                        lambda kind, **kw: calls.append((kind, kw)) or True)

    path = tmp_path / "receipts.jsonl"
    for goal in (7, 9, 7, 9, 7):
        br.mint(_world(), goal, KEY, path=path)
    head_path = tmp_path / "receipts.jsonl.head"
    assert head_path.exists()
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    head_path.unlink()

    br.mint(_world(), 7, KEY, path=path)

    remediated = [kw for k, kw in calls if k == EventKind.CONFIG_REMEDIATED]
    assert remediated, "missing head anchor on a non-empty chain went unaudited"
    assert remediated[0]["field"] == "receipt_head_anchor"


def test_verify_chain_flags_truncation_when_head_also_deleted(tmp_path):
    # Regression: an auditor calling verify_chain directly (no subsequent mint)
    # must NOT see a cost-shaved chain as intact just because the .head anchor
    # was deleted along with the tail -- completeness can't be verified, so it
    # fails closed.
    path = tmp_path / "receipts.jsonl"
    for goal in (7, 9, 7, 9, 7):
        br.mint(_world(), goal, KEY, path=path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")
    (tmp_path / "receipts.jsonl.head").unlink()
    report = br.verify_chain(path, KEY)
    assert not report.ok
    assert "anchor missing" in report.reason


def test_forged_head_anchor_refuses_to_mint(tmp_path):
    # A head file that exists but fails its own HMAC is unambiguous tamper
    # evidence (this code only ever writes a correctly-signed head) -- mint()
    # must refuse rather than silently overwrite it with a fresh, lower floor.
    path = tmp_path / "receipts.jsonl"
    br.mint(_world(), 7, KEY, path=path)
    head_path = tmp_path / "receipts.jsonl.head"
    head_path.write_text(json.dumps({"count": 999, "sig": "deadbeef"}))
    with pytest.raises(br.ReceiptChainTampered):
        br.mint(_world(), 7, KEY, path=path)


def test_forged_head_anchor_flagged_by_verify_chain(tmp_path):
    path = tmp_path / "receipts.jsonl"
    br.mint(_world(), 7, KEY, path=path)
    head_path = tmp_path / "receipts.jsonl.head"
    head_path.write_text(json.dumps({"count": 999, "sig": "deadbeef"}))
    report = br.verify_chain(path, KEY)
    assert not report.ok
    assert "signature" in report.reason


def test_concurrent_mint_keeps_chain_intact(tmp_path):
    # Many minters racing on one chain must not fork the hash links: the
    # read-prev -> append sequence is serialized, so verify_chain stays ok.
    import threading

    path = tmp_path / "receipts.jsonl"
    n = 16
    barrier = threading.Barrier(n)

    def worker(goal):
        barrier.wait()
        br.mint(_world(), goal, KEY, path=path)

    threads = [threading.Thread(target=worker, args=(7,)) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    report = br.verify_chain(path, KEY)
    assert report.ok, report.reason
    assert report.count == n


def test_goal_with_no_episodes_mints_zero_receipt(tmp_path):
    line = br.mint(FakeWorld([]), 42, KEY, path=tmp_path / "r.jsonl")
    payload = json.loads(line)["payload"]
    assert payload["total_dollars"] == 0
    assert payload["started_at"] is None and payload["ended_at"] is None
    assert br.verify(line, KEY) == br.VALID


def test_a_lone_surrogate_signature_is_invalid_not_a_crash():
    # Receipt JSON can carry a lone surrogate ("\ud800"); verify() classifies, never raises.
    receipt = json.dumps({"payload": {"count": 1}, "sig": "\ud800"})
    assert br.verify(receipt, "k" * 32) == br.INVALID
