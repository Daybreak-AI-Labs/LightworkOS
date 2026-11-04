"""Opt-in trajectory donation pipeline."""
from __future__ import annotations

import json

from maverick import donation
from maverick.donation import (
    TrajectoryRecord,
    clear_outbox,
    hash_brief,
    list_pending,
    should_donate,
    write_record,
)


def _config(monkeypatch, telemetry: dict) -> None:
    """Point ``load_config`` at a stub config with the given ``[telemetry]``.

    ``_donation_thresholds`` does ``from .config import load_config`` at call
    time, so patching the attribute on the config module takes effect.
    """
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", lambda: {"telemetry": dict(telemetry)})


class TestSelectionGate:
    def test_only_success_donated(self):
        assert should_donate("failure", 0.9, 0.9) is False
        assert should_donate("blocked", 0.9, 0.9) is False
        assert should_donate("interrupted", 0.9, 0.9) is False

    def test_low_confidence_rejected(self):
        assert should_donate("success", 0.5, 0.9) is False

    def test_low_disagreement_rejected(self):
        """We only want trajectories where the swarm earned its keep
        (high disagreement = the swarm explored multiple branches)."""
        assert should_donate("success", 0.9, 0.2) is False

    def test_gold_row_accepted(self):
        assert should_donate("success", 0.85, 0.75) is True


class TestWriteRecord:
    def test_no_donation_when_disabled(self, tmp_path, monkeypatch):
        """Default: donate_trajectories=false → never write."""
        monkeypatch.setattr(donation, "_donations_enabled", lambda: False)
        rec = TrajectoryRecord(
            outcome="success", verifier_confidence=0.9,
            disagreement_entropy=0.9,
        )
        path = write_record(rec, outbox=tmp_path)
        assert path is None
        assert list(tmp_path.glob("*.json")) == []

    def test_donation_writes_when_enabled(self, tmp_path, monkeypatch):
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        rec = TrajectoryRecord(
            task_brief_hash="abc123",
            task_brief_text="plan a trip to Lisbon",
            outcome="success",
            verifier_confidence=0.9,
            disagreement_entropy=0.7,
            reward=1.0,
        )
        path = write_record(rec, outbox=tmp_path)
        assert path is not None
        assert path.exists()
        payload = json.loads(path.read_text())
        # Text is redacted because donate_text=False.
        assert payload["task_brief_text"] is None
        # Metadata is preserved.
        assert payload["task_brief_hash"] == "abc123"
        assert payload["outcome"] == "success"

    def test_verifier_critique_stripped_when_text_off(self, tmp_path, monkeypatch):
        # verifier_critique is raw model free-text; the metadata-only contract
        # must clear it unless donate_text is on (regression: it leaked through).
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        rec = TrajectoryRecord(
            task_brief_hash="abc123",
            task_brief_text="plan a trip to Lisbon",
            verifier_critique="the proprietary Project Falcon strategy is wrong",
            outcome="success",
            verifier_confidence=0.9,
            disagreement_entropy=0.7,
            reward=1.0,
        )
        path = write_record(rec, outbox=tmp_path)
        payload = json.loads(path.read_text())
        assert payload["verifier_critique"] == ""

    def test_text_included_when_double_opt_in(self, tmp_path, monkeypatch):
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: True)
        rec = TrajectoryRecord(
            task_brief_hash="abc",
            task_brief_text="plan a trip to Lisbon",
            outcome="success",
            verifier_confidence=0.9,
            disagreement_entropy=0.7,
        )
        path = write_record(rec, outbox=tmp_path)
        assert path is not None
        payload = json.loads(path.read_text())
        assert payload["task_brief_text"] == "plan a trip to Lisbon"

    def test_secret_scrubbing_runs_on_text(self, tmp_path, monkeypatch):
        """If text donation is on, the scrubber still strips API keys."""
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: True)
        rec = TrajectoryRecord(
            task_brief_hash="abc",
            task_brief_text="my key is sk-ant-api01-secrettokenvaluexyz1234567890abc",
            outcome="success",
            verifier_confidence=0.9,
            disagreement_entropy=0.7,
        )
        path = write_record(rec, outbox=tmp_path)
        payload = json.loads(path.read_text())
        assert "sk-ant-api01-secrettokenvaluexyz1234567890abc" not in payload["task_brief_text"]
        assert "[REDACTED:anthropic_key]" in payload["task_brief_text"]

    def test_secret_scrubbing_runs_on_nested_sub_trajectories(self, tmp_path, monkeypatch):
        """Nested trajectory metadata must be scrubbed before donation."""
        secret = "sk-ant-api01-secrettokenvaluexyz1234567890abc"
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        rec = TrajectoryRecord(
            task_brief_hash="abc",
            model_id=f"model {secret}",
            action_sequence=[secret],
            agent_credit={f"researcher-{secret}": 0.5},
            sub_trajectories=[
                {
                    "role": f"researcher {secret}",
                    "name": f"researcher-{secret}",
                    "actions": [secret, f"web_search {secret}"],
                    "credit": 0.5,
                    "weight": 1.0,
                },
            ],
            outcome="success",
            verifier_confidence=0.9,
            disagreement_entropy=0.7,
        )

        path = write_record(rec, outbox=tmp_path)

        payload_text = path.read_text()
        payload = json.loads(payload_text)
        assert secret not in payload_text
        assert payload["task_brief_text"] is None
        assert payload["action_sequence"] == ["[REDACTED:anthropic_key]"]
        sub = payload["sub_trajectories"][0]
        assert sub["role"] == "researcher [REDACTED:anthropic_key]"
        assert sub["name"] == "researcher-[REDACTED:anthropic_key]"
        assert sub["actions"] == [
            "[REDACTED:anthropic_key]",
            "web_search [REDACTED:anthropic_key]",
        ]
        assert "researcher-[REDACTED:anthropic_key]" in payload["agent_credit"]

    def test_selection_gate_blocks_low_quality(self, tmp_path, monkeypatch):
        """Even with donation enabled, low-disagreement runs don't write."""
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        rec = TrajectoryRecord(
            outcome="success",
            verifier_confidence=0.9,
            disagreement_entropy=0.1,  # below threshold
        )
        path = write_record(rec, outbox=tmp_path)
        assert path is None

    def test_record_persists_goal_id_for_world_join(self, tmp_path, monkeypatch):
        """training.ingest / export_texts join a record to the world DB by
        goal_id; it must survive into the written payload. Without it on the
        dataclass the join would hit goal_id=0, fetch no goal_events, and every
        trajectory would come back step-less + transcript-less.
        """
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        monkeypatch.setattr("maverick.memory_ownership.current_owner", lambda **kwargs: "")
        rec = TrajectoryRecord(
            task_brief_hash="abc", goal_id=42, outcome="success",
            verifier_confidence=0.9, disagreement_entropy=0.7,
        )
        path = write_record(rec, outbox=tmp_path)
        assert path is not None
        payload = json.loads(path.read_text())
        assert payload["goal_id"] == 42


class TestConfigurableThresholds:
    """The donation bar is configurable via ``[telemetry]``.

    The default (entropy ≥ 0.5) only captures high-disagreement swarm runs --
    typical single-agent goals have disagreement_entropy=0 and donate nothing,
    so the learning loop never sees data from normal use. Setting
    ``donate_min_entropy = 0`` captures every successful, high-confidence run.
    """

    def test_default_bar_rejects_zero_disagreement(self, monkeypatch):
        # No config keys -> fall back to the gold-row defaults (0.5 / 0.75).
        _config(monkeypatch, {})
        assert should_donate("success", 0.9, 0.0) is False

    def test_zero_min_entropy_captures_single_agent_success(self, monkeypatch):
        _config(monkeypatch, {"donate_min_entropy": 0})
        # A clean single-agent run (no swarm disagreement) now donates.
        assert should_donate("success", 0.9, 0.0) is True
        # Confidence still gates: the default 0.75 floor stays in force.
        assert should_donate("success", 0.5, 0.0) is False

    def test_lowered_confidence_floor(self, monkeypatch):
        _config(monkeypatch, {"donate_min_entropy": 0, "donate_min_confidence": 0.4})
        assert should_donate("success", 0.5, 0.0) is True
        assert should_donate("success", 0.3, 0.0) is False

    def test_explicit_kwargs_override_config(self, monkeypatch):
        # Config says capture-everything, but an explicit call can re-raise the bar.
        _config(monkeypatch, {"donate_min_entropy": 0, "donate_min_confidence": 0.0})
        assert should_donate("success", 0.9, 0.0, min_entropy=0.5) is False
        assert should_donate("success", 0.9, 0.6, min_entropy=0.5) is True

    def test_failure_never_donated_regardless_of_config(self, monkeypatch):
        _config(monkeypatch, {"donate_min_entropy": 0, "donate_min_confidence": 0.0})
        assert should_donate("failure", 1.0, 1.0) is False

    def test_thresholds_helper_reads_config(self, monkeypatch):
        _config(monkeypatch, {"donate_min_entropy": 0.0, "donate_min_confidence": 0.6})
        assert donation._donation_thresholds() == (0.0, 0.6)

    def test_thresholds_helper_fails_open_to_defaults(self, monkeypatch):
        import maverick.config as cfg

        def _boom():
            raise RuntimeError("no config")

        monkeypatch.setattr(cfg, "load_config", _boom)
        assert donation._donation_thresholds() == (0.5, 0.75)

    def test_write_record_honors_zero_entropy_config(self, tmp_path, monkeypatch):
        """End-to-end: with donate_min_entropy=0, a zero-disagreement success
        passes the gate inside write_record and lands in the outbox."""
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        _config(monkeypatch, {"donate_min_entropy": 0})
        rec = TrajectoryRecord(
            task_brief_hash="single",
            outcome="success",
            verifier_confidence=0.9,
            disagreement_entropy=0.0,  # solo run, no swarm
        )
        path = write_record(rec, outbox=tmp_path)
        assert path is not None and path.exists()


class TestRejectedAttempts:
    """Rejected pre-revision drafts ride along for DPO pairing (chosen=accepted
    final, rejected=discarded draft)."""

    def _rec(self):
        return TrajectoryRecord(
            task_brief_hash="rj", outcome="success",
            verifier_confidence=0.92, disagreement_entropy=0.7,
            rejected_attempts=[
                {"text": "a weak first draft", "confidence": 0.62,
                 "critique": "missed a constraint"},
            ],
        )

    def test_text_kept_with_double_opt_in(self, tmp_path, monkeypatch):
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: True)
        path = write_record(self._rec(), outbox=tmp_path)
        att = json.loads(path.read_text())["rejected_attempts"][0]
        assert att["text"] == "a weak first draft"
        assert att["confidence"] == 0.62

    def test_text_stripped_without_text_opt_in(self, tmp_path, monkeypatch):
        """Default metadata-only contract: drop the draft TEXT, keep its score."""
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        path = write_record(self._rec(), outbox=tmp_path)
        att = json.loads(path.read_text())["rejected_attempts"][0]
        assert "text" not in att
        assert att["confidence"] == 0.62

    def test_secret_scrubbed_in_rejected_text(self, tmp_path, monkeypatch):
        secret = "sk-ant-api01-secrettokenvaluexyz1234567890abc"
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: True)
        rec = TrajectoryRecord(
            task_brief_hash="rj", outcome="success",
            verifier_confidence=0.92, disagreement_entropy=0.7,
            rejected_attempts=[{"text": f"draft with {secret}", "confidence": 0.6}],
        )
        payload_text = write_record(rec, outbox=tmp_path).read_text()
        assert secret not in payload_text


class TestScoredCandidates:
    """Best-of-N candidates ride along for DPO pairing, scored by objective tests."""

    def _rec(self):
        return TrajectoryRecord(
            task_brief_hash="bon", outcome="success",
            verifier_confidence=1.0, disagreement_entropy=0.7,
            reward=1.0,
            scored_candidates=[
                {"text": "diff --git a pass", "score": 1.0, "all_pass": True},
                {"text": "diff --git a fail", "score": 0.0, "all_pass": False},
            ],
        )

    def test_text_kept_with_double_opt_in(self, tmp_path, monkeypatch):
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: True)
        cands = json.loads(write_record(self._rec(), outbox=tmp_path).read_text())["scored_candidates"]
        assert cands[0]["text"] == "diff --git a pass"
        assert cands[0]["score"] == 1.0 and cands[1]["score"] == 0.0

    def test_text_stripped_without_text_opt_in(self, tmp_path, monkeypatch):
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        cands = json.loads(write_record(self._rec(), outbox=tmp_path).read_text())["scored_candidates"]
        assert "text" not in cands[0]               # patch dropped
        assert cands[0]["score"] == 1.0 and cands[0]["all_pass"] is True  # metadata kept

    def test_secret_scrubbed_in_candidate_patch(self, tmp_path, monkeypatch):
        secret = "sk-ant-api01-secrettokenvaluexyz1234567890abc"
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: True)
        rec = TrajectoryRecord(
            task_brief_hash="bon", outcome="success",
            verifier_confidence=1.0, disagreement_entropy=0.7, reward=1.0,
            scored_candidates=[{"text": f"patch {secret}", "score": 1.0, "all_pass": True}],
        )
        assert secret not in write_record(rec, outbox=tmp_path).read_text()


class TestHashBrief:
    def test_same_brief_same_hash(self):
        assert hash_brief("foo") == hash_brief("foo")

    def test_whitespace_invariant(self):
        assert hash_brief("foo") == hash_brief("  foo  ")

    def test_different_briefs_different_hashes(self):
        assert hash_brief("a") != hash_brief("b")

    def test_short_stable_id(self):
        h = hash_brief("anything")
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)


class TestOutboxHelpers:
    def test_list_pending_empty(self, tmp_path):
        assert list_pending(tmp_path) == []

    def test_list_pending_returns_sorted(self, tmp_path):
        (tmp_path / "b.json").write_text("{}")
        (tmp_path / "a.json").write_text("{}")
        out = list_pending(tmp_path)
        assert [p.name for p in out] == ["a.json", "b.json"]

    def test_clear_outbox(self, tmp_path):
        (tmp_path / "x.json").write_text("{}")
        (tmp_path / "y.json").write_text("{}")
        n = clear_outbox(tmp_path)
        assert n == 2
        assert list(tmp_path.glob("*.json")) == []


class TestDefaultOutboxTenantScoping:
    """DEFAULT_OUTBOX must resolve the ACTIVE tenant at call time, like every
    other learning store (reflexion, dreaming, self_harness). Binding it once
    at import time froze it to whatever tenant was active during import --
    with critique mining on by default, that let one tenant's donated outbox
    feed another tenant's dream cycle."""

    def test_resolves_current_tenant_directory(self, tmp_path, monkeypatch):
        from maverick.paths import reset_tenant, set_tenant

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
        monkeypatch.delenv("MAVERICK_TENANT", raising=False)

        tok_a = set_tenant("tenant-a")
        try:
            outbox_a = donation._default_outbox()
        finally:
            reset_tenant(tok_a)

        tok_b = set_tenant("tenant-b")
        try:
            outbox_b = donation._default_outbox()
        finally:
            reset_tenant(tok_b)

        assert outbox_a != outbox_b
        assert "tenant-a" in str(outbox_a)
        assert "tenant-b" in str(outbox_b)

    def test_write_record_lands_in_the_calling_tenants_outbox(
        self, tmp_path, monkeypatch,
    ):
        from maverick.paths import reset_tenant, set_tenant

        monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
        monkeypatch.delenv("MAVERICK_TENANT", raising=False)
        monkeypatch.setattr(donation, "_donations_enabled", lambda: True)
        monkeypatch.setattr(donation, "_text_donations_enabled", lambda: False)
        _config(monkeypatch, {"donate_min_entropy": 0})

        tok = set_tenant("acme")
        try:
            rec = TrajectoryRecord(
                task_brief_hash=hash_brief("x"), outcome="success",
                verifier_confidence=0.9, disagreement_entropy=0.0,
            )
            path = write_record(rec)
            assert path is not None
            assert "acme" in str(path)
            # A different tenant must not see this record via the default
            # (no-argument) outbox resolution.
            tok2 = set_tenant("other")
            try:
                assert list_pending() == []
            finally:
                reset_tenant(tok2)
            assert list_pending() == [path]
        finally:
            reset_tenant(tok)
