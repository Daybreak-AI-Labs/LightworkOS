"""JitRL gradient-free test-time adaptation.

Continual adaptation on a frozen model lives entirely in a retrievable
(state, action, return) store: no weights change. These pin the k-NN
value/advantage estimate, the advantage-ranked steering (with a store-empty
no-op), JSONL persistence, the PRM-encoded adapter path, and off-by-default.
"""
from __future__ import annotations

import pytest
from maverick import jit_rl
from maverick.jit_rl import JitAdapter, JitStore
from maverick.prm import StepContext


def _feat(*xs):
    return tuple(float(x) for x in xs)


class TestStoreKNN:
    def test_empty_store_is_neutral(self):
        s = JitStore()
        assert s.value(_feat(0, 0)) == 0.0
        assert s.advantage(_feat(0, 0), "a") == 0.0
        assert s.neighbors(_feat(0, 0)) == []

    def test_value_is_mean_return_of_neighbors(self):
        s = JitStore()
        s.record(_feat(0, 0), "a", 1.0)
        s.record(_feat(0, 0), "b", 0.0)
        assert s.value(_feat(0, 0), k=2) == 0.5

    def test_advantage_prefers_locally_better_action(self):
        s = JitStore()
        # Near (0,0): action "a" returns 1.0, action "b" returns 0.0.
        for _ in range(3):
            s.record(_feat(0, 0), "a", 1.0)
            s.record(_feat(0, 0), "b", 0.0)
        adv_a = s.advantage(_feat(0, 0), "a", k=6)
        adv_b = s.advantage(_feat(0, 0), "b", k=6)
        assert adv_a > 0 > adv_b
        assert abs(adv_a - 0.5) < 1e-9 and abs(adv_b + 0.5) < 1e-9

    def test_unseen_action_gets_zero_advantage(self):
        s = JitStore()
        s.record(_feat(0, 0), "a", 1.0)
        assert s.advantage(_feat(0, 0), "never_taken", k=4) == 0.0

    def test_neighbors_respects_locality(self):
        s = JitStore()
        s.record(_feat(0, 0), "near", 1.0)
        s.record(_feat(10, 10), "far", -1.0)
        # Query near origin, k=1 -> the near experience wins.
        nbr = s.neighbors(_feat(0.1, 0.1), k=1)
        assert len(nbr) == 1 and nbr[0].action == "near"

    def test_mismatched_feature_length_ranked_last(self):
        s = JitStore()
        s.record(_feat(0, 0), "good", 1.0)
        s.record(_feat(0, 0, 0), "malformed", 1.0)  # wrong length
        nbr = s.neighbors(_feat(0, 0), k=1)
        assert nbr[0].action == "good"

    def test_max_experiences_drops_oldest(self):
        s = JitStore(max_experiences=2)
        s.record(_feat(0, 0), "1", 1.0)
        s.record(_feat(0, 0), "2", 1.0)
        s.record(_feat(0, 0), "3", 1.0)
        assert len(s) == 2


class TestSteer:
    def test_steer_ranks_by_advantage(self):
        adapter = JitAdapter(k=6, beta=2.0)
        for _ in range(3):
            adapter.store.record(_feat(1, 0), "good", 1.0)
            adapter.store.record(_feat(1, 0), "bad", 0.0)
        ranked = adapter._steer_from_features(_feat(1, 0), ["bad", "good"])
        assert [s.action for s in ranked][0] == "good"
        # score = beta * advantage
        top = ranked[0]
        assert abs(top.score - 2.0 * top.advantage) < 1e-9

    def test_steer_empty_store_preserves_order(self):
        adapter = JitAdapter()
        ranked = adapter._steer_from_features(_feat(0, 0), ["x", "y", "z"])
        assert [s.action for s in ranked] == ["x", "y", "z"]
        assert all(s.score == 0.0 for s in ranked)


class TestAdapterWithPRMEncoding:
    def test_record_and_advantage_through_step_context(self):
        adapter = JitAdapter(k=8, beta=1.0)
        # Same StepContext shape, different actions with different returns.
        ctx = StepContext(goal_id=1, step_index=0, role="coder", tool_name="edit")
        for _ in range(4):
            adapter.record_step(ctx, "edit", 1.0)
            adapter.record_step(ctx, "revert", -1.0)
        assert adapter.advantage(ctx, "edit") > 0
        assert adapter.advantage(ctx, "revert") < 0
        ranked = adapter.steer(ctx, ["revert", "edit"])
        assert ranked[0].action == "edit"

    def test_steer_no_history_preserves_order(self):
        adapter = JitAdapter()
        ctx = StepContext(goal_id=9, step_index=2, role="writer")
        ranked = adapter.steer(ctx, ["a", "b"])
        assert [s.action for s in ranked] == ["a", "b"]


class TestPersistence:
    def test_experience_survives_reload(self, tmp_path):
        p = tmp_path / "jit.ndjson"
        s1 = JitStore(path=p)
        s1.record(_feat(0, 0), "a", 1.0)
        s1.record(_feat(0, 0), "b", 0.0)
        # Fresh store from the same path reloads the triplets.
        s2 = JitStore(path=p)
        assert len(s2) == 2
        assert abs(s2.value(_feat(0, 0), k=2) - 0.5) < 1e-9
        from maverick.file_lock import private_path_is_restricted
        assert private_path_is_restricted(p)

    def test_reload_skips_malformed_lines(self, tmp_path):
        p = tmp_path / "jit.ndjson"
        p.write_text('[]\n"x"\n{"features": [0.0], "action": "a", "ret": 1.0}\n',
                     encoding="utf-8")
        s = JitStore(path=p)
        assert len(s) == 1

    def test_persistent_buffer_is_bounded_on_disk(self, tmp_path):
        p = tmp_path / "jit.ndjson"
        store = JitStore(path=p, max_experiences=3)
        for i in range(10):
            store.record(_feat(i), f"a{i}", float(i))
        assert len(p.read_text(encoding="utf-8").splitlines()) <= 3
        reloaded = JitStore(path=p, max_experiences=3)
        assert len(reloaded) == 3
        assert [item.action for item in reloaded.neighbors(_feat(9), k=3)] == [
            "a9", "a8", "a7",
        ]


class TestGate:
    def test_on_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_JIT_RL", raising=False)
        # Real config default (no [jit_rl] enable set) -> on.
        assert jit_rl.enabled() is True

    def test_respects_disable_setting(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_JIT_RL", raising=False)
        monkeypatch.setattr(jit_rl, "_settings", lambda: {
            "enable": False, "k": 8, "beta": 1.0, "max_experiences": 5000})
        assert jit_rl.enabled() is False

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_JIT_RL", "1")
        assert jit_rl.enabled() is True
        monkeypatch.setenv("MAVERICK_JIT_RL", "0")  # explicit opt-out
        assert jit_rl.enabled() is False

    def test_build_from_env_in_memory(self, tmp_path):
        adapter = jit_rl.build_from_env(path=tmp_path / "jit.ndjson")
        assert isinstance(adapter, JitAdapter)
        ctx = StepContext(goal_id=1, step_index=0, role="coder")
        adapter.record_step(ctx, "a", 1.0)
        assert len(adapter.store) == 1


class TestBestOfNSelector:
    def _cands(self):
        from maverick.best_of_n import Candidate
        return [
            Candidate(text="a", confidence=0.7, accepts=True),
            Candidate(text="b", confidence=0.72, accepts=True),
        ]

    def test_cold_store_matches_default_selection(self):
        # With no experience, advantage is 0 everywhere -> highest confidence wins,
        # exactly like the default (accepts, confidence) selection.
        adapter = JitAdapter()
        ctx = StepContext(goal_id=1, step_index=0, role="coder")
        select = jit_rl.make_best_of_n_selector(adapter, ctx)
        best = select(self._cands())
        assert best.text == "b"  # 0.72 > 0.70

    def test_records_outcomes_for_future_adaptation(self):
        adapter = JitAdapter()
        ctx = StepContext(goal_id=1, step_index=0, role="coder")
        select = jit_rl.make_best_of_n_selector(adapter, ctx)
        select(self._cands())
        assert len(adapter.store) == 2  # both candidates recorded

    def test_learned_advantage_biases_selection(self):
        from maverick.best_of_n import Candidate
        adapter = JitAdapter(k=8, beta=1.0)
        ctx = StepContext(goal_id=1, step_index=0, role="coder")
        feats = adapter._features(ctx)
        # Teach the store that ordinal 0 ("cand_0") returns much better here.
        for _ in range(5):
            adapter.store.record(feats, "cand_0", 1.0)
            adapter.store.record(feats, "cand_1", 0.0)
        select = jit_rl.make_best_of_n_selector(adapter, ctx)
        # Candidate 1 has slightly higher raw confidence, but cand_0's learned
        # advantage outweighs the 0.02 gap -> the adapter steers to cand_0.
        cands = [Candidate(text="a", confidence=0.70, accepts=True),
                 Candidate(text="b", confidence=0.72, accepts=True)]
        assert select(cands).text == "a"

    @pytest.mark.asyncio
    async def test_best_of_n_uses_select_hook(self):
        from maverick.best_of_n import best_of_n

        async def gen():
            gen.i += 1
            return f"cand{gen.i}"
        gen.i = 0

        async def verify(text):
            from types import SimpleNamespace
            return SimpleNamespace(confidence=0.8, accepts=True)

        # A select hook that always picks the LAST candidate proves the hook is used.
        res = await best_of_n(gen, verify, n=3, accept_early=False,
                              select=lambda cs: cs[-1])
        assert res.best == "cand3"
