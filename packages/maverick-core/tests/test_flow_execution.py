"""Flow lowering (import -> Flow), the live execution driver + resumable state,
per-node outcomes, and the self-rewrite proposal pass."""
from __future__ import annotations

from maverick.automation_import import ir as iir
from maverick.automation_import.to_flow import to_flow
from maverick.flow import evolve, execution, node_outcomes
from maverick.flow.ir import NODE_ACTION, NODE_AGENT, NODE_APPROVAL, Flow, FlowNode


def _patch_home(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *p, **k: tmp_path.joinpath(*p))


def _approval_binding(run, *, inputs=None):
    from maverick.flow import store
    from maverick.flow.approvals import paused_operation_binding

    return paused_operation_binding(store.load_run(run.run_id), inputs=inputs)


def _approval_attestation(
    run, *, inputs=None, decision="approved", decided_by="system:direct",
):
    from maverick.flow import store
    from maverick.flow.approvals import (
        flow_decision_attestation_material,
        paused_operation_binding,
    )
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    current = store.load_run(run.run_id)
    binding = paused_operation_binding(current, inputs=inputs)
    material = flow_decision_attestation_material(
        current,
        inputs=inputs,
        operation_binding_sha256=binding,
        authority_binding_sha256="",
        decision=decision,
        decided_by=decided_by,
    )
    return issue_flow_decision_attestation(
        None,
        material=material,
        expires_at=float(current.human["approval_card"]["expires_at"]),
    )


def test_flow_exception_text_redacts_signed_approval_token():
    token = "eyJ" + "A" * 32 + "." + "b" * 64

    visible = execution._safe_failure(
        RuntimeError(f"resume provider reflected {token}"),
    )

    assert token not in visible
    assert "REDACTED:lightwork_flow_approval_token" in visible


# ---- lowering ---------------------------------------------------------------

class TestLowering:
    def test_single_step_lowers_to_single_agent(self):
        a = iir.ImportedAutomation(
            "n8n", "1", "One thing", iir.ImportedTrigger(kind=iir.TRIGGER_WEBHOOK),
            steps=[iir.ImportedStep(name="do it", description="carry out the thing")])
        f = to_flow(a)
        assert len(f.nodes) == 1
        assert f.nodes["n0"].kind == NODE_AGENT
        assert f.validate() == []

    def test_clean_tool_step_becomes_action(self):
        a = iir.ImportedAutomation(
            "n8n", "2", "notify", iir.ImportedTrigger(kind=iir.TRIGGER_WEBHOOK),
            steps=[iir.ImportedStep(name="Post", app="slack", operation="post",
                                    params={"text": "hi"}, tools_hint=["slack"])])
        f = to_flow(a)
        assert f.nodes["n0"].kind == NODE_ACTION
        assert f.nodes["n0"].tool == "slack_bot"
        assert f.nodes["n0"].params["op"] == "post"

    def test_ambiguous_step_becomes_agent(self):
        a = iir.ImportedAutomation(
            "n8n", "3", "x", iir.ImportedTrigger(kind=iir.TRIGGER_WEBHOOK),
            steps=[iir.ImportedStep(name="Decide", tools_hint=["a", "b"])])  # >1 hint
        f = to_flow(a)
        assert f.nodes["n0"].kind == NODE_AGENT

    def test_empty_import_still_yields_runnable_flow(self):
        a = iir.ImportedAutomation("n8n", "4", "Empty", iir.ImportedTrigger(), steps=[])
        f = to_flow(a)
        assert f.validate() == [] and f.nodes["n0"].kind == NODE_AGENT

    def test_multi_step_chains_in_order(self):
        a = iir.ImportedAutomation(
            "n8n", "5", "chain", iir.ImportedTrigger(kind=iir.TRIGGER_WEBHOOK),
            steps=[iir.ImportedStep(name="s1"), iir.ImportedStep(name="s2"),
                   iir.ImportedStep(name="s3")])
        f = to_flow(a)
        assert f.start == "n0"
        assert f.nodes["n0"].next == "n1" and f.nodes["n1"].next == "n2"
        assert f.nodes["n2"].next is None


# ---- live execution driver + resumable state --------------------------------

class TestExecution:
    def test_execute_persists_completed_run(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="f1", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="do {{x}}", output="r")})
        run = execution.execute(
            f, agent_runner=lambda brief, d: (f"ran:{brief}", 0.8),
            action_runner=lambda t, p, d: ("", None), data={"x": "1"}, owner="user:a")
        assert run.status == "completed" and run.data["r"] == "ran:do 1"
        from maverick.flow import store
        assert store.load_run(run.run_id).owner == "user:a"


    def test_action_flow_rejects_unsafe_shell_tool(self):
        f = Flow(id="unsafe", name="unsafe", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_ACTION, tool="shell",
                          params={"args": {"cmd": "id"}}, output="o")})

        assert "unsafe direct action tool 'shell'" in "; ".join(f.validate())

    def test_default_action_runner_blocks_unsafe_shell_tool(self):
        run = execution.default_action_runner(world=None)

        result, outcome = run("shell", {"args": {"cmd": "id"}}, {})

        assert outcome == 0.0
        assert result == "ERROR: unsafe direct action tool 'shell'"

    def test_flow_max_dollars_caps_agent_fan_out(self, tmp_path, monkeypatch):
        # Three chained agent nodes at the default $5 per-node reservation; a $12
        # aggregate cap lets 2 run and skips the 3rd (2*5=10 ok, +5 would exceed).
        _patch_home(tmp_path, monkeypatch)
        ran = []
        f = Flow(id="fB", name="f", start="a", max_dollars=12.0, nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="1", output="r1", next="b"),
            "b": FlowNode(id="b", kind=NODE_AGENT, brief="2", output="r2", next="c"),
            "c": FlowNode(id="c", kind=NODE_AGENT, brief="3", output="r3")})

        def agent(brief, d):
            ran.append(brief)
            return ("ok", 1.0)
        run = execution.execute(f, agent_runner=agent, action_runner=lambda t, p, d: ("", None))
        assert ran == ["1", "2"]                       # the 3rd never spawned a goal
        assert run.status == "budget_limited" and "r3" not in run.data

    def test_flow_max_dollars_zero_is_unlimited(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="fB0", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="1", output="r1", next="b"),
            "b": FlowNode(id="b", kind=NODE_AGENT, brief="2", output="r2")})
        run = execution.execute(f, agent_runner=lambda brief, d: ("ok", 1.0),
                                action_runner=lambda t, p, d: ("", None))
        assert run.data["r1"] == "ok" and run.data["r2"] == "ok"

    def test_flow_max_dollars_survives_delay_resume(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        ran = []
        f = Flow(id="fBR", name="f", start="a", max_dollars=5.0, nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="before", output="r1", next="pause"),
            "pause": FlowNode(id="pause", kind="delay", seconds=1.0, next="b"),
            "b": FlowNode(id="b", kind=NODE_AGENT, brief="after", output="r2")})

        def agent(brief, d):
            ran.append(brief)
            return (f"ran:{brief}", 1.0)

        paused = execution.execute(f, agent_runner=agent, action_runner=lambda t, p, d: ("", None),
                                   now=lambda: 100.0)
        assert paused.status == "paused_delay" and paused.cost_dollars == 5.0

        resumed = execution.execute(f, agent_runner=agent, action_runner=lambda t, p, d: ("", None),
                                    resume_run_id=paused.run_id, now=lambda: 101.0)
        assert ran == ["before"]
        assert resumed.status == "budget_limited" and "r2" not in resumed.data
        assert resumed.cost_dollars == 5.0

    def test_execute_records_node_outcomes(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="fX", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="b")})
        execution.execute(f, agent_runner=lambda brief, d: ("ok", 0.9),
                          action_runner=lambda t, p, d: ("", None))
        assert node_outcomes.stats("fX")["a"] == {"n": 1, "mean": 0.9, "kind": NODE_AGENT}

    def test_execute_records_per_node_run_trace(self, tmp_path, monkeypatch):
        # The run persists a per-node {status, outcome} trace for the designer's
        # live-run overlay.
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="fT", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="ok step", next="b"),
            "b": FlowNode(id="b", kind=NODE_ACTION, tool="web_search", next=None)})
        run = execution.execute(
            f, agent_runner=lambda brief, d: ("ok", 1.0),
            action_runner=lambda t, p, d: ("ERROR: boom", 0.0))
        assert run.nodes["a"]["status"] == "done" and run.nodes["a"]["outcome"] == 1.0
        assert run.nodes["b"]["status"] == "done" and run.nodes["b"]["outcome"] == 0.0
        # work nodes also carry their measured wall-clock duration
        assert run.nodes["a"]["seconds"] >= 0.0 and run.nodes["b"]["seconds"] >= 0.0
        from maverick.flow import store
        assert store.load_run(run.run_id).nodes["b"]["outcome"] == 0.0   # persisted

    def test_run_trace_survives_pause_and_resume(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="fTR", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="first", output="r", next="b"),
            "b": FlowNode(id="b", kind="approval", prompt="ok?", next="c"),
            "c": FlowNode(id="c", kind=NODE_AGENT, brief="last")})
        paused = execution.execute(f, agent_runner=lambda b, d: ("x", 1.0),
                                   action_runner=lambda *a: ("", None))
        assert paused.status == "paused_approval" and paused.nodes["a"]["outcome"] == 1.0
        resumed = execution.execute(f, agent_runner=lambda b, d: ("x", 1.0),
                                    action_runner=lambda *a: ("", None),
                                     resume_run_id=paused.run_id, decision="approved",
                                     decided_by="system:direct",
                                     approval_binding_sha256=_approval_binding(paused),
                                     approval_decision_attestation=(
                                         _approval_attestation(paused)
                                     ))
        # the pre-pause node's trace is preserved alongside the post-resume nodes
        assert resumed.nodes["a"]["outcome"] == 1.0 and resumed.nodes["c"]["outcome"] == 1.0

    def test_approved_agent_step_is_claimed_and_later_action_outlives_decision_ttl(
        self, tmp_path, monkeypatch,
    ):
        import time as real_time

        from maverick.flow import store
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="fClaim", name="f", start="gate", nodes={
            "gate": FlowNode(id="gate", kind="approval", prompt="ok?", next="work"),
            "work": FlowNode(id="work", kind=NODE_AGENT, brief="long work", next="send"),
            "send": FlowNode(id="send", kind=NODE_ACTION, tool="web_search",
                             params={"query": "hi"})})
        paused = execution.execute(f, agent_runner=lambda b, d: ("x", 1.0),
                                   action_runner=lambda *a: ("ok", 1.0))
        seen, sent = [], []
        start = real_time.time()

        def agent(brief, data):
            # The resume is durably claimed before the agent starts, and the
            # agent outlives the 15-minute decision attestation.
            seen.append(store.load_run(paused.run_id).status)
            monkeypatch.setattr(real_time, "time", lambda: start + 3600.0)
            return ("x", 1.0)

        resumed = execution.execute(
            f, agent_runner=agent,
            action_runner=lambda tool, params, data: sent.append(tool) or ("ok", 1.0),
            resume_run_id=paused.run_id, decision="approved", decided_by="system:direct",
            approval_binding_sha256=_approval_binding(paused),
            approval_decision_attestation=_approval_attestation(paused))
        assert seen == ["resuming"]
        assert sent == ["web_search"] and resumed.status == "completed"

    def test_approval_card_and_run_share_rendered_pause_values(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        flow = Flow(id="fPrompt", name="Payments", start="gate", nodes={
            "gate": FlowNode(
                id="gate", kind="approval",
                prompt="Approve paying {{vendor}} {{amount}}?", next="done",
            ),
            "done": FlowNode(id="done", kind=NODE_AGENT, brief="Record decision"),
        })
        paused = execution.execute(
            flow, agent_runner=lambda brief, data: ("done", 1.0),
            action_runner=lambda *args: ("", None),
            data={"vendor": "Acme Corp", "amount": 5000},
        )
        assert paused.status == "paused_approval"
        assert paused.prompt == "Approve paying Acme Corp 5000?"
        assert paused.human["approval_card"]["summary"] == paused.prompt
        card = paused.human["approval_card"]
        assert card["target"]["label"] == "AI task"
        assert card["parameters"]["summary"][-1] == "Next: AI task"
        assert not any("digest" in text or "node" in text
                       for text in card["parameters"]["summary"])
        assert "current permissions" in card["preview"]["after"]

    def test_pause_resume_across_persisted_state(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="f2", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind="approval", prompt="ok?", next="b"),
            "b": FlowNode(id="b", kind=NODE_AGENT, brief="go", output="done")})
        def ag(brief, d):
            return ("ran", 1.0)
        paused = execution.execute(f, agent_runner=ag, action_runner=lambda *a: ("", None),
                                   data={"n": 1})
        assert paused.status == "paused_approval" and paused.cursor == "a"
        resumed = execution.execute(f, agent_runner=ag, action_runner=lambda *a: ("", None),
                                     resume_run_id=paused.run_id, decision="approved",
                                     decided_by="system:direct",
                                     approval_binding_sha256=_approval_binding(paused),
                                     approval_decision_attestation=(
                                         _approval_attestation(paused)
                                     ))
        assert resumed.status == "completed" and resumed.data["done"] == "ran"
        assert resumed.run_id == paused.run_id          # same run, resumed in place

    def test_approval_saved_before_copy_change_can_resume(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        from maverick.approval_cards import digest
        from maverick.flow import approvals

        flow = Flow(id="old-card", name="Old card", start="approve", nodes={
            "approve": FlowNode(id="approve", kind="approval", prompt="Continue?", next="do"),
            "do": FlowNode(id="do", kind=NODE_AGENT, brief="finish", output="result"),
        })
        presentation = approvals.approval_card_presentation
        with monkeypatch.context() as patch:
            patch.setattr(
                approvals, "approval_card_presentation",
                lambda flow, paused, next_node, prompt: presentation(
                    flow, paused, next_node, prompt, legacy=True,
                    run_data_sha256=digest({"n": 1}),
                ),
            )
            paused = execution.execute(
                flow, agent_runner=lambda brief, data: ("done", 1.0),
                action_runner=lambda *args: ("", None), data={"n": 1},
            )
        assert paused.status == "paused_approval"
        assert paused.human["approval_card"]["parameters"]["summary"][1].startswith(
            "Continue after approval node:")
        resumed = execution.execute(
            flow, agent_runner=lambda brief, data: ("done", 1.0),
            action_runner=lambda *args: ("", None),
            resume_run_id=paused.run_id, decision="approved",
            decided_by="system:direct",
            approval_binding_sha256=_approval_binding(paused),
            approval_decision_attestation=_approval_attestation(paused),
        )
        assert resumed.status == "completed"

    def test_resume_merges_free_form_human_inputs(self, tmp_path, monkeypatch):
        # An approval can also COLLECT data: inputs given at resume merge into the
        # run data, so a downstream node sees the human's correction.
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="fi", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind="approval", prompt="fix?", next="b"),
            "b": FlowNode(id="b", kind=NODE_AGENT, brief="use {{corrected}}", output="r")})
        got = {}

        def ag(brief, d):
            got["brief"] = brief
            return ("done", 1.0)
        paused = execution.execute(f, agent_runner=ag, action_runner=lambda *a: ("", None), data={})
        assert paused.status == "paused_approval"
        resumed = execution.execute(f, agent_runner=ag, action_runner=lambda *a: ("", None),
                                    resume_run_id=paused.run_id, decision="approved",
                                    decided_by="system:direct",
                                     approval_binding_sha256=_approval_binding(
                                         paused, inputs={"corrected": "the fixed value"},
                                     ),
                                     approval_decision_attestation=_approval_attestation(
                                         paused, inputs={"corrected": "the fixed value"},
                                     ),
                                     inputs={"corrected": "the fixed value"})
        assert got["brief"] == "use the fixed value"        # human input threaded in
        assert resumed.data["corrected"] == "the fixed value"

    def test_resume_inputs_cannot_overwrite_existing_run_data(self, tmp_path, monkeypatch):
        # Resume-time inputs may collect new values, but they must not tamper
        # with trusted data created before the approval pause.
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="f-guard", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind="approval", prompt="approve?", next="b"),
            "b": FlowNode(id="b", kind=NODE_AGENT,
                          brief="pay {{amount}} because {{note}}", output="r")})
        got = {}

        def ag(brief, d):
            got["brief"] = brief
            return ("done", 1.0)

        paused = execution.execute(
            f, agent_runner=ag, action_runner=lambda *a: ("", None),
            data={"amount": "100.00"})
        assert paused.status == "paused_approval"
        resumed = execution.execute(
            f, agent_runner=ag, action_runner=lambda *a: ("", None),
            resume_run_id=paused.run_id, decision="approved",
            decided_by="system:direct",
             approval_binding_sha256=_approval_binding(
                 paused,
                 inputs={"amount": "999999.00", "note": "reviewed"},
             ),
             approval_decision_attestation=_approval_attestation(
                 paused,
                 inputs={"amount": "999999.00", "note": "reviewed"},
             ),
             inputs={"amount": "999999.00", "note": "reviewed"})
        assert got["brief"] == "pay 100.00 because reviewed"
        assert resumed.data["amount"] == "100.00"
        assert resumed.data["note"] == "reviewed"

    def test_dry_run_traces_but_records_no_outcomes(self, tmp_path, monkeypatch):
        # A sandboxed dry run exercises the graph (status trace captured) but must
        # NOT ground outcomes -- mock successes would skew the self-rewrite signal.
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="dry", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="do {{x}}", next="gate"),
            "gate": FlowNode(id="gate", kind=NODE_APPROVAL,
                             prompt="approve sandboxed post?", next="b"),
            "b": FlowNode(id="b", kind=NODE_ACTION, tool="slack_bot")})
        ag, act = execution.sandbox_runners()
        run = execution.execute(f, agent_runner=ag, action_runner=act,
                                approve_fn=lambda *_: "approved",
                                data={"x": "1"}, record_outcomes=False)
        assert run.status == "completed"
        assert run.nodes["a"]["outcome"] == 1.0 and run.nodes["b"]["outcome"] == 1.0
        assert node_outcomes.stats("dry") == {}          # nothing grounded

    def test_dry_run_never_echoes_rendered_params_or_brief_in_saved_data(
            self, tmp_path, monkeypatch):
        from maverick.flow import store

        _patch_home(tmp_path, monkeypatch)
        private_value = "cedar-marble-4829-7731"  # pragma: allowlist secret
        f = Flow(id="private-dry", name="Private test", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT,
                          brief=f"Summarize {private_value}", output="draft", next="b"),
            "b": FlowNode(id="b", kind=NODE_ACTION, tool="web_search",
                          params={"body": f"pin={private_value}"}, output="posted"),
        })
        ag, act = execution.sandbox_runners()

        run = execution.execute(f, agent_runner=ag, action_runner=act,
                                data={"sample": "ordinary"}, record_outcomes=False)
        saved = store.load_run(run.run_id)

        assert run.status == "completed" and saved.status == "completed"
        assert saved.data["posted"] == {
            "dry_run": True, "tool": "web_search", "parameters": "withheld",
        }
        assert private_value not in str(run.data)
        assert private_value not in str(saved.data)
        assert private_value not in str(saved.input_data)

    def test_execute_preserves_queued_placeholder_idem_and_inputs(self, tmp_path, monkeypatch):
        # A queued placeholder (saved by enqueue with the idempotency key + inputs)
        # keeps those fields when the job later runs it.
        _patch_home(tmp_path, monkeypatch)
        from maverick.flow import store
        rid = store.new_run_id()
        store.save_run(store.FlowRun(run_id=rid, flow_id="fp", status="queued",
                                     idem_key="evt:9", input_data={"seed": 1}))
        f = Flow(id="fp", name="f", start="a",
                 nodes={"a": FlowNode(id="a", kind=NODE_AGENT, brief="go")})
        run = execution.execute(f, agent_runner=lambda b, d: ("ok", 1.0),
                                action_runner=lambda *a: ("", None), data={"seed": 1}, run_id=rid)
        assert run.status == "completed"
        assert run.idem_key == "evt:9" and run.input_data == {"seed": 1}

    def test_resume_of_completed_run_is_rejected(self, tmp_path, monkeypatch):
        # Guard against re-running a finished flow (duplicate side effects) or
        # running a node a human rejected.
        import pytest
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="fc", name="f", start="a",
                 nodes={"a": FlowNode(id="a", kind=NODE_AGENT, brief="b")})
        run = execution.execute(f, agent_runner=lambda b, d: ("ok", 1.0),
                                action_runner=lambda *a: ("", None))
        assert run.status == "completed"
        with pytest.raises(execution.FlowNotResumable):
            execution.execute(f, agent_runner=lambda b, d: ("ok", 1.0),
                              action_runner=lambda *a: ("", None), resume_run_id=run.run_id)

    def test_resume_rejected_ends_run(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="f3", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind="approval", prompt="ok?", next="b"),
            "b": FlowNode(id="b", kind=NODE_AGENT, brief="go", output="done")})
        paused = execution.execute(f, agent_runner=lambda *a: ("", None),
                                   action_runner=lambda *a: ("", None))
        rej = execution.execute(f, agent_runner=lambda *a: ("", None),
                                action_runner=lambda *a: ("", None),
                                 resume_run_id=paused.run_id, decision="rejected",
                                 decided_by="system:direct",
                                 approval_binding_sha256=_approval_binding(paused),
                                 approval_decision_attestation=_approval_attestation(
                                     paused, decision="rejected",
                                 ))
        assert rej.status == "rejected" and "done" not in rej.data


class TestRetryFromFailure:
    def _flow(self):
        return Flow(id="fr", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="prep", output="r1", next="b"),
            "b": FlowNode(id="b", kind=NODE_ACTION, tool="web_search", output="r2", next="c"),
            "c": FlowNode(id="c", kind=NODE_AGENT, brief="wrap", output="r3")})

    def test_failed_run_records_cursor_and_resumes_at_failed_node(self, tmp_path, monkeypatch):
        _patch_home(tmp_path, monkeypatch)
        agent_calls = []

        def agent(brief, d):
            agent_calls.append(brief)
            return ("ok", 1.0)

        def broken(t, p, d):
            raise RuntimeError("connector down")
        run = execution.execute(self._flow(), agent_runner=agent, action_runner=broken)
        assert run.status == "failed" and run.cursor == "b"
        assert "connector down" in run.error
        # data as of the failure survives: node a's output is still there
        assert run.data["r1"] == "ok"
        resumed = execution.execute(
            self._flow(), agent_runner=agent, action_runner=lambda t, p, d: ("fixed", 1.0),
            resume_run_id=run.run_id, from_failure=True)
        assert resumed.status == "completed" and resumed.run_id == run.run_id
        assert resumed.data["r2"] == "fixed" and resumed.data["r3"] == "ok"
        # node a ran exactly once across the original run + the retry
        assert agent_calls == ["prep", "wrap"]

    def test_from_failure_only_applies_to_failed_runs(self, tmp_path, monkeypatch):
        import pytest
        _patch_home(tmp_path, monkeypatch)
        f = Flow(id="fr2", name="f", start="a",
                 nodes={"a": FlowNode(id="a", kind=NODE_AGENT, brief="b")})
        done = execution.execute(f, agent_runner=lambda b, d: ("ok", 1.0),
                                 action_runner=lambda *a: ("", None))
        with pytest.raises(execution.FlowNotResumable):
            execution.execute(f, agent_runner=lambda b, d: ("ok", 1.0),
                              action_runner=lambda *a: ("", None),
                              resume_run_id=done.run_id, from_failure=True)

    def test_failed_run_without_cursor_is_not_retryable(self, tmp_path, monkeypatch):
        import pytest
        from maverick.flow import store
        _patch_home(tmp_path, monkeypatch)
        f = self._flow()
        store.save_run(store.FlowRun(run_id="r-nocursor", flow_id=f.id, status="failed"))
        with pytest.raises(execution.FlowNotResumable, match="failure cursor"):
            execution.execute(f, agent_runner=lambda *a: ("", None),
                              action_runner=lambda *a: ("", None),
                              resume_run_id="r-nocursor", from_failure=True)


# ---- self-rewrite proposals -------------------------------------------------

class TestEvolve:
    def _flow(self):
        return Flow(id="fp", name="f", start="a", nodes={
            "a": FlowNode(id="a", kind=NODE_AGENT, brief="reliable", next="b"),
            "b": FlowNode(id="b", kind=NODE_ACTION, tool="flaky", next="c"),
            "c": FlowNode(id="c", kind=NODE_AGENT, brief="middling")})

    def test_proposes_hardening_reliable_agent_and_softening_flaky_action(self):
        stats = {
            "a": {"n": 20, "mean": 0.95, "kind": NODE_AGENT},   # -> harden to action
            "b": {"n": 15, "mean": 0.3, "kind": NODE_ACTION},   # -> soften to agent
            "c": {"n": 20, "mean": 0.7, "kind": NODE_AGENT},    # middling -> no proposal
        }
        props = {p.node_id: p for p in evolve.propose(self._flow(), stats=stats)}
        assert props["a"].to_kind == NODE_ACTION
        assert props["b"].to_kind == NODE_AGENT
        assert "c" not in props

    def test_min_support_gates_out_small_samples(self):
        stats = {"a": {"n": 3, "mean": 1.0, "kind": NODE_AGENT}}
        assert evolve.propose(self._flow(), stats=stats) == []

    def test_maybe_propose_is_gated_off_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_FLOWS", raising=False)
        monkeypatch.setattr("maverick.config.get_flows", lambda: {"enable": False})
        assert evolve.maybe_propose(self._flow()) == []
