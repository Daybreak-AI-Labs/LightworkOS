"""Process-loss acceptance with a separate durable synthetic ticket provider.

The first interpreter exits inside create(), after the external fixture commits
but before it returns a receipt. Recovery runs in a fresh interpreter and can
only search/read that provider; a third interpreter records human acceptance.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest
from maverick.governed_operations import ServiceContext
from maverick.vendor_onboarding import VendorOnboardingService
from maverick.vendor_onboarding_adapters import (
    EvidenceDocument,
    FakeGoogleDriveEvidence,
    FakeJiraTickets,
)

_CRASH_EXIT = 73
_NOW = 1_800_000_000.0
_DOCUMENT = b"We do not train models on customer data. Data is encrypted at rest and in transit."


def _write_json(path: Path, value) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class _DurableTickets(FakeJiraTickets):
    """Test-only provider process state, deliberately outside Lightwork's store."""

    def __init__(self, path: Path, *, crash_after_create=False, allow_create=False,
                 crash_before_send=False, crash_after_observation=False):
        saved = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        state = {(row["tenant"], row["key"]): row["value"] for row in saved.get("tickets", [])}
        super().__init__(state)
        self.path = path
        self.creates = saved.get("creates", 0)
        self.reads = saved.get("reads", 0)
        self.crash_after_create = crash_after_create
        self.allow_create = allow_create
        self.crash_before_send = crash_before_send
        self.crash_after_observation = crash_after_observation

    def _persist(self):
        _write_json(self.path, {
            "creates": self.creates, "reads": self.reads,
            "tickets": [{"tenant": tenant, "key": key, "value": value}
                        for (tenant, key), value in self.state.items()],
        })

    def create(self, ctx, payload, operation_id, **kwargs):
        if self.crash_before_send:
            os._exit(_CRASH_EXIT)
        if not (self.crash_after_create or self.allow_create):
            # Persist the attempted retry too: even if the application catches
            # this assertion, the parent must observe the forbidden dispatch.
            self.creates += 1
            self._persist()
            raise AssertionError("recovery is read-only; create must never be retried")
        receipt = super().create(ctx, payload, operation_id, **kwargs)
        self._persist()
        # Deliberately bypass every finally block/exception handler. The OS
        # releases the service lock when this interpreter terminates.
        if self.crash_after_create:
            os._exit(_CRASH_EXIT)
        return receipt

    def find(self, ctx, payload, **kwargs):
        self.reads += 1
        result = super().find(ctx, payload, **kwargs)
        self._persist()
        return result

    def verify(self, ctx, key, payload, **kwargs):
        self.reads += 1
        result = super().verify(ctx, key, payload, **kwargs)
        self._persist()
        if self.crash_after_observation:
            os._exit(_CRASH_EXIT)
        return result


def _matrix_crash(ctx, service, root, point):
    row = service.intake(ctx, "Synthetic Crash Matrix Vendor", "security-paper", "VEND", "Offline crash matrix")
    row = service.collect_evidence(ctx, row["id"], row["revision"])
    row = service.assess(ctx, row["id"], row["revision"])
    row = service.review(ctx, row["id"], row["revision"], "approved", "Restricted synthetic pilot")
    _write_json(root / "case-reference.json", {"case_id": row["id"]})
    save = service._save

    def crash_at_transition(context, current, **changes):
        preparing = changes.get("stage") == "action_pending_approval"
        if (point == "before_intent" and preparing
                or point == "before_local_acceptance" and changes.get("outcome")):
            os._exit(_CRASH_EXIT)
        saved = save(context, current, **changes)
        if point == "after_intent" and preparing:
            os._exit(_CRASH_EXIT)
        return saved

    service._save = crash_at_transition
    row = service.prepare_action(ctx, row["id"], row["revision"])
    row = service.approve_action(
        ctx,
        row["id"],
        row["revision"],
        row["operation"]["approval_card"]["binding_sha256"],
    )
    row = service.execute(ctx, row["id"])
    service.accept(ctx, row["id"], row["revision"], True, "Procurement accepted verified ticket")
    raise AssertionError(f"fixture must terminate at {point}")


def _matrix_resume(ctx, service, tickets, root):
    reference = json.loads((root / "case-reference.json").read_text(encoding="utf-8"))
    row = service.get(ctx, reference["case_id"])
    before = json.loads(json.dumps(row))
    # These two crash points never had an approved operation. An explicit human
    # decision below authorizes the continuation; restart itself grants nothing.
    new_approval = (row.get("operation") or {}).get("state") in {None, "prepared"}
    if row.get("operation") is None:
        row = service.prepare_action(ctx, row["id"], row["revision"])
    if row["operation"]["state"] == "prepared":
        row = service.approve_action(
            ctx,
            row["id"],
            row["revision"],
            row["operation"]["approval_card"]["binding_sha256"],
        )
    row = service.execute(ctx, row["id"])
    if row["operation"]["state"] == "reconciliation_required":
        row = service.reconcile(ctx, row["id"])
    assert row["outcome"] is None
    if row["operation"]["state"] == "verified":
        row = service.accept(ctx, row["id"], row["revision"], True,
                             "Procurement accepted verified ticket")
    return {"pid": os.getpid(), "before": before, "case": row,
            "creates": tickets.creates, "reads": tickets.reads,
            "explicit_new_human_approval": new_approval}


def _worker(mode: str, root: Path) -> dict:
    from maverick import audit, config

    # Test-only audit sink, matching the existing offline acceptance fixtures.
    audit.record = lambda *args, **kwargs: True
    audit.record_global = lambda *args, **kwargs: True
    config.reset_config_cache()
    ctx = ServiceContext("customer-process", "reviewer@example.test", "procurement",
                         "reviewer@example.test", "jira", human=True)
    documents = FakeGoogleDriveEvidence({(ctx.tenant, "security-paper"): EvidenceDocument(
        "security-paper", "1", _NOW - 86400, _DOCUMENT,
    )})
    point = os.environ.get("LIGHTWORK_FIXTURE_CRASH_POINT")
    crashing_matrix = mode == "matrix-crash"
    tickets = _DurableTickets(
        root / "external-provider.json",
        crash_after_create=mode == "crash" or crashing_matrix and point == "after_provider_commit",
        allow_create=mode in {"execute-race", "matrix-crash"}
        or mode == "matrix-resume" and point in {"before_intent", "after_intent"},
        crash_before_send=crashing_matrix and point == "before_send",
        crash_after_observation=crashing_matrix and point == "after_observation",
    )
    service = VendorOnboardingService(
        documents, tickets,
        lambda context, capability, resource: context.tenant == ctx.tenant and context.actor == ctx.actor,
        clock=lambda: _NOW,
    )
    if mode == "matrix-crash":
        return _matrix_crash(ctx, service, root, point)
    if mode == "matrix-resume":
        return _matrix_resume(ctx, service, tickets, root)
    manifest_path = root / "case-reference.json"
    if mode in {"crash", "prepare"}:
        row = service.intake(ctx, "Synthetic Process Vendor", "security-paper", "VEND", "Offline recovery")
        row = service.collect_evidence(ctx, row["id"], row["revision"])
        row = service.assess(ctx, row["id"], row["revision"])
        row = service.review(ctx, row["id"], row["revision"], "approved", "Restricted synthetic pilot")
        row = service.prepare_action(ctx, row["id"], row["revision"])
        row = service.approve_action(
            ctx,
            row["id"],
            row["revision"],
            row["operation"]["approval_card"]["binding_sha256"],
        )
        _write_json(manifest_path, {"case_id": row["id"], "operation_id": row["operation"]["id"]})
        if mode == "prepare":
            return {"case": row}
        service.execute(ctx, row["id"])
        raise AssertionError("fixture must terminate after provider success")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    row = service.get(ctx, manifest["case_id"])
    before = {"state": row["operation"]["state"], "receipt": row["operation"]["receipt"],
              "confirmation": row["operation"]["external_confirmation"], "outcome": row["outcome"]}
    if mode == "execute-race":
        _write_json(root / f"ready-{os.getpid()}.json", {"revision": row["revision"]})
        deadline = time.monotonic() + 15
        while not (root / "dispatch-gate").exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("parent did not release the dispatch gate")
            time.sleep(0.01)
        row = service.execute(ctx, row["id"])
    elif mode == "reconcile":
        row = service.execute(ctx, row["id"])
        assert row["operation"]["state"] == "reconciliation_required"
        row = service.reconcile(ctx, row["id"])
        assert row["operation"]["state"] == "verified"
        with pytest.raises(PermissionError, match="human"):
            service.accept(replace(ctx, human=False), row["id"], row["revision"], True, "Model approval")
        assert service.get(ctx, row["id"])["outcome"] is None
    elif mode == "accept":
        row = service.accept(ctx, row["id"], row["revision"], True, "Procurement accepted verified ticket")
    else:
        raise ValueError(mode)
    return {"pid": os.getpid(), "before": before, "case": row,
            "creates": tickets.creates, "reads": tickets.reads}


def _child(mode, root, env):
    return subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--worker", mode, str(root)],
        env=env, capture_output=True, text=True, encoding="utf-8", timeout=30,
        check=False,
    )


def test_process_loss_after_provider_success_recovers_without_repeating_create(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        "[vendor_onboarding]\nenable=true\n[vendor_management]\nenable=true\n"
        "[ai_vendor_risk]\nenable=true\n[model_risk_assurance]\nenable=true\n",
        encoding="utf-8",
    )
    env = dict(os.environ, MAVERICK_HOME=str(tmp_path / "lightwork-state"),
               MAVERICK_CONFIG=str(config), MAVERICK_ENTERPRISE="0",
               MAVERICK_SECURE_DEFAULT="0", MAVERICK_ENCRYPT_AT_REST="0",
               PYTHONIOENCODING="utf-8")
    env.pop("MAVERICK_TENANT", None)
    env.pop("MAVERICK_CLIENT_ID", None)
    crashed = _child("crash", tmp_path, env)
    assert crashed.returncode == _CRASH_EXIT, crashed.stderr
    external = json.loads((tmp_path / "external-provider.json").read_text(encoding="utf-8"))
    assert external["creates"] == 1
    assert len(external["tickets"]) == 1
    assert external["reads"] == 0  # died before readback or local receipt

    recovered = _child("reconcile", tmp_path, env)
    assert recovered.returncode == 0, recovered.stderr
    proof = json.loads(recovered.stdout)
    assert proof["before"] == {"state": "executing", "receipt": None,
                               "confirmation": None, "outcome": None}
    assert proof["creates"] == 1
    assert proof["reads"] == 2  # search + exact payload readback
    assert proof["case"]["operation"]["attempts"] == 1
    assert proof["case"]["operation"]["external_confirmation"]["reconciled"] is True
    assert proof["case"]["stage"] == "execution_completed"
    assert proof["case"]["outcome"] is None

    accepted = _child("accept", tmp_path, env)
    assert accepted.returncode == 0, accepted.stderr
    final = json.loads(accepted.stdout)
    assert final["pid"] != proof["pid"]
    assert final["before"]["outcome"] is None
    assert final["case"]["outcome"]["accepted"] is True
    assert final["case"]["outcome"]["released"] is False
    assert final["case"]["operation"]["id"] == proof["case"]["operation"]["id"]
    assert final["creates"] == 1
    assert final["reads"] == 3  # acceptance rechecks the external state


def test_two_actual_processes_contend_for_one_approved_intent(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text(
        "[vendor_onboarding]\nenable=true\n[vendor_management]\nenable=true\n"
        "[ai_vendor_risk]\nenable=true\n[model_risk_assurance]\nenable=true\n",
        encoding="utf-8",
    )
    env = dict(os.environ, MAVERICK_HOME=str(tmp_path / "lightwork-state"),
               MAVERICK_CONFIG=str(config), MAVERICK_ENTERPRISE="0",
               MAVERICK_SECURE_DEFAULT="0", MAVERICK_ENCRYPT_AT_REST="0",
               PYTHONIOENCODING="utf-8")
    env.pop("MAVERICK_TENANT", None)
    env.pop("MAVERICK_CLIENT_ID", None)
    prepared = _child("prepare", tmp_path, env)
    assert prepared.returncode == 0, prepared.stderr
    original = json.loads(prepared.stdout)["case"]
    workers = []
    try:
        for _ in range(2):
            workers.append(subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--worker", "execute-race", str(tmp_path)],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8",
            ))
        deadline = time.monotonic() + 20
        while len(list(tmp_path.glob("ready-*.json"))) != 2:
            assert time.monotonic() < deadline, "both workers must reach the same intent before dispatch"
            assert all(worker.poll() is None for worker in workers), "worker exited before dispatch"
            time.sleep(0.01)
        ready = [json.loads(path.read_text(encoding="utf-8")) for path in tmp_path.glob("ready-*.json")]
        assert [item["revision"] for item in ready] == [original["revision"]] * 2
        (tmp_path / "dispatch-gate").write_text("ready", encoding="utf-8")
        results = []
        for worker in workers:
            stdout, stderr = worker.communicate(timeout=30)
            assert worker.returncode == 0, stderr
            results.append(json.loads(stdout))
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
            worker.wait(timeout=5)
    external = json.loads((tmp_path / "external-provider.json").read_text(encoding="utf-8"))
    assert external["creates"] == 1
    assert len(external["tickets"]) == 1
    assert results[0]["pid"] != results[1]["pid"]
    assert results[0]["case"] == results[1]["case"]
    assert results[0]["case"]["revision"] == original["revision"] + 2
    assert results[0]["case"]["operation"]["attempts"] == 1
    assert results[0]["case"]["operation"]["id"] == original["operation"]["id"]


@pytest.mark.parametrize("point,prior_state,creates", [
    ("before_intent", None, 0),
    ("after_intent", "prepared", 0),
    ("before_send", "executing", 0),
    ("after_provider_commit", "executing", 1),
    ("after_observation", "executing", 1),
    ("before_local_acceptance", "verified", 1),
])
def test_six_crash_points_preserve_authority_effect_and_acceptance(tmp_path, point, prior_state, creates):
    config = tmp_path / "config.toml"
    config.write_text(
        "[vendor_onboarding]\nenable=true\n[vendor_management]\nenable=true\n"
        "[ai_vendor_risk]\nenable=true\n[model_risk_assurance]\nenable=true\n",
        encoding="utf-8",
    )
    env = dict(os.environ, MAVERICK_HOME=str(tmp_path / "lightwork-state"),
               MAVERICK_CONFIG=str(config), MAVERICK_ENTERPRISE="0",
               MAVERICK_SECURE_DEFAULT="0", MAVERICK_ENCRYPT_AT_REST="0",
               PYTHONIOENCODING="utf-8", LIGHTWORK_FIXTURE_CRASH_POINT=point)
    env.pop("MAVERICK_TENANT", None)
    env.pop("MAVERICK_CLIENT_ID", None)
    crashed = _child("matrix-crash", tmp_path, env)
    assert crashed.returncode == _CRASH_EXIT, crashed.stderr
    provider_path = tmp_path / "external-provider.json"
    prior = json.loads(provider_path.read_text(encoding="utf-8")) if provider_path.exists() else {}
    assert prior.get("creates", 0) == creates
    assert len(prior.get("tickets", [])) == creates
    recovered = _child("matrix-resume", tmp_path, env)
    assert recovered.returncode == 0, recovered.stderr
    proof = json.loads(recovered.stdout)
    before, final = proof["before"], proof["case"]
    assert (before.get("operation") or {}).get("state") == prior_state
    assert before["outcome"] is None
    assert proof["explicit_new_human_approval"] is (prior_state in {None, "prepared"})
    if before.get("operation"):
        assert final["operation"]["id"] == before["operation"]["id"]
        assert final["operation"]["payload_sha256"] == before["operation"]["payload_sha256"]
    if point == "before_send":
        # The durable claim alone cannot prove a send occurred; absent search
        # results do not authorize a new create or a fabricated acceptance.
        assert proof["creates"] == 0 and proof["reads"] == 1
        assert final["stage"] == "reconciliation_required"
        assert final["outcome"] is None
        assert final["operation"]["receipt"] is None
    else:
        assert proof["creates"] == 1
        assert final["stage"] == "accepted"
        assert final["operation"]["state"] == "verified"
        assert final["outcome"]["accepted"] is True
        assert final["outcome"]["released"] is False
    assert final["operation"]["attempts"] == 1


if __name__ == "__main__":
    assert sys.argv[1] == "--worker"
    print(json.dumps(_worker(sys.argv[2], Path(sys.argv[3])), sort_keys=True))
