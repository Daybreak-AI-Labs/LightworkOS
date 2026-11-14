"""Acceptance must reject failed verification even with optimized Python."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _optimized(relative):
    path = ROOT / relative
    namespace = {"__name__": "optimized_acceptance", "__file__": str(path)}
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec", optimize=1), namespace)
    return namespace


@pytest.mark.parametrize("scenario", ["bridge", "artifact", "drill", "application", "vendor"])
def test_failed_acceptance_verification_survives_optimization(scenario, tmp_path, monkeypatch):
    if scenario in {"bridge", "artifact"}:
        module = _optimized("scripts/acceptance/signing_identity_transition.py")
        cli = tmp_path / "cli.js"
        cli.touch()
        cli.with_name("package.json").write_text('{"version":"fixture"}')
        monkeypatch.setattr(module["shutil"], "which", lambda _: "node")

        def command(arguments, **_kwargs):
            if "generate" in arguments:
                Path(arguments[-1]).with_suffix(".key.pub").write_text("fixture-public-key")
            else:
                signer = Path(arguments[arguments.index("--private-key-path") + 1]).stem
                Path(arguments[-1] + ".sig").write_text(signer)
            return SimpleNamespace(returncode=0)

        def verify(envelope, **_kwargs):
            if envelope["to_signature"] == "unrelated":
                raise module["bridge"].IdentityTransitionError("unrelated fixture signer")
            return {} if scenario == "bridge" else envelope

        monkeypatch.setattr(module["subprocess"], "run", command)
        monkeypatch.setattr(module["bridge"], "verify", verify)
        module["verify_minisign"] = lambda *_args: "wrong-digest"
        with pytest.raises(RuntimeError, match="verification"):
            module["exercise"](cli)
    elif scenario == "drill":
        # The real rehearsal must exercise its application reader; returning
        # a wrong restored value cannot be hidden by -O removing the check.
        script = ROOT / "scripts/acceptance/workspace_recovery_drill.py"
        code = (
            "import runpy\nfrom maverick_dashboard.draft_store import DraftStore\n"
            "DraftStore.read = lambda *_: {'payload': {'title': 'wrong restored draft'}}\n"
            f"runpy.run_path({str(script)!r}, run_name='__main__')\n"
        )
        result = subprocess.run([sys.executable, "-O", "-c", code], capture_output=True, text=True, timeout=90)
        assert result.returncode != 0
        assert "Restored draft verification failed" in result.stderr
        assert '"fixture_draft_decrypted": true' not in result.stdout
    elif scenario == "application":
        from maverick import recovery_rehearsal, world_model
        from maverick_dashboard.draft_store import DraftStore

        module = _optimized("scripts/acceptance/workspace_application_recovery.py")
        monkeypatch.setattr(recovery_rehearsal, "_run", lambda _: {
            "outcome": "verified_supported_formats", "application_identity": "fixture",
        })
        monkeypatch.setattr(DraftStore, "read", lambda *_: {
            "context": "wrong", "slot": module["SLOT"], "revision": 1, "payload": {"title": module["BEFORE"]},
        })
        goal = SimpleNamespace(id=1, title=module["BEFORE"], description=module["BEFORE"], owner="user:recovery-fixture")
        monkeypatch.setattr(world_model, "WorldModel", lambda _: SimpleNamespace(
            get_goal=lambda ident: goal if ident == 1 else None,
            artifacts_for_goal=lambda _: [{"id": 2, "goal_id": 1, "content": module["BEFORE"], "version": 1}],
            close=lambda: None,
        ))
        (tmp_path / "request.json").write_text(json.dumps({
            "application_version": "fixture", "archive_sha256": "a" * 64, "custody_sha256": "b" * 64,
        }))
        (tmp_path / "recovery.key").write_text("00" * 32)
        module["target"](tmp_path, {"goal": 1, "artifact": 2, "later_goal": 3, "later_artifact": 4})
        evidence = json.loads((tmp_path / "application-result.json").read_text())
        assert evidence["outcome"] == "failed"
        assert evidence["failure_stage"] == "application-readers"
    else:
        from maverick import vendor_evidence_evolution as evolution

        module = _optimized("scripts/demo_vendor_onboarding.py")
        observation = dict.fromkeys((
            "id", "capture_origin", "source_case_id", "source_case_revision", "source_workflow_version",
            "evidence_sha256", "assessment_id", "assessment_revision", "assessment_sha256", "source_provenance_sha256",
        ), "fixture")
        observation["inputs"] = {}
        monkeypatch.setattr(evolution, "EvidenceRenewalEvolution", lambda *_args, **_kwargs: SimpleNamespace(
            observe_case=lambda *_args, **_kwargs: observation,
            propose=lambda *_args, **_kwargs: {"id": "fixture"},
            evaluate=lambda *_args, **_kwargs: {"revision": 1, "evaluation": {}},
            run_for_case=lambda *_args: {"classification": "wrong"},
            promote=lambda *_args, **_kwargs: {"revision": 1},
            rollback=lambda *_args, **_kwargs: {"revision": 2},
        ))
        monkeypatch.setattr(evolution, "RenewalInputs", lambda **kwargs: kwargs)
        module["asdict"] = lambda value: value
        with pytest.raises(RuntimeError, match="verification"):
            module["evolution_example"](None, None, {"id": "fixture", "outcome": {"renewal_due_at": 1000}}, None, [0])
