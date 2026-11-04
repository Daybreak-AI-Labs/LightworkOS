"""Installed release adapter for bounded rule-only taught workflows.

Native completed practice proves execution readiness for that exact bundle,
not accuracy, generalization or improvement. Independent release approval stays
in CandidatePromotions. Included workflows must use bounded owned rules. No
tools, AI fallback or outside effects are admitted: restoring publication
therefore cannot claim to undo business actions.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from contextlib import contextmanager
from contextvars import ContextVar

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from maverick.candidate_promotion import (
    ArtifactCommitment,
    ArtifactObservation,
    CanaryObservation,
    CandidatePromotionConflict,
    CandidatePromotionDenied,
    CandidatePromotionUnavailable,
    DeploymentEffectReceipt,
    DeploymentObservation,
    DeploymentReconciliation,
    LineageCommitment,
    PromotionTarget,
    PromotionTargetPreset,
    ResourceRequirements,
    RunPromotionAdmission,
    StudyClaim,
    TrustedStudyAdmission,
)
from maverick.flow import runner, store
from maverick.flow.ir import validate_learned_operator
from maverick.governed_records import GovernedRecordStore, configured_governed_records_backend
from maverick.paths import canonical_tenant_id, tenant_scope
from pydantic import BaseModel, ConfigDict, Field

from . import rbac, workspace_tenants
from .candidate_promotion_api import _binding

router = APIRouter(prefix="/api/v1/research/local-flow-release", tags=["local-flow-release"])
asset_router = APIRouter()
TARGET = "installed-lightwork"
STATE = "lightwork.rule-only-flow-release.v1"
INTENTS = "lightwork.publication-bound-flow-runs.v1"
RECONCILE = "lightwork.local-flow-release-reconciliation.v1"
PROTOCOL = "Successful exact-definition practice; live terminal failure rate. No correctness or improvement claim."
SOURCE = re.compile(r"artifact:flow-bundle/([A-Za-z0-9][A-Za-z0-9_.-]{0,127})/([a-f0-9]{64})\Z")
_OPERATOR = ContextVar("local_flow_release_operator", default=None)
_TERMINAL = {runner.STATUS_COMPLETED, runner.STATUS_FAILED, runner.STATUS_REJECTED,
             runner.STATUS_INDETERMINATE, runner.STATUS_BUDGET_LIMITED}


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value):
    return hashlib.sha256(_bytes(value)).hexdigest()


def _records():
    if configured_governed_records_backend() != "local":
        raise CandidatePromotionUnavailable("Local workflow releases require a single-computer installation.")
    return GovernedRecordStore("local-flow-release-targets", "LFT", "local_flow_release", required_backend="local")


def _effects():
    return GovernedRecordStore("local-flow-release-effects", "LFX", "local_flow_release_effect", required_backend="local")


def _owner_authority(tenant, owner):
    from maverick.tenant.registry import assert_tenant_active

    from .scim_groups import active_for_principal
    from .session_revocation import revocation_epoch

    assert_tenant_active(tenant)
    selected, generation = workspace_tenants.get_selection_binding(owner)
    role = rbac.get_tenant_role(tenant, owner)
    if (not owner.startswith("user:") or selected != tenant
            or active_for_principal(owner) is False
            or "operate" not in rbac.permissions_for(role)):
        raise CandidatePromotionDenied("The workflow owner's current workspace permission is unavailable.")
    return _sha([tenant, owner, role, generation, revocation_epoch(owner.removeprefix("user:"))])


def _pure_definition(flow, *, permit_fallback=False):
    from .flows_api import _require_learned_flow_evidence

    if flow.learned_recipe is not None or not flow.nodes or len(flow.nodes) > 64:
        raise CandidatePromotionDenied("This release path supports bounded taught rules only.")
    _require_learned_flow_evidence(flow)
    taught = 0
    for node in flow.nodes.values():
        if node.body is not None or node.branches or node.kind not in {"agent", "setvar", "branch", "switch", "subflow"}:
            raise CandidatePromotionDenied("Connected actions and waiting steps need a separate release connection.")
        if node.kind == "agent":
            validate_learned_operator(node)
            if node.learned_operator is None or not permit_fallback and node.learned_fallback is not False:
                raise CandidatePromotionDenied("Turn on Use learned rules only, save, and complete a new practice run first.")
            taught += 1
    if flow.validate() or flow.reachability_errors():
        raise CandidatePromotionDenied("The saved workflow needs valid taught rules and complete routes.")
    return taught


def qualified_bundle(flow, *, permit_fallback=False, retained_manifest=None,
                     require_current_versions=True):
    """Qualify one finite, owner-contained complete execution bundle.

    Retained publication arms use their own immutable child map. Newer drafts
    do not rewrite those arms, but deletion, owner/generation replacement and
    current evidence withdrawal still refuse their use.
    """
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    _owner_authority(tenant, flow.owner)
    if not require_current_versions and retained_manifest is None:
        raise CandidatePromotionDenied("Choose the exact retained included versions before reviewing old rules.")
    if retained_manifest is not None and (not isinstance(retained_manifest, dict)
            or len(retained_manifest) > 16
            or any(not isinstance(key, str) or not isinstance(value, str)
                   or re.fullmatch(r"[a-f0-9]{64}", value) is None
                   for key, value in retained_manifest.items())):
        raise CandidatePromotionDenied("The retained included workflows cannot be verified.")
    with store._definitions_lock():
        visiting, visited, definitions, heights = set(), set(), [], {}
        node_count, taught = 0, 0

        def visit(current, depth):
            nonlocal node_count, taught
            if depth > 8 or current.id in visiting:
                raise CandidatePromotionDenied("Included workflows must finish without calling themselves, within eight levels.")
            if current.id in visited:
                if depth + heights[current.id] > 8:
                    raise CandidatePromotionDenied("Included workflows must stay within eight levels on every route.")
                return heights[current.id]
            if len(definitions) >= 17:
                raise CandidatePromotionDenied("Choose at most sixteen included workflows for this release.")
            live = store.load_flow(current.id)
            if (live is None or current.owner != flow.owner or live.owner != flow.owner
                    or live.revision != current.revision
                    or require_current_versions and live.to_dict() != current.to_dict()):
                raise CandidatePromotionDenied("An included workflow was removed, changed or is no longer owned by this account. Review current saved versions.")
            node_count += len(current.nodes)
            if node_count > 64:
                raise CandidatePromotionDenied("Use at most sixty-four total steps across this release.")
            taught += _pure_definition(current, permit_fallback=permit_fallback)
            definitions.append(current)
            visiting.add(current.id)
            height = 0
            for node in current.nodes.values():
                if node.kind != "subflow":
                    continue
                if retained_manifest is None:
                    child = store.load_flow(node.flow_ref)
                else:
                    digest = retained_manifest.get(node.flow_ref)
                    child = store.load_flow_snapshot(digest) if digest else None
                if child is None or child.id != node.flow_ref:
                    raise CandidatePromotionDenied("An included workflow is unavailable. Open the saved workflow and choose it again.")
                height = max(height, 1 + visit(child, depth + 1))
            visiting.remove(current.id)
            visited.add(current.id)
            heights[current.id] = height
            return height

        visit(flow, 0)
        if not taught:
            raise CandidatePromotionDenied("Include at least one step with valid taught rules.")
        if retained_manifest is None:
            root, _version, children = store.snapshot_flow_bundle(flow)
        else:
            root = hashlib.sha256(store._canonical_flow_bytes(flow.to_dict())).hexdigest()
            children = dict(retained_manifest)
        store.validate_snapshot_bundle_owners(flow, children)
        material = {"schema": "maverick.flow.release.v1", "definition_digest": root, "subflow_digests": children}
        return {"root": root, "manifest": children, "flows": definitions,
                "bundle_sha": store.release_digest_for(root, children), "size": len(_bytes(material)),
                "taught_count": taught}


def _current(tenant, owner, flow_id):
    _owner_authority(tenant, owner)
    flow = store.load_flow(flow_id)
    if flow is None or flow.owner != owner:
        raise CandidatePromotionDenied("The selected workflow is no longer available to its owner.")
    return flow


def _bundle(flow):
    value = qualified_bundle(flow)
    return value["root"], value["bundle_sha"], value["size"]


def _practice(record):
    from maverick.config import get_flows
    from maverick.flow import enabled
    flags = get_flows()
    if not enabled() or flags.get("learned_operators") is not True:
        raise CandidatePromotionDenied("Workflows and learned rules must be enabled before release review.")
    _learning_allowed()
    flow = _current(record["tenant"], record["owner"], record["flow_id"])
    bundle = qualified_bundle(flow)
    from maverick.flow.operator_artifacts import COMPOSED_SCHEMA
    if flags.get("composed_operators") is not True and any(
            node.learned_operator and node.learned_operator["artifact"].get("schema") == COMPOSED_SCHEMA
            for included in bundle["flows"] for node in included.nodes.values()):
        raise CandidatePromotionDenied("Composed learned rules must be enabled before this release review.")
    root, bundle_sha, size = bundle["root"], bundle["bundle_sha"], bundle["size"]
    if root != record["root"] or bundle_sha != record["bundle_sha"]:
        raise CandidatePromotionConflict("The workflow changed after its practice check. Prepare a new release review.")
    run = store.load_run(record["practice_run"], owner=record["owner"])
    if (run is None or run.flow_id != flow.id or run.dry_run is not True
            or not _successful_execution(run) or run.definition_digest != root
            or run.definition_version != flow.version or run.definition_revision != flow.revision
            or run.subflow_digests != bundle["manifest"]):
        raise CandidatePromotionDenied("A successful practice run of this exact saved rule-only version is required.")
    result = _practice_result(run)
    if result != record["practice_result"]:
        raise CandidatePromotionConflict("The recorded practice result changed. Prepare a new review.")
    if record.get("comparison_id"):
        from .local_flow_comparisons import validate_release
        comparison = validate_release(record["comparison_id"], record)
        if comparison["binding"] != record.get("comparison_binding"):
            raise CandidatePromotionConflict("The known-case comparison changed. Prepare a new release review.")
    return flow, root, bundle_sha, size, result


def _practice_result(run):
    return _sha([run.run_id, run.definition_digest, run.subflow_digests, run.status, run.updated,
                 sorted((key, row.get("status"), row.get("outcome")) for key, row in run.nodes.items())])


def _successful_execution(run):
    # Native taught agents report agreement with no correctness outcome;
    # included workflows report successful completion as 1.0, failure as 0.0.
    return (run.status == runner.STATUS_COMPLETED and not run.error and bool(run.nodes)
            and all(row.get("status") == "done" and row.get("outcome") in (None, 1.0)
                    for row in run.nodes.values()))


def _learning_allowed():
    from maverick.learning_guard import Halted, check_learning_halt
    try:
        check_learning_halt("flow_rule_release", "review")
    except Halted as exc:
        raise CandidatePromotionDenied("Learning is paused. Review the emergency stop before preparing or publishing new rules.") from exc


def _retained_bundle(flow, release):
    if flow is None:
        raise CandidatePromotionDenied("The retained workflow is unavailable. Restoration cannot continue.")
    bundle = qualified_bundle(flow, retained_manifest=release.get("subflow_digests", {}),
                              require_current_versions=False)
    if bundle["root"] != release.get("definition_digest") or bundle["bundle_sha"] != release.get("release_digest"):
        raise CandidatePromotionDenied("The retained included workflows changed. Review the current publication.")
    return bundle


def _target_record(run_id=None):
    records = _records()
    pointer = records.get("LFT-current") if run_id is None else None
    identifier = pointer.get("target_record") if pointer else "LFT-" + str(run_id or "")[4:]
    value = records.get(identifier) if identifier else None
    if value is None:
        raise CandidatePromotionUnavailable("Prepare a rule-only workflow release on the Research page first.")
    if value.get("tenant") != canonical_tenant_id(value.get("tenant")):
        raise CandidatePromotionDenied("The release belongs to another workspace.")
    return value


def run_admission(tenant, principal, run_id):
    with tenant_scope(tenant=canonical_tenant_id(tenant)):
        record = _target_record(run_id)
        if record["tenant"] != tenant or record["owner"] != principal or record["run_id"] != run_id:
            raise CandidatePromotionDenied("This release-readiness check is not available to your account and workspace.")
        flow, root, bundle_sha, size, result = _practice(record)
        authority = _owner_authority(tenant, principal)
        artifact = ArtifactCommitment("taught-flow", "bundle", f"artifact:flow-bundle/{flow.id}/{root}", bundle_sha, size)
        protocol = _sha(PROTOCOL)
        evaluator = "native-flow-practice"
        if record.get("comparison_id"):
            from .local_flow_comparisons import PROTOCOL as comparison_protocol
            from .local_flow_comparisons import validate_release
            comparison = validate_release(record["comparison_id"], record)
            result = _sha([result, comparison["binding"], comparison["results"]])
            protocol = _sha([PROTOCOL, comparison_protocol])
            evaluator = "native-flow-known-cases"
        study = StudyClaim(_sha([record["run_id"], result, PROTOCOL]), "qualified", result,
                           evaluator, "v1", protocol)
        admission = TrustedStudyAdmission(tenant, run_id, _sha([flow.id, root]), result, bundle_sha,
                                         study, (artifact,), _sha([record["binding"], authority]))
        return RunPromotionAdmission(tenant, principal, "flow-run:" + record["practice_run"], run_id,
            admission.run_manifest_sha256, _sha([record["binding"], authority]), result, bundle_sha,
            (LineageCommitment("model", "taught-flow-" + root[:24], "v" + str(flow.version), root, "reevaluate"),),
            authority, admission)


def artifact_observation(tenant, source_ref):
    with tenant_scope(tenant=canonical_tenant_id(tenant)):
        record = _target_record()
        match = SOURCE.fullmatch(source_ref)
        if not match or (match[1], match[2], tenant) != (record["flow_id"], record["root"], record["tenant"]):
            raise CandidatePromotionDenied("Only the selected immutable taught workflow can be staged.")
        flow, _root, bundle_sha, size, _result = _practice(record)
        return ArtifactObservation(tenant, source_ref, bundle_sha, size,
                                   _sha([record["binding"], flow.owner, _owner_authority(tenant, flow.owner)]))


def target_preset(tenant, preset):
    with tenant_scope(tenant=canonical_tenant_id(tenant)):
        record = _target_record()
        if preset != TARGET or record["tenant"] != tenant:
            raise CandidatePromotionDenied("This local workflow release target is unavailable.")
        return PromotionTargetPreset(TARGET,
            PromotionTarget(TARGET, record["baseline"]["release_digest"], STATE, INTENTS, RECONCILE),
            ResourceRequirements(0, 1_000_000, 0.0), record["binding"])


def completed_runs(tenant, principal):
    try:
        with tenant_scope(tenant=canonical_tenant_id(tenant)):
            record = _target_record()
            run_admission(tenant, principal, record["run_id"])
            return (record["run_id"],)
    except (CandidatePromotionDenied, CandidatePromotionConflict, CandidatePromotionUnavailable):
        return ()


def _release_runs(record, activation):
    if not activation:
        return []
    rows = []
    for preview in store.iter_run_metadata(batch_size=200, flow_id=record["flow_id"],
            owner=record["owner"], release_id=activation, statuses=_TERMINAL):
        if preview.dry_run:
            continue
        # The disposable index selects candidates; retained checkpoints establish
        # the execution evidence saved by canary acceptance.
        run = store.load_run(preview.run_id, owner=record["owner"], flow_id=record["flow_id"])
        if (run is None or run.release_id != activation or run.status not in _TERMINAL
                or run.dry_run):
            continue
        rows.append(run)
        if len(rows) == 1000:
            break
    return rows


def release_status(manifest, *, review=False):
    """A release-only projection; private input/output data is never included."""
    record = _bound(manifest)
    root = store.load_flow_snapshot(record["root"])
    bundle = _retained_bundle(root, {"definition_digest": record["root"], "release_digest": record["bundle_sha"],
                                    "subflow_digests": record.get("subflow_digests", {})})
    active = store.load_published_bundle(record["flow_id"])
    effect = _effects().get(_effect_id(manifest))
    activation = effect.get("activation_id") if effect else ""
    rows = _release_runs(record, activation)
    current = active is not None and activation and active[1]["release_id"] == activation
    result = {"kind": "rule_only_workflow", "name": root.name, "version": root.version,
              "baseline_version": record["baseline"]["definition_version"],
              "included_workflows": [{"name": flow.name, "version": flow.version} for flow in bundle["flows"][1:]],
              "observed_runs": len(rows), "can_assess": bool(current and rows),
              "current_release": "candidate" if current else "previous" if active and active[1]["release_digest"] == record["baseline"]["release_digest"] else "other",
              "evidence": "Exact-version practice is readiness evidence. Up to the latest 1,000 retained real terminal runs of this activation are checked for failures, not correctness or business improvement.",
              "rollback": "Restores the previous published rules and their exact included versions with a fresh authorization, if their original owners and sources remain available. Waiting work from either old release stays revoked. Saved drafts are kept."}
    if record.get("comparison_id"):
        from .local_flow_comparisons import summary, validate_release
        try:
            comparison = validate_release(record["comparison_id"], record)
            result["known_case_comparison"] = summary(comparison)
            if review:
                def plain(value):
                    return "Yes" if value is True else "No" if value is False else str(value) if value is not None else "No result recorded"
                result["known_case_comparison"]["reviewed_cases"] = [
                    {"expected": plain(case["expected"]), "inputs": case["inputs"],
                     "baseline": plain(pair["baseline"]["result"]), "candidate": plain(pair["candidate"]["result"]),
                     "baseline_matched": pair["baseline"]["matches"], "candidate_matched": pair["candidate"]["matches"]}
                    for case, pair in zip(comparison["cases"], comparison["results"], strict=True)]
        except (CandidatePromotionConflict, CandidatePromotionDenied):
            result["known_case_comparison"] = {"scope": "The original cases are no longer available or their exact binding changed. No current agreement result is claimed."}
    if review:
        result["steps"] = []
        flow_names = {flow.id: flow.name for flow in bundle["flows"]}
        for included in bundle["flows"]:
            names = {key: node.label or "Step " + str(index + 1) for index, (key, node) in enumerate(included.nodes.items())}
            prefix = included.name + " · version " + str(included.version) + " · " if len(bundle["flows"]) > 1 else ""
            result["steps"].extend([{"label": prefix + (node.label or "Step " + str(index + 1)), "kind": node.kind,
                            "instructions": node.brief if node.kind == "agent" else
                                "Run included workflow: " + flow_names[node.flow_ref] if node.kind == "subflow" else "",
                            "questions": node.learned_operator["artifact"].get("spec", {}).get("inputs", {}) if node.learned_operator else {},
                            "examples": node.learned_operator["artifact"].get("examples", []) if node.learned_operator else [],
                            "output": node.output, "fallback": "Stops when the rules do not agree" if node.kind == "agent" else "",
                            "included_workflow": flow_names.get(node.flow_ref, "") if node.kind == "subflow" else "",
                            "condition": node.condition, "assignments": node.subflow_inputs if node.kind == "subflow" else node.assignments,
                            "cases": [{"condition": node.condition + " equals " + str(case.get("value")),
                                       "next": names.get(case.get("to") or node.next, "Finish")}
                                      for case in node.cases],
                            "next": names.get(node.next, ""),
                            "if_true": names.get(node.if_true, ""), "if_false": names.get(node.if_false, "")}
                           for index, node in enumerate(included.nodes.values())])
    return result


def _effect_id(manifest):
    return "LFX-" + _sha([manifest["run"]["tenant"], manifest["candidate_id"]])[:40]


def _bound(manifest):
    run = manifest.get("run", {})
    record = _target_record(run.get("run_id"))
    target = manifest.get("target", {})
    if (run.get("tenant") != record["tenant"] or run.get("run_id") != record["run_id"]
            or run.get("output_artifact_sha256") != record["bundle_sha"]
            or target.get("target_id") != TARGET
            or target.get("expected_active_sha256") != record["baseline"]["release_digest"]):
        raise CandidatePromotionConflict("The local release target changed. Review the current workflow release.")
    return record


def _receipt(record, effect, action):
    before, after = (record["bundle_sha"], record["baseline"]["release_digest"]) if action == "rollback" else (
        record["baseline"]["release_digest"], record["bundle_sha"])
    return DeploymentEffectReceipt(record["tenant"], TARGET, action + "-" + effect["id"][4:],
                                   action, before, after, _sha([effect["id"], action, effect.get(action + "_release")]))


class LocalFlowDeployment:
    @contextmanager
    def authority_scope(self, tenant, actor):
        from .candidate_promotion_composition import _authority
        _authority(tenant, actor)
        token = _OPERATOR.set((tenant, actor))
        try:
            yield
        finally:
            _OPERATOR.reset(token)

    @staticmethod
    def _actor(record):
        binding = _OPERATOR.get()
        if not binding or binding[0] != record["tenant"] or binding[1] == record["owner"]:
            raise CandidatePromotionDenied("A current independent release administrator must decide this operation.")
        grant = record.get("release_authorization", {})
        if (grant.get("owner") != record["owner"] or grant.get("bundle_sha") != record["bundle_sha"]
                or grant.get("baseline_release") != record["baseline"]["release_id"]
                or grant.get("flow_revision") != record["flow_revision"]
                or grant.get("scope") != "independent_publish_and_retained_restore"):
            raise CandidatePromotionDenied("The workflow owner did not authorize this exact publication and retained restoration.")
        return binding[1]

    def observe(self, tenant, target_id):
        with tenant_scope(tenant=canonical_tenant_id(tenant)):
            record = _target_record()
            if target_id != TARGET or record["tenant"] != tenant:
                raise CandidatePromotionDenied("This release target is unavailable.")
            flow = _current(tenant, record["owner"], record["flow_id"])
            active = store.load_published_bundle(flow.id)
            if active is None or active[0].owner != flow.owner or active[0].revision != flow.revision:
                raise CandidatePromotionConflict("The selected workflow has no current compatible publication.")
            _retained_bundle(*active)
            release = active[1]
            # Keyset paging over active statuses only: newer finished runs must not hide older waiting work.
            pending = [(run.run_id, run.status, run.release_id)
                       for run in store.iter_run_metadata(batch_size=200, flow_id=flow.id, statuses=runner.ACTIVE_STATUSES)]
            return DeploymentObservation(tenant, TARGET, release["release_digest"], STATE, INTENTS,
                _sha(["no outside effects", flow.owner, flow.revision]), _sha(pending), record["binding"], True,
                _sha([release, pending, record["binding"]]))

    def stage(self, manifest):
        record = _bound(manifest)
        actor = self._actor(record)
        _practice(record)
        with store.active_release_guard(record["flow_id"], expected_release_id=record["baseline"]["release_id"]):
            effect = _effects().create({"id": _effect_id(manifest), "binding": record["binding"],
                "manifest": _sha(manifest), "activation_id": secrets.token_hex(32),
                "restore_id": secrets.token_hex(32), "activate_release": None, "rollback_release": None},
                action="flow.release.stage", actor=actor)
        return _receipt(record, effect, "stage")

    def _effect(self, manifest):
        effect = _effects().get(_effect_id(manifest))
        if effect is None or effect["manifest"] != _sha(manifest):
            raise CandidatePromotionConflict("This exact workflow has not been staged.")
        return effect

    def activate(self, manifest, stage_receipt):
        record = _bound(manifest)
        actor = self._actor(record)
        flow, _root, _sha_bundle, _size, _result = _practice(record)
        effect = self._effect(manifest)
        if stage_receipt.get("operation_id") != _receipt(record, effect, "stage").operation_id:
            raise CandidatePromotionConflict("The staged release changed.")
        release = store.publish_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision,
            expected_release_id=record["baseline"]["release_id"], activation_id=effect["activation_id"],
            expected_bundle_digest=record["bundle_sha"])
        effect = _effects().update(effect["id"], lambda row: row.update(activate_release=release),
            expected_revision=effect["revision"], action="flow.release.activate", actor=actor)
        return _receipt(record, effect, "activate")

    def canary(self, manifest):
        record = _bound(manifest)
        effect = self._effect(manifest)
        observed = self.observe(record["tenant"], TARGET)
        active = store.load_published_bundle(record["flow_id"])
        if active[1]["release_id"] != effect["activation_id"]:
            raise CandidatePromotionConflict("The current publication is not this candidate's activation.")
        rows = _release_runs(record, effect["activation_id"])
        if not rows:
            raise CandidatePromotionUnavailable("Complete a real run of this release before assessing its observed failure rate.")
        failed = sum(not _successful_execution(run) for run in rows)
        return CanaryObservation(record["tenant"], TARGET, observed.active_artifact_sha256,
            (("error_rate", failed / len(rows)),), _sha([(run.run_id, run.status, run.updated) for run in rows]))

    def rollback(self, manifest, rollback_handle):
        record = _bound(manifest)
        actor = self._actor(record)
        effect = self._effect(manifest)
        if rollback_handle != record["binding"]:
            raise CandidatePromotionConflict("The retained release does not match this review.")
        # Match native lock order. Qualification and restoration share one
        # definition critical section, so a child cannot disappear or change
        # original ownership/generation between those decisions.
        with store._activation_lock(record["flow_id"]), store._definitions_lock():
            draft = store.load_flow(record["flow_id"])
            if draft is None or draft.owner != record["owner"] or draft.revision != record["flow_revision"]:
                raise CandidatePromotionConflict("The workflow owner or generation changed. Restoration is blocked.")
            prior = store.load_flow_snapshot(record["baseline"]["definition_digest"])
            _retained_bundle(prior, record["baseline"])
            release = store.restore_published_flow(draft.id, record["baseline"], expected_release_id=effect["activation_id"],
                expected_version=draft.version, expected_revision=draft.revision, activation_id=effect["restore_id"])
        effect = _effects().update(effect["id"], lambda row: row.update(rollback_release=release),
            expected_revision=effect["revision"], action="flow.release.restore", actor=actor)
        return _receipt(record, effect, "rollback")

    def reconcile(self, manifest):
        record = _bound(manifest)
        effect = _effects().get(_effect_id(manifest))
        if effect is not None and effect["manifest"] != _sha(manifest):
            raise CandidatePromotionConflict("The saved release decision changed.")
        active = store.load_published_bundle(record["flow_id"])
        if active is None or active[0].owner != record["owner"] or active[0].revision != record["flow_revision"]:
            raise CandidatePromotionConflict("The current workflow release cannot be reconciled.")
        _retained_bundle(*active)
        release = active[1]
        restored = release["release_id"] in {record["baseline"]["release_id"], effect["restore_id"] if effect else ""}
        if release["release_id"] not in {record["baseline"]["release_id"], effect["activation_id"] if effect else "", effect["restore_id"] if effect else ""}:
            raise CandidatePromotionConflict("Another publication replaced this release. No action was repeated.")
        return DeploymentReconciliation(record["tenant"], TARGET, release["release_digest"], STATE, INTENTS,
            restored, True, True, _sha([release, "No connected effects; other activation epochs remain revoked."]))


def install_local_flow_promotions(state):
    """Supply the stock bounded adapter without replacing explicit deployment wiring."""
    names = {"candidate_promotion_artifact_resolver": artifact_observation,
             "candidate_promotion_deployment_adapter": LocalFlowDeployment(),
             "candidate_promotion_run_admission_resolver": run_admission,
             "candidate_promotion_target_preset_resolver": target_preset,
             "candidate_promotion_completed_runs_resolver": completed_runs}
    # A custom study/deployment owns its composition. Never mix our target with it.
    if (any(getattr(state, name, None) is not None for name in names)
            or getattr(state, "candidate_promotion_study_resolver", None) is not None
            or getattr(state, "candidate_promotions_factory", None) is not None
            or getattr(state, "candidate_promotions", None) is not None):
        return
    for name, value in names.items():
        setattr(state, name, value)
    state.local_flow_promotions_installed = True


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm: bool
    flow_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    version: int = Field(ge=1)
    revision: str = Field(min_length=1, max_length=128)
    practice_run: str = Field(default="", max_length=128)
    comparison_id: str = Field(default="", pattern=r"^(?:FCP-[a-f0-9]{32})?$")
    bundle_sha: str = Field(default="", pattern=r"^(?:[a-f0-9]{64})?$")


def _practice_runs(flow, owner, bundle, limit=50):
    """The newest finished practice runs of this exact bundle, found without reading run files."""
    runs = []
    # A practice (dry) run is pinned to its bundle's release digest, so the index
    # selects just those runs however many real runs came after them.
    for run in store.iter_run_metadata(batch_size=100, flow_id=flow.id, owner=owner,
            release_id=bundle["bundle_sha"], statuses={runner.STATUS_COMPLETED}):
        if (run.dry_run and _successful_execution(run)
                and run.definition_digest == bundle["root"] and run.definition_version == flow.version
                and run.definition_revision == flow.revision and run.subflow_digests == bundle["manifest"]):
            runs.append(run)
            if len(runs) == limit:
                break
    return runs


def choices(request):
    from fastapi import Response
    from maverick.config import candidate_promotion_enabled

    tenant, actor, context = _binding(request, Response())
    flows = []
    from .local_flow_comparisons import records as comparisons
    comparison_rows = comparisons().list(limit=1000) if getattr(request.app.state, "local_flow_promotions_installed", False) else []
    for flow in store.list_flows():
        if flow.owner != actor:
            continue
        try:
            bundle = qualified_bundle(flow, permit_fallback=True)
            published = store.load_published_bundle(flow.id)
        except (ValueError, CandidatePromotionDenied, CandidatePromotionConflict, CandidatePromotionUnavailable,
                HTTPException, store.FlowSnapshotError):
            # One workflow with an unreadable or unqualified publication must not hide the others.
            continue
        root = bundle["root"]
        runs = _practice_runs(flow, actor, bundle)
        checks = [{"id": row["id"], "when": row["created_at"], "cases": len(row["cases"])}
                  for row in comparison_rows if row.get("flow_id") == flow.id and row.get("owner") == actor
                  and row.get("root") == root and row.get("bundle_sha") == bundle["bundle_sha"]
                  and row.get("state") == "done" and published and row.get("baseline") == published[1]]
        included = [{"name": child.name, "version": child.version, "href": "/flows/designer/" + child.id,
                     "rules_only": all(node.learned_fallback is False for node in child.nodes.values() if node.kind == "agent")}
                    for child in bundle["flows"][1:]]
        flows.append({"id": flow.id, "name": flow.name, "version": flow.version, "revision": flow.revision,
                      "bundle_sha": bundle["bundle_sha"], "included_workflows": included,
                      "root_rules_only": all(node.learned_fallback is False for node in flow.nodes.values() if node.kind == "agent"),
                      "rules_only": all(node.learned_fallback is False for child in bundle["flows"]
                                        for node in child.nodes.values() if node.kind == "agent"),
                      "published": published is not None, "practice_runs": [{"id": run.run_id, "created": run.created} for run in runs],
                      "baseline_version": published[0].version if published else None,
                      "comparisons": checks[:50],
                      "href": "/flows/" + flow.id})
    prepared = None
    try:
        record = _target_record()
        if record["tenant"] == tenant and record["owner"] == actor:
            _practice(record)
            prepared = {"flow_id": record["flow_id"], "version": record["version"],
                        "bundle_sha": record["bundle_sha"], "practice_run": record["practice_run"],
                        "comparison_id": record.get("comparison_id", "")}
    except (CandidatePromotionUnavailable, CandidatePromotionConflict, CandidatePromotionDenied, store.FlowSnapshotError):
        pass
    return {"context": context, "enabled": candidate_promotion_enabled(), "flows": flows, "prepared": prepared,
            "detail": "Use a published rule-only baseline, then change and practice the new saved version. This checks readiness, not accuracy or improvement. One local release review is prepared per workspace at a time."}


def prepare_local_release(request, payload, *, rules_only=False):
    from fastapi import Response
    from maverick.authority_effects import authority_effect_fence

    from .flows_api import _assert_flow_access, _require_flows, _require_learned_flow_evidence

    tenant, actor, _context = _binding(request, Response(), payload)
    if not getattr(request.app.state, "local_flow_promotions_installed", False):
        raise HTTPException(409, "This installation uses its own release connection. Ask its administrator to review that setup.")
    _require_flows()
    with authority_effect_fence():
        flow = _current(tenant, actor, payload.flow_id)
        _assert_flow_access(request, flow)
        _require_learned_flow_evidence(flow)
        if flow.version != payload.version or flow.revision != payload.revision:
            raise HTTPException(409, "The saved workflow changed. Refresh and review again.")
        bundle = qualified_bundle(flow, permit_fallback=rules_only)
        if (payload.bundle_sha and payload.bundle_sha != bundle["bundle_sha"]
                or bundle["manifest"] and not payload.bundle_sha):
            raise HTTPException(409, "An included workflow changed or was not reviewed. Refresh the complete saved versions before continuing.")
        if rules_only:
            _learning_allowed()
            with store._definitions_lock():
                current = _current(tenant, actor, flow.id)
                current_bundle = qualified_bundle(current, permit_fallback=True)
                if (current.version != flow.version or current.revision != flow.revision
                        or current_bundle["bundle_sha"] != bundle["bundle_sha"]):
                    raise HTTPException(409, "The saved or included workflows changed. Refresh and review again.")
                updated = current.copy()
                for node in updated.nodes.values():
                    if node.kind == "agent":
                        node.learned_fallback = False
                saved = store.save_flow(updated, expected_version=flow.version, expected_revision=flow.revision)
            return {"flow_id": saved.id, "version": saved.version, "detail": "Rule-only draft saved. Publish a baseline, then practice each changed version before preparing its release review."}
        baseline = store.load_published_bundle(flow.id)
        if baseline is None or baseline[0].owner != actor or baseline[0].revision != flow.revision:
            raise HTTPException(409, "Publish a compatible rule-only baseline first.")
        _retained_bundle(*baseline)
        root, bundle_sha = bundle["root"], bundle["bundle_sha"]
        if bundle_sha == baseline[1]["release_digest"]:
            raise HTTPException(409, "The saved draft is already published. Change its learned rules and practice the new version first.")
        run = store.load_run(payload.practice_run, owner=actor)
        if run is None:
            raise HTTPException(409, "Choose a completed practice run for this saved version.")
        result = _practice_result(run)
        material = {"tenant": tenant, "owner": actor, "flow_id": flow.id, "root": root, "bundle_sha": bundle_sha,
                    "version": flow.version, "flow_revision": flow.revision, "baseline": baseline[1],
                    "practice_run": run.run_id, "practice_result": result, "subflow_digests": bundle["manifest"]}
        if payload.comparison_id:
            from .local_flow_comparisons import validate_release
            comparison = validate_release(payload.comparison_id, material)
            material.update(comparison_id=comparison["id"], comparison_binding=comparison["binding"])
        material["release_authorization"] = {"owner": actor, "bundle_sha": bundle_sha,
            "baseline_release": baseline[1]["release_id"], "flow_revision": flow.revision,
            "scope": "independent_publish_and_retained_restore"}
        record = {"id": "LFT-" + _sha(material)[:40], **material, "binding": _sha(material), "run_id": "FLQ-" + _sha(material)[:40]}
        _practice(record)
        records = _records()
        previous = records.get("LFT-current")
        if previous and previous.get("target_record") != record["id"]:
            from .candidate_promotion_api import _service
            service = _service(request)
            rows = service.list(tenant, actor, limit=256)
            if len(rows) == 256 or any(row.get("state") in {"awaiting_review", "authorized", "stage_claimed", "staged",
                    "activation_claimed", "canary", "rollback_claimed", "uncertain"}
                    and row.get("manifest", {}).get("target", {}).get("state_schema") == STATE for row in rows):
                raise HTTPException(409, "Finish or recover this workspace's current workflow release decision before preparing another.")
        saved = records.get(record["id"])
        if saved is None:
            saved = records.create(record, action="flow.release.prepare", actor=actor, max_records=1000)
        pointer = {"id": "LFT-current", "target_record": saved["id"]}
        if previous and previous.get("target_record") != saved["id"]:
            records.update("LFT-current", lambda row: row.update(pointer), expected_revision=previous["revision"],
                           action="flow.release.select", actor=actor)
        elif not previous:
            records.create(pointer, action="flow.release.select", actor=actor)
        return {"flow_id": flow.id, "run_id": saved["run_id"], "target": TARGET,
                "detail": "Exact practice evidence prepared. Ask for independent approval in release decisions. No release was activated and no improvement was established."}


@router.get("")
def local_release_options(request: Request):
    return JSONResponse(choices(request), headers={"Cache-Control": "private, no-store"})


@router.post("/rules-only")
def save_rule_only(payload: Selection, request: Request):
    return _native_call(lambda: prepare_local_release(request, payload, rules_only=True))


@router.post("/prepare")
def prepare_release(payload: Selection, request: Request):
    return _native_call(lambda: prepare_local_release(request, payload))


def _native_call(function):
    try:
        return function()
    except (CandidatePromotionConflict, CandidatePromotionDenied, CandidatePromotionUnavailable,
            store.FlowVersionConflict, store.FlowSnapshotError) as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/review/{candidate_id}")
def review_release(request: Request, candidate_id: str):
    from fastapi import Response

    from .candidate_promotion_api import _service
    tenant, actor, _context = _binding(request, Response(), administrator=True)
    row = _service(request).inspect(tenant, actor, candidate_id)
    return JSONResponse(_native_call(lambda: release_status(row["manifest"], review=True)),
                        headers={"Cache-Control": "private, no-store"})


@asset_router.get("/static/lightwork-local-flow-release.js")
def local_release_asset():
    from .app import _STATIC_DIR
    return FileResponse(_STATIC_DIR / "lightwork-local-flow-release.js", media_type="application/javascript",
                        headers={"Cache-Control": "public, max-age=300"})
