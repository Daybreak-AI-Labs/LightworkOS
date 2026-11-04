"""Default governed execution over packaged local research containers.

The program remains in the existing ResearchJobs custody. Only supported exact
installed text snapshots are copied into temporary, network-isolated inputs.
Neither a queue receipt nor candidate-reported numbers are execution evidence.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime

from maverick.budget import Budget
from maverick.governed_operations import digest
from maverick.knowledge_content_projection import ExistingKnowledgeContentProjector
from maverick.research_jobs import ResearchJobs
from maverick.research_runs import (
    ResearchDispatchReceipt,
    ResearchMaterializationUnavailable,
    ResearchMetric,
    ResearchResourceCost,
    ResearchRunConflict,
)
from maverick.sandbox.research import ResearchContainerRunner, _input_digest, _inputs

from . import research_api
from .knowledge_access_api import _actor_authority

ADAPTER = "packaged-local-research"
VERSION = "v1"
DATA_FILE = "lightwork_inputs/datasets.json"
CONSTRAINTS = {"local_only", "internal_only", "no_export", "delete_after_use", "no_training", "analysis_only"}


def jobs():
    return ResearchJobs(authority_resolver=research_api.resolve_authority,
        dispatch_authority_resolver=research_api.resolve_dispatch_authority)


def program_choices(tenant, actor):
    service = jobs()
    rows = service.list(tenant, actor)
    choices = []
    for row in rows:
        try:
            source = service._record(row["id"])
            profile, _ = service._fresh(source)
            if source["status"] != "queued" or source.get("registry", {}).get("datasets") or source.get("registry", {}).get("model"):
                continue
            choices.append({"id":source["id"], "label":"Saved program "+str(len(choices)+1)+" · "+source["entrypoint"],
                "code_sha256":source["input_sha256"],"code_revision":"sha256:"+source["input_sha256"],
                "experiment_id":source["evaluator_id"],"experiment_version":profile.evaluator(source["evaluator_id"]).version,
                "environment_id":"installed-local-container","environment_version":"1",
                "environment_sha256":digest(asdict(profile)),"metric_protocol_sha256":digest(asdict(profile.evaluator(source["evaluator_id"])))})
        except (PermissionError, ValueError, RuntimeError):
            continue
    return choices


def _materials(service, record, actor):
    manifest = record["manifest"]
    research_api.resolve_dispatch_authority(record["tenant"], actor)
    source = jobs()._record(manifest.get("program_id", ""))
    if (source["tenant"] != record["tenant"] or source["principal"] != record["created_by"] or source["status"] != "queued" or
            source.get("registry", {}).get("datasets") or source.get("registry", {}).get("model")):
        raise ResearchRunConflict("Choose your current saved program submission with no separate dataset or model binding")
    profile, code = jobs()._fresh(source)
    evaluator = profile.evaluator(source["evaluator_id"])
    expected = {"code_sha256":source["input_sha256"],"code_revision":"sha256:"+source["input_sha256"],
        "experiment_id":evaluator.id,"experiment_version":evaluator.version,
        "environment_id":"installed-local-container","environment_version":"1",
        "environment_sha256":digest(asdict(profile)),"metric_protocol_sha256":digest(asdict(evaluator))}
    if any(manifest.get(key) != value for key,value in expected.items()):
        raise ResearchRunConflict("The selected program, installed setup or result check changed")
    if manifest["action"] != "analyze" or manifest["model_ref"] is not None:
        raise ResearchMaterializationUnavailable("This installed executor analyzes text snapshots without a model. Training and model execution need a separately supported executor")
    caps = manifest["resource_caps"]
    if caps["max_provider_calls"] != 0 or caps["max_cost"] != "0" or caps["max_wall_seconds"] < profile.limits.timeout_seconds+45:
        raise ResearchMaterializationUnavailable("Choose no paid AI calls or spending and enough time for the installed container and its cleanup")
    binding, datasets, _ = service._resolve_binding(record["tenant"], manifest)
    projector = ExistingKnowledgeContentProjector()
    inputs = []
    for admission in datasets:
        if set(admission.usage_constraints)-CONSTRAINTS or not admission.source_ref.startswith((
                "catalog:evidence-graph/","catalog:fleet-memory/","catalog:vector-knowledge/","catalog:knowledge-correction/")):
            raise ResearchMaterializationUnavailable("This dataset source or its usage rules are not supported by the installed text-snapshot executor")
        document = projector.resolve_for_context(record["tenant"],admission.reference,admission,
            _actor_authority(record["tenant"],record["created_by"],"analyze",manifest["purpose"]))
        if document.summary_truncated:
            raise ResearchMaterializationUnavailable("This source needs a complete supported text snapshot before it can be used for an experiment")
        inputs.append({"reference":asdict(admission.reference),"content_sha256":document.content_sha256,
            "title":document.title,"chunks":list(document.retrieval_chunks)})
    encoded=json.dumps({"schema":"lightwork.research-text-inputs.v1","seed":manifest["seed"],"datasets":inputs},
        ensure_ascii=False,sort_keys=True,allow_nan=False,separators=(",",":")).encode("utf-8")
    if DATA_FILE in code or len(encoded)>4*1024*1024:
        raise ResearchMaterializationUnavailable("The bounded dataset input is too large or conflicts with a program file")
    files = _inputs({**code,DATA_FILE:encoded},source["entrypoint"])
    required_storage=sum(len(value) for value in files.values())+profile.limits.scratch_bytes+profile.limits.output_bytes
    if required_storage > caps["max_storage_bytes"]:
        raise ResearchMaterializationUnavailable("Increase the storage limit to cover these inputs, the installed scratch space and bounded output")
    material = {"manifest_sha256":record["manifest_sha256"],"registry_binding_sha256":binding["binding_sha256"],
        "program_id":source["id"],"program_revision":source["revision"],"code_sha256":source["input_sha256"],
        "input_sha256":_input_digest(files),"input_bytes":sum(len(value) for value in files.values()),
        "profile_sha256":digest(asdict(profile)),"evaluator_sha256":digest(asdict(evaluator)),
        "reviewer_authority":asdict(research_api.resolve_dispatch_authority(record["tenant"],actor))}
    return material, profile, evaluator, files, source


def review_binding(service, record, actor):
    return _materials(service,record,actor)[0]


def complete_review(service, record, actor):
    material,profile,evaluator,files,source=_materials(service,record,actor)
    # Readiness checks resolve only a locally present immutable image, never pull.
    runner=ResearchContainerRunner(profile.image_id,limits=profile.limits)
    runner._initialize(budget=Budget(max_wall_seconds=15,max_dollars=0,max_tool_calls=0))
    return {"review_sha256":digest(material),"revision":record["revision"],"binding":material,
        "summary":{"program":source["entrypoint"],"check":evaluator.id.replace("_"," "),
            "environment":"Installed local container", "purpose":record["manifest"]["purpose"].replace("_"," "),
            "datasets":[{"name":ref["asset_id"],"version":ref["version"]} for ref in record["manifest"]["dataset_refs"]],
            "caps":record["manifest"]["resource_caps"],"input_bytes":material["input_bytes"],
            "data_format":"Exact installed text snapshots at /candidate/"+DATA_FILE,
            "limits":"No network or model calls. Candidate output is checked against the installed expected output; it cannot report its own score. Local financial cost is not independently metered."},
        "files":[{"path":name,"text":value.decode("utf-8")} for name,value in sorted(files.items()) if name != DATA_FILE],
        "can_approve":record["created_by"] != actor and record["status"] == "queued"}


class PackagedResearchExecution:
    def __init__(self):
        self.service = None

    def validate_start(self, service, record, actor):
        self.service=service
        approval=service._attempt(record).get("execution_approval")
        if (not isinstance(approval,dict) or approval["reviewer"] != actor or
                service.store.authoritative_time()>=approval["expires_at"] or
                approval["authority"] != asdict(service._worker_authority(record["tenant"],actor)) or
                review_binding(service,record,actor) != approval["binding"]):
            raise ResearchRunConflict("A different administrator must complete the current review before separately starting this run")

    def materialize_and_dispatch(self, request):
        service=self.service
        record=service._record(request.tenant,request.run_id)
        actor=service._attempt(record)["worker_authority"]["principal"]
        self.validate_start(service,record,actor)
        if request.plan != record["manifest"]:
            raise ResearchRunConflict("The admitted execution plan changed")
        material,profile,evaluator,files,source=_materials(service,record,actor)
        budget=Budget(max_input_tokens=0,max_output_tokens=0,max_dollars=0,
            max_wall_seconds=request.resource_caps.max_wall_seconds,max_tool_calls=1)
        @contextmanager
        def guard():
            with service.effect_fence():
                current=service._record(request.tenant,request.run_id)
                self.validate_start(service,current,actor)
                if service._attempt(current).get("stop_requested"):
                    raise ResearchRunConflict("The execution owner requested Stop")
                budget.check()
                yield
        def cancelled():
            current=service._record(request.tenant,request.run_id)
            try:
                research_api.resolve_dispatch_authority(request.tenant,actor)
                return service._attempt(current).get("stop_requested") is True
            except PermissionError:
                return True
        def observe(value):
            service.execution_observation(request.tenant,actor,request.run_id,value)
        result=ResearchContainerRunner(profile.image_id,limits=profile.limits).run(files,budget=budget,
            entrypoint=source["entrypoint"],effect_guard=guard,cancelled=cancelled,observation=observe)
        if result.image_id!=profile.image_id or result.input_sha256!=material["input_sha256"] or not result.cleanup_verified:
            raise ResearchRunConflict("Actual execution provenance or cleanup did not match the review")
        facts=ResearchJobs._safe_result(result)
        facts.update(state="execution_finished", evaluator_id=evaluator.id,evaluator_version=evaluator.version,
            expected_stdout_sha256=evaluator.stdout_sha256, input_bytes=material["input_bytes"],
            review_sha256=digest(material), actual_started_at=result.inspect_policy["execution_started_at"])
        observe(facts)
        return ResearchDispatchReceipt(tenant=request.tenant,run_id=request.run_id,attempt=request.attempt,
            request_sha256=request.request_sha256,dispatch_id=result.container_name,adapter_id=ADAPTER,
            adapter_version=VERSION,adapter_authority_sha256=digest(material),
            materialized_dataset_sha256s=tuple(item.content_sha256 for item in request.datasets),
            dispatched_at=datetime.fromisoformat(facts["actual_started_at"].replace("Z","+00:00")).timestamp())

    def finish(self, service, record, actor):
        attempt=service._attempt(record)
        facts=attempt.get("execution")
        if not isinstance(facts,dict) or facts.get("state")!="execution_finished" or not facts.get("cleanup_verified"):
            raise ResearchRunConflict("Actual execution completion is not available")
        stopped=attempt.get("stop_requested") is True or facts["reason"]=="cancelled"
        passed=not stopped and facts["reason"]=="completed" and facts["exit_code"]==0 and facts["stdout_sha256"]==facts["expected_stdout_sha256"]
        outcome="cancelled" if stopped else "completed" if passed else "failed"
        evidence=digest(facts)
        metric=ResearchMetric(name="correct_output",value="1" if passed else "0",evaluator_id=facts["evaluator_id"],
            evaluator_version=facts["evaluator_version"],source_artifact_sha256=facts["stdout_sha256"],lineage_sha256=facts["input_sha256"])
        costs=(ResearchResourceCost(category="compute",basis="observed",quantity=str(facts["inspect_policy"]["elapsed_seconds"]),
            unit="seconds",amount=None,currency=None,evidence_sha256=evidence,
            source_ref="artifact:research-runs/"+record["run_id"]+"/execution",incomplete_reason="Local compute has no independently metered financial price."),)
        return service.finish(record["tenant"],actor,record["run_id"],expected_revision=record["revision"],outcome=outcome,
            result_idempotency_key="container-result-"+evidence[:32],costs=costs,metrics=() if stopped else (metric,),
            output_artifact_sha256=facts["stdout_sha256"],failure_code=None if outcome=="completed" else "owner_stopped" if stopped else "correct_output_check_failed",
            failure_evidence_sha256=None if outcome=="completed" else evidence)
