"""Tenant-scoped research queue and controller-owned exact-output evaluation.

Only trusted composition supplies authority/profile resolvers or the runner.
Candidates supply UTF-8 files, never host paths, images, evaluator definitions,
credentials, or environment overrides. The built-in oracle checks exact stdout;
it does not qualify arbitrary benchmarks or infer improvement from test prose.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field

from .budget import Budget
from .governed_records import GovernedRecordStore
from .paths import canonical_tenant_id, tenant_scope
from .privacy_ops import RecordConflict
from .provider_cost_cap import work_item_scope
from .research_registry import (
    ResearchAssetRef,
    ResearchRegistry,
    ResearchRegistryError,
)
from .sandbox.research import ResearchContainerRunner, ResearchLimits, _input_digest, _inputs
from .self_modify_evidence import (
    AuthenticatedTestCounts,
    AuthenticatedTestEvidence,
    AuthenticatedTestRequest,
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_ACTIVE = {"running", "cancel_requested"}
_MAX_CANDIDATE = 256 * 1024
_REGISTRY_BINDING_SCHEMA = "lightwork.research-job-registry-binding.v1"


class ResearchConflict(RuntimeError):
    """The reviewed generation or queued authority no longer applies."""


class ResearchNotFound(LookupError):
    """No job visible to this principal in this tenant."""


class ResearchUnavailable(RuntimeError):
    """The operator has not enabled a valid research controller profile."""


class ResearchExecutionUncertain(RuntimeError):
    """A candidate effect occurred but its cleanup or provenance is uncertain."""


def _digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _identifier(value, name):
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class ResearchAuthority:
    tenant: str
    principal: str
    authorization_sha256: str

    def __post_init__(self):
        canonical_tenant_id(self.tenant)
        if (
            type(self.principal) is not str
            or not self.principal.startswith("user:")
            or len(self.principal) > 512
            or any(ord(c) < 32 for c in self.principal)
            or type(self.authorization_sha256) is not str
            or not _SHA.fullmatch(self.authorization_sha256)
        ):
            raise ValueError("named research authority and digest are required")


@dataclass(frozen=True)
class ResearchDispatchAuthority:
    """Current named administrator authority for one research dispatch."""

    tenant: str
    principal: str
    authorization_sha256: str

    def __post_init__(self):
        canonical_tenant_id(self.tenant)
        if (
            type(self.principal) is not str
            or not self.principal.startswith("user:")
            or len(self.principal) > 512
            or any(ord(c) < 32 for c in self.principal)
            or type(self.authorization_sha256) is not str
            or not _SHA.fullmatch(self.authorization_sha256)
        ):
            raise ValueError("named research dispatcher authority and digest are required")


@dataclass(frozen=True)
class ResearchEvaluator:
    id: str
    version: str
    stdout_sha256: str

    def __post_init__(self):
        _identifier(self.id, "evaluator ID")
        _identifier(self.version, "evaluator version")
        if type(self.stdout_sha256) is not str or not _SHA.fullmatch(self.stdout_sha256):
            raise ValueError("evaluator requires an exact stdout SHA-256")


@dataclass(frozen=True)
class ResearchProfile:
    image_id: str
    evaluators: tuple[ResearchEvaluator, ...]
    queue_seconds: int = 3600
    limits: ResearchLimits = field(default_factory=ResearchLimits)

    def __post_init__(self):
        if type(self.image_id) is not str or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", self.image_id
        ):
            raise ValueError("research image must be an immutable locally present ID")
        if (
            type(self.queue_seconds) is not int
            or not 30 <= self.queue_seconds <= 86400
            or type(self.limits) is not ResearchLimits
            or type(self.evaluators) is not tuple
            or not 1 <= len(self.evaluators) <= 32
            or any(type(e) is not ResearchEvaluator for e in self.evaluators)
            or len({e.id for e in self.evaluators}) != len(self.evaluators)
        ):
            raise ValueError("invalid bounded research profile")

    @classmethod
    def from_config(cls, value):
        if not isinstance(value, dict) or value.get("enable") is not True:
            raise ResearchUnavailable(
                "Research execution is disabled by the installation administrator"
            )
        if set(value) - {"enable", "image_id", "evaluators", "queue_seconds", "limits"}:
            raise ValueError("unknown research execution setting")
        raw = value.get("evaluators")
        if not isinstance(raw, dict) or not 1 <= len(raw) <= 32:
            raise ValueError("one to 32 operator-owned evaluators are required")
        evaluators = []
        for name, spec in sorted(raw.items()):
            if not isinstance(spec, dict) or set(spec) != {"version", "stdout_sha256"}:
                raise ValueError("invalid exact-output evaluator configuration")
            evaluators.append(ResearchEvaluator(name, **spec))
        limits = value.get("limits", {})
        if not isinstance(limits, dict) or set(limits) - set(ResearchLimits.__dataclass_fields__):
            raise ValueError("invalid research resource limits")
        return cls(
            value.get("image_id"),
            tuple(evaluators),
            value.get("queue_seconds", 3600),
            ResearchLimits(**limits),
        )

    def evaluator(self, name: str) -> ResearchEvaluator:
        for evaluator in self.evaluators:
            if evaluator.id == name:
                return evaluator
        raise ValueError("select an operator-approved evaluator")


def configured_profile() -> ResearchProfile:
    """Global operator configuration only; tenant overlays cannot edit the oracle."""
    from . import config

    # Prime wizard environment and source-error tracking. This table uses
    # replacement semantics at each higher-precedence source: removing an
    # evaluator in the app must not deep-merge a stale base evaluator back in.
    config.load_global_config()
    if config.config_source_errors(include_tenant=False):
        raise ResearchUnavailable("Research execution configuration is unavailable")
    value = {}
    sources = [config.config_path(), config.dashboard_overrides_path()]
    operator_overlay = os.environ.get(config.CONFIG_OVERLAY_ENV)
    if operator_overlay:
        from pathlib import Path

        sources.append(Path(operator_overlay).expanduser())
    for source in sources:
        loaded = config._load_config_file(source)
        if "research_execution" in loaded:
            value = loaded["research_execution"]
    return ResearchProfile.from_config(value)


def _candidate(files, entrypoint):
    if (
        type(files) is not dict
        or not 1 <= len(files) <= 64
        or type(entrypoint) is not str
        or any(type(k) is not str or type(v) is not str for k, v in files.items())
    ):
        raise ValueError("candidate must contain one to 64 named UTF-8 source files")
    if sum(len(k) + len(v) for k, v in files.items()) > _MAX_CANDIDATE:
        raise ValueError("candidate exceeds the 256 KiB submission limit")
    try:
        encoded = {name: value.encode("utf-8") for name, value in files.items()}
    except UnicodeError as exc:
        raise ValueError("candidate source must be valid UTF-8") from exc
    if sum(len(v) for v in encoded.values()) > _MAX_CANDIDATE:
        raise ValueError("candidate exceeds the 256 KiB submission limit")
    return _inputs(encoded, entrypoint)


def _empty_registry_binding():
    material = {"schema": _REGISTRY_BINDING_SCHEMA, "datasets": [], "model": None}
    return {**material, "binding_sha256": _digest(material)}


def _public(record):
    fields = (
        "id",
        "revision",
        "status",
        "created_at",
        "updated_at",
        "expires_at",
        "input_sha256",
        "evaluator_id",
        "entrypoint",
        "observation",
        "evaluation",
        "execution",
        "dispatched_by",
        "dispatch_review_sha256",
        "registry",
        "next_action",
    )
    return {name: record[name] for name in fields if name in record}


def _source_manifest(record):
    return [
        {
            "path": path,
            "bytes": len(source.encode("utf-8")),
            "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        }
        for path, source in sorted(record["files"].items())
    ]


def _review_material(record, authority):
    return {
        "schema": "lightwork.research-dispatch-review.v1",
        "job_id": record["id"],
        "revision": record["revision"],
        "tenant": record["tenant"],
        "submitted_by": record["principal"],
        "submitter_authority": record["authority"],
        "request_sha256": record["request_sha256"],
        "input_sha256": record["input_sha256"],
        "profile_sha256": record["profile_sha256"],
        "evaluator_sha256": record["evaluator_sha256"],
        "evaluator_id": record["evaluator_id"],
        "entrypoint": record["entrypoint"],
        "expires_at": record["expires_at"],
        "source_manifest": _source_manifest(record),
        "registry": record.get("registry", _empty_registry_binding()),
        "dispatcher_authority": asdict(authority),
    }


def _review_public(record, authority, *, include_source):
    result = _public(record)
    result.update(submitted_by=record["principal"], source_manifest=_source_manifest(record))
    if include_source:
        result["files"] = dict(record["files"])
        result["review_sha256"] = _digest(_review_material(record, authority))
    return result


class ResearchJobs:
    """CAS queue; claimed work is never automatically replayed after worker loss.

    ``run`` requires a separately resolved named administrator and a digest of
    the exact source review. Submitter authority never implies dispatch authority.
    """

    def __init__(
        self,
        *,
        authority_resolver: Callable[[str, str], ResearchAuthority],
        dispatch_authority_resolver: Callable[[str, str], ResearchDispatchAuthority],
        profile_resolver: Callable[[], ResearchProfile] = configured_profile,
        runner_factory=ResearchContainerRunner,
        record_store=None,
        effect_fence=None,
        registry: ResearchRegistry | None = None,
    ):
        from .authority_effects import authority_effect_fence

        self.authority_resolver = authority_resolver
        self.dispatch_authority_resolver = dispatch_authority_resolver
        self.profile_resolver = profile_resolver
        self.runner_factory = runner_factory
        self.registry = registry
        self.store = record_store or GovernedRecordStore(
            "research-jobs", "research", "research-job"
        )
        self.effect_fence = effect_fence or authority_effect_fence

    def _authority(self, tenant, principal):
        result = self.authority_resolver(tenant, principal)
        if type(result) is not ResearchAuthority or (result.tenant, result.principal) != (
            tenant,
            principal,
        ):
            raise PermissionError("research authority is unavailable")
        return result

    def _dispatch_authority(self, tenant, principal):
        result = self.dispatch_authority_resolver(tenant, principal)
        if type(result) is not ResearchDispatchAuthority or (result.tenant, result.principal) != (
            tenant,
            principal,
        ):
            raise PermissionError("research dispatch authority is unavailable")
        return result

    def _record(self, record_id):
        _identifier(record_id, "job ID")
        result = self.store.get(record_id)
        if result is None:
            raise ResearchNotFound("Research job was not found in this workspace")
        return result

    def _registry_binding(self, tenant, dataset_refs, model_ref):
        if isinstance(dataset_refs, str | bytes) or not isinstance(dataset_refs, (list, tuple)):
            raise ValueError("dataset_refs must be a bounded registry-reference list")
        references = tuple(dataset_refs)
        if len(references) > 32 or any(
            type(reference) is not ResearchAssetRef or reference.kind != "dataset"
            for reference in references
        ):
            raise ValueError("dataset_refs contains an invalid dataset registry reference")
        keys = [(item.asset_id, item.version, item.manifest_sha256) for item in references]
        if keys != sorted(set(keys)):
            raise ValueError("dataset_refs must be unique and sorted")
        if model_ref is not None and (
            type(model_ref) is not ResearchAssetRef or model_ref.kind != "model"
        ):
            raise ValueError("model_ref must be an exact model registry reference")
        if not references and model_ref is None:
            return _empty_registry_binding()
        if self.registry is None:
            raise ResearchUnavailable("Research datasets and models require the governed registry")
        datasets = [
            asdict(
                self.registry.resolve_dataset(
                    tenant, reference, purpose="research_evaluation", action="analyze"
                )
            )
            for reference in references
        ]
        model = (
            None
            if model_ref is None
            else asdict(
                self.registry.resolve_model(tenant, model_ref, purpose="research_evaluation")
            )
        )
        material = {"schema": _REGISTRY_BINDING_SCHEMA, "datasets": datasets, "model": model}
        return {**material, "binding_sha256": _digest(material)}

    def _fresh_registry(self, row):
        binding = row.get("registry", _empty_registry_binding())
        if not isinstance(binding, dict) or binding.get("schema") != _REGISTRY_BINDING_SCHEMA:
            raise ResearchConflict("research registry binding is unavailable")
        material = {key: value for key, value in binding.items() if key != "binding_sha256"}
        if set(binding) != {
            "schema",
            "datasets",
            "model",
            "binding_sha256",
        } or not hmac.compare_digest(str(binding.get("binding_sha256") or ""), _digest(material)):
            raise ResearchConflict("research registry binding digest does not match")
        datasets = binding.get("datasets")
        model = binding.get("model")
        if not isinstance(datasets, list) or len(datasets) > 32:
            raise ResearchConflict("research dataset bindings are malformed")
        try:
            dataset_refs = tuple(ResearchAssetRef(**item["reference"]) for item in datasets)
            model_ref = None if model is None else ResearchAssetRef(**model["reference"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ResearchConflict("research registry binding is malformed") from exc
        refreshed = self._registry_binding(row["tenant"], dataset_refs, model_ref)
        if refreshed != binding:
            raise ResearchConflict("research dataset or model authority changed")
        return refreshed

    def submit(
        self,
        tenant,
        principal,
        *,
        files,
        evaluator_id,
        idempotency_key,
        entrypoint="main.py",
        dataset_refs=(),
        model_ref=None,
    ):
        _identifier(idempotency_key, "idempotency key")
        _identifier(evaluator_id, "evaluator ID")
        candidate = _candidate(files, entrypoint)
        with tenant_scope(tenant=tenant):
            authority = self._authority(tenant, principal)
            profile = self.profile_resolver()
            evaluator = profile.evaluator(evaluator_id)
            registry = self._registry_binding(tenant, dataset_refs, model_ref)
            request = {"files": files, "entrypoint": entrypoint, "evaluator_id": evaluator_id}
            if registry["datasets"] or registry["model"] is not None:
                request["registry"] = registry
            record_id = "research-" + _digest([principal, idempotency_key])[:40]
            request_digest = _digest(request)
            prior = self.store.get(record_id)
            if prior:
                return self._replay(prior, principal, request_digest)
            row = {
                "id": record_id,
                "schema": "lightwork.research-job.v1",
                "tenant": tenant,
                "principal": principal,
                "authority": asdict(authority),
                "profile_sha256": _digest(asdict(profile)),
                "evaluator_sha256": _digest(asdict(evaluator)),
                "request_sha256": request_digest,
                "files": dict(files),
                "entrypoint": entrypoint,
                "evaluator_id": evaluator_id,
                "input_sha256": _input_digest(candidate),
                "registry": registry,
                "status": "queued",
                "expires_at": self.store.authoritative_time() + profile.queue_seconds,
                "next_action": "Await an installation administrator dispatching this queued job",
            }
            try:
                saved = self.store.create(
                    row, actor=principal, action="research.submit", max_records=256
                )
            except RecordConflict:
                return self._replay(self._record(record_id), principal, request_digest)
            return _public(saved)

    @staticmethod
    def _replay(prior, principal, request_digest):
        if prior["principal"] != principal or prior["request_sha256"] != request_digest:
            raise ResearchConflict("idempotency key belongs to a different research submission")
        return _public(prior)

    def get(self, tenant, principal, record_id):
        with tenant_scope(tenant=tenant):
            record = self._record(record_id)
            if record["tenant"] != tenant or record["principal"] != principal:
                raise ResearchNotFound("Research job was not found in this workspace")
            self._authority(tenant, principal)
            return _public(record)

    def list(self, tenant, principal):
        with tenant_scope(tenant=tenant):
            self._authority(tenant, principal)
            return [
                _public(row)
                for row in self.store.list(limit=256)
                if row["tenant"] == tenant and row["principal"] == principal
            ]

    def review(self, tenant, dispatcher, record_id):
        """Return exact source only to a currently authorized administrator."""
        with tenant_scope(tenant=tenant):
            authority = self._dispatch_authority(tenant, dispatcher)
            record = self._record(record_id)
            if record["tenant"] != tenant:
                raise ResearchNotFound("Research job was not found in this workspace")
            return _review_public(record, authority, include_source=True)

    def review_list(self, tenant, dispatcher):
        """Tenant administrator queue; source bodies require an individual review."""
        with tenant_scope(tenant=tenant):
            authority = self._dispatch_authority(tenant, dispatcher)
            return [
                _review_public(row, authority, include_source=False)
                for row in self.store.list(limit=256)
                if row["tenant"] == tenant
            ]

    def cancel(self, tenant, principal, record_id, *, expected_revision):
        with tenant_scope(tenant=tenant):
            self.get(tenant, principal, record_id)
            return self._cancel(record_id, expected_revision=expected_revision, actor=principal)

    def cancel_for_review(self, tenant, dispatcher, record_id, *, expected_revision):
        with tenant_scope(tenant=tenant):
            self._dispatch_authority(tenant, dispatcher)
            record = self._record(record_id)
            if record["tenant"] != tenant:
                raise ResearchNotFound("Research job was not found in this workspace")
            return self._cancel(record_id, expected_revision=expected_revision, actor=dispatcher)

    def _cancel(self, record_id, *, expected_revision, actor):
        def mutate(row):
            if row["status"] == "queued":
                row.update(status="cancelled", next_action="Submit a new job to run again")
            elif row["status"] == "running":
                row.update(
                    status="cancel_requested",
                    next_action="Wait for bounded container cleanup; evaluation is suppressed",
                )
            else:
                raise ResearchConflict("job is no longer cancellable")

        # Share the process-admission fence so a cancellation that commits
        # before the runner's guarded spawn is always observed before any
        # candidate process can start.
        with self.effect_fence():
            return _public(
                self.store.update(
                    record_id,
                    mutate,
                    expected_revision=expected_revision,
                    actor=actor,
                    action="research.cancel",
                )
            )

    def _fresh(self, row):
        current = self._record(row["id"])
        immutable = (
            "tenant",
            "principal",
            "authority",
            "profile_sha256",
            "evaluator_sha256",
            "request_sha256",
            "files",
            "entrypoint",
            "evaluator_id",
            "input_sha256",
            "registry",
            "expires_at",
        )
        if any(current.get(field) != row.get(field) for field in immutable):
            raise ResearchConflict("Research job source or authority binding changed")
        authority = self._authority(row["tenant"], row["principal"])
        profile = self.profile_resolver()
        candidate = _candidate(current["files"], current["entrypoint"])
        self._fresh_registry(current)
        if (
            row["authority"] != asdict(authority)
            or row["profile_sha256"] != _digest(asdict(profile))
            or row["input_sha256"] != _input_digest(candidate)
            or self.store.authoritative_time() >= row["expires_at"]
        ):
            raise ResearchConflict(
                "Research authority, source, evaluator or budget changed; submit a newly reviewed job"
            )
        return profile, candidate

    def _fresh_dispatch(self, row, dispatcher):
        current = self._dispatch_authority(row["tenant"], dispatcher)
        stored = self._record(row["id"])
        if (
            row.get("dispatch_authority") != asdict(current)
            or stored.get("dispatch_authority") != row.get("dispatch_authority")
            or stored.get("dispatched_by") != dispatcher
            or stored.get("dispatch_review_sha256") != row.get("dispatch_review_sha256")
        ):
            raise ResearchConflict(
                "Research dispatcher authority changed; a new review is required"
            )
        return current

    def _execution_event(self, record_id, actor, state, **fields):
        current = self._record(record_id)
        recorded_at = self.store.authoritative_time()

        def mutate(row):
            if row["status"] not in _ACTIVE:
                raise ResearchConflict("research claim is no longer active")
            execution = row.get("execution")
            if (
                not isinstance(execution, dict)
                or execution.get("schema") != "lightwork.research-execution.v1"
            ):
                raise ResearchConflict("research execution history is unavailable")
            events = execution.get("events")
            if not isinstance(events, list) or len(events) >= 16:
                raise ResearchConflict("research execution history is invalid")
            events.append({"state": state, "recorded_at": recorded_at, **fields})
            execution["state"] = state

        return self.store.update(
            record_id,
            mutate,
            expected_revision=current["revision"],
            actor=actor,
            action=f"research.execution.{state}",
        )

    @staticmethod
    def _safe_result(result):
        try:
            policy_json = json.dumps(
                result.inspect_policy, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise ResearchExecutionUncertain("execution returned invalid provenance") from exc
        if (
            type(result.container_name) is not str
            or not 1 <= len(result.container_name) <= 128
            or any(ord(char) < 32 for char in result.container_name)
            or type(result.image_id) is not str
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", result.image_id)
            or type(result.input_sha256) is not str
            or not _SHA.fullmatch(result.input_sha256)
            or type(result.policy_sha256) is not str
            or not _SHA.fullmatch(result.policy_sha256)
            or type(result.entrypoint) is not str
            or not 1 <= len(result.entrypoint) <= 200
            or type(result.exit_code) is not int
            or not -(2**31) <= result.exit_code < 2**31
            or type(result.reason) is not str
            or not 1 <= len(result.reason) <= 64
            or type(result.stdout) is not str
            or type(result.stderr) is not str
            or type(result.captured_bytes) is not int
            or not 0 <= result.captured_bytes <= 2 * 1024 * 1024
            or type(result.cleanup_verified) is not bool
            or type(result.inspect_policy) is not dict
            or len(policy_json.encode("utf-8")) > 64 * 1024
            or not hmac.compare_digest(
                result.policy_sha256, hashlib.sha256(policy_json.encode()).hexdigest()
            )
        ):
            raise ResearchExecutionUncertain("execution returned invalid provenance")
        return {
            "container": result.container_name,
            "image_id": result.image_id,
            "input_sha256": result.input_sha256,
            "policy_sha256": result.policy_sha256,
            "entrypoint": result.entrypoint,
            "exit_code": result.exit_code,
            "reason": result.reason,
            "captured_bytes": result.captured_bytes,
            "stdout_bytes": len(result.stdout.encode("utf-8")),
            "stderr_bytes": len(result.stderr.encode("utf-8")),
            "stdout_sha256": hashlib.sha256(result.stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr.encode("utf-8")).hexdigest(),
            "cleanup_verified": result.cleanup_verified,
            "inspect_policy": json.loads(policy_json),
        }

    @contextmanager
    def _effect_guard(self, row, dispatcher, budget):
        """Revalidate under the same fence held by app-owned authority mutators."""
        with self.effect_fence():
            self._fresh(row)
            self._fresh_dispatch(row, dispatcher)
            self._fresh_registry(row)
            budget.check()
            current = self._record(row["id"])
            if current["status"] != "running":
                raise ResearchConflict("research claim is no longer executable")
            yield

    def _finish(self, record_id, *, status, next_action, actor=None, **fields):
        current = self._record(record_id)
        finish_actor = actor or current.get("dispatched_by")
        if type(finish_actor) is not str or not finish_actor.startswith("user:"):
            raise ResearchConflict("named research dispatcher is unavailable")

        def mutate(row):
            if row["status"] not in _ACTIVE:
                raise ResearchConflict("research claim is no longer active")
            # Cancellation wins only after a known-safe controller outcome.
            # If provenance or cleanup is uncertain, preserve that stronger
            # terminal state so the app cannot invite an unsafe retry.
            if row["status"] == "cancel_requested" and status != "uncertain":
                row.update(status="cancelled", next_action="Submit a new job to run again")
            else:
                row.update(status=status, next_action=next_action, **fields)

        return _public(
            self.store.update(
                record_id,
                mutate,
                expected_revision=current["revision"],
                actor=finish_actor,
                action="research.finish",
            )
        )

    def run(self, tenant, record_id, *, expected_revision, dispatcher, review_sha256):
        if type(review_sha256) is not str or not _SHA.fullmatch(review_sha256):
            raise ResearchConflict("exact source review is required")
        with tenant_scope(tenant=tenant), work_item_scope(f"research-job:{record_id}"):
            row = self._record(record_id)
            if row["tenant"] != tenant:
                raise ResearchNotFound("Research job was not found in this workspace")
            dispatch_authority = self._dispatch_authority(tenant, dispatcher)
            expected_review = _digest(_review_material(row, dispatch_authority))
            if not hmac.compare_digest(review_sha256, expected_review):
                raise ResearchConflict(
                    "research source or dispatcher authority changed; review the exact source again"
                )
            claimed_at = self.store.authoritative_time()

            def claim(current):
                if current["status"] != "queued":
                    raise ResearchConflict(
                        "only a queued research job can be dispatched; never replay uncertain work"
                    )
                current.update(
                    status="running",
                    dispatched_by=dispatcher,
                    dispatch_authority=asdict(dispatch_authority),
                    dispatch_review_sha256=review_sha256,
                    execution={
                        "schema": "lightwork.research-execution.v1",
                        "state": "claimed",
                        "attempt": 1,
                        "events": [
                            {
                                "state": "claimed",
                                "recorded_at": claimed_at,
                                "dispatcher": dispatcher,
                            }
                        ],
                    },
                    next_action="Wait for bounded execution; after worker loss, inspect container cleanup before submitting a new job",
                )

            row = self.store.update(
                record_id,
                claim,
                expected_revision=expected_revision,
                actor=dispatcher,
                action="research.claim",
            )
            # The claim is durable before any candidate effect. Process death leaves
            # it running and cannot cause a later worker to repeat the candidate.
            try:
                profile, files = self._fresh(row)
                self._fresh_dispatch(row, dispatcher)
                budget = Budget(
                    max_input_tokens=0,
                    max_output_tokens=0,
                    max_dollars=0,
                    max_wall_seconds=profile.limits.timeout_seconds + 45,
                    max_tool_calls=1,
                )
                budget.check()
                self._execution_event(
                    record_id,
                    dispatcher,
                    "execution_started",
                    image_id=profile.image_id,
                    input_sha256=row["input_sha256"],
                    entrypoint=row["entrypoint"],
                    profile_sha256=row["profile_sha256"],
                    evaluator_sha256=row["evaluator_sha256"],
                    registry_sha256=row.get("registry", _empty_registry_binding())[
                        "binding_sha256"
                    ],
                )
                runner = self.runner_factory(profile.image_id, limits=profile.limits)
                self._fresh(row)  # Docker setup can outlive an authority/profile change.
                self._fresh_dispatch(row, dispatcher)
                budget.check()
                if self._record(record_id)["status"] == "cancel_requested":
                    return self._finish(
                        record_id,
                        status="cancelled",
                        actor=dispatcher,
                        next_action="Submit a new job to run again",
                    )
                result = runner.run(
                    files,
                    budget=budget,
                    entrypoint=row["entrypoint"],
                    effect_guard=lambda: self._effect_guard(row, dispatcher, budget),
                )
                safe_result = self._safe_result(result)
                self._execution_event(record_id, dispatcher, "finished", **safe_result)
                if not result.cleanup_verified:
                    raise ResearchExecutionUncertain("container cleanup was not verified")
                self._fresh(row)
                self._fresh_dispatch(row, dispatcher)
                if (
                    result.image_id != profile.image_id
                    or result.input_sha256 != row["input_sha256"]
                    or result.entrypoint != row["entrypoint"]
                ):
                    raise ResearchConflict(
                        "execution provenance or cleanup does not match the submitted job"
                    )
                return self._evaluate(row, profile, result, dispatcher=dispatcher)
            except ResearchExecutionUncertain:
                return self._finish(
                    record_id,
                    status="uncertain",
                    actor=dispatcher,
                    next_action="Installation administrator must verify exact container and snapshot cleanup; this job will not run again",
                )
            except (
                PermissionError,
                ResearchConflict,
                ResearchRegistryError,
                ResearchUnavailable,
                ValueError,
            ):
                return self._finish(
                    record_id,
                    status="review_required",
                    actor=dispatcher,
                    next_action="Authority, source or controller settings changed; review and submit a new job",
                )
            except Exception:  # noqa: BLE001 - preserve uncertainty, never stringify candidate/controller secrets
                return self._finish(
                    record_id,
                    status="uncertain",
                    actor=dispatcher,
                    next_action="Installation administrator must verify container cleanup; this job will not run again",
                )

    def _evaluate(self, row, profile, result, *, dispatcher):
        evaluator = profile.evaluator(row["evaluator_id"])
        request = AuthenticatedTestRequest.issue(
            "research.exact-stdout.v1",
            subject_sha256=row["input_sha256"],
            execution_context_sha256=_digest(
                {
                    "job_id": row["id"],
                    "authority": row["authority"],
                    "profile": row["profile_sha256"],
                    "evaluator": row["evaluator_sha256"],
                    "registry": row.get("registry", _empty_registry_binding())["binding_sha256"],
                    "container": result.container_name,
                    "policy": result.policy_sha256,
                }
            ),
        )
        output_sha256 = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
        passed = (
            result.reason == "completed"
            and result.exit_code == 0
            and output_sha256 == evaluator.stdout_sha256
        )
        evidence = AuthenticatedTestEvidence.for_request(
            request,
            authority=f"research.exact-stdout:{evaluator.id}:{evaluator.version}:{row['evaluator_sha256']}",
            counts=AuthenticatedTestCounts(passed=int(passed), failed=int(not passed)),
        )
        # Publish only while holding the same fence as app-owned authority
        # mutations. A revocation cannot land between these final reads and the
        # trusted evidence record.
        with self.effect_fence():
            self._fresh(row)
            self._fresh_dispatch(row, dispatcher)
            return self._finish(
                row["id"],
                status="completed",
                actor=dispatcher,
                next_action="Review the controller-owned exact-output result",
                evaluation=asdict(evidence),
                observation={
                    "exit_code": result.exit_code,
                    "reason": result.reason,
                    "stdout_sha256": output_sha256,
                    "policy_sha256": result.policy_sha256,
                    "cleanup_verified": True,
                },
            )
