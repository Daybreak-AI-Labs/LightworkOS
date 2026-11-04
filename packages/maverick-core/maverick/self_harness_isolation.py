"""Protocol boundary for container-isolated evaluator candidate execution.

The controller in this module receives private tasks from a separately identified
final-set generator and owns the evaluator callable. A candidate sandbox receives
one canonical JSON payload containing only fields the registered observation
protocol permits. Arbitrary submitted Python executes only through
``ResearchContainerRunner``: a non-root, read-only Linux container with one
read-only candidate snapshot, bounded scratch/output/process resources, a fixed
credential-free environment, no Docker socket or host control path, and
``--network=none``. There is no host-execution fallback.

The container establishes candidate containment. It does not establish an
independent evaluator custodian: on Windows especially, the controller, final-set
storage, and Docker daemon remain under the same host account. Confirmatory
qualification must request externally administered custody and fail closed until
that deployment evidence exists.
"""
from __future__ import annotations

import json
import math
import re
import textwrap
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from .budget import Budget
from .sandbox.research import (
    ResearchContainerError,
    ResearchContainerRunner,
    ResearchLimits,
    _input_digest,
    _inputs,
)
from .self_harness_holdout import (
    AlphaBudget,
    BoundaryAttempt,
    EvaluationCost,
    EvaluationReceipt,
    HoldoutQuery,
    HoldoutQueryLedger,
    QueryPermit,
    fingerprint_manifest,
)

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_MAX_FIELDS = 256
_MAX_ATTEMPTS = 256
_MAX_PRIVATE_TASK_BYTES = 16 * 1024 * 1024
_BOOTSTRAP = "__lightwork_evaluator_bootstrap__.py"
_OBSERVATIONS = "__lightwork_candidate_observations__.json"
_CANDIDATE_ENTRYPOINT = "__lightwork_candidate_entrypoint__.py"
_RESULT_SCHEMA = "maverick-contained-candidate-result-v1"
_CONTAINER_BOUNDARY = "lightwork.research-linux-container-policy.v2"


class EvaluationIsolationError(RuntimeError):
    """A sealed evaluation could not prove its local isolation contract."""


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    )


def _detached(value: object, *, label: str, maximum: int) -> object:
    try:
        encoded = _canonical(value)
    except (RecursionError, TypeError, ValueError) as exc:
        raise EvaluationIsolationError(f"{label} is not canonical JSON") from exc
    if not 1 <= len(encoded.encode("utf-8")) <= maximum:
        raise EvaluationIsolationError(f"{label} exceeds its size bound")
    return json.loads(encoded)


def _field_names(values: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)) or len(values) > _MAX_FIELDS:
        raise ValueError(f"{label} must be a bounded sequence")
    fields = tuple(str(value or "").strip() for value in values)
    if (len(fields) != len(set(fields))
            or any(not _NAME.fullmatch(value) for value in fields)):
        raise ValueError(f"{label} contains an invalid or duplicate name")
    return fields


_CONTAINER_BOOTSTRAP = textwrap.dedent(
    r'''
    import builtins
    import contextlib
    import hashlib
    import io
    import json
    import os
    import runpy
    import socket
    import sys

    _attempts = []
    _seen = set()

    def _note(surface):
        if surface not in _seen and len(_attempts) < 256:
            _seen.add(surface)
            _attempts.append({"surface": surface})

    def _sensitive_name(value):
        upper = str(value).upper()
        return any(token in upper for token in (
            "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "PRIVATE_KEY"
        ))

    class _ObservedEnvironment(dict):
        def __getitem__(self, key):
            _note("credential" if _sensitive_name(key) else "environment")
            return super().__getitem__(key)

        def get(self, key, default=None):
            _note("credential" if _sensitive_name(key) else "environment")
            return super().get(key, default)

        def __contains__(self, key):
            _note("credential" if _sensitive_name(key) else "environment")
            return super().__contains__(key)

        def __iter__(self):
            _note("environment")
            return super().__iter__()

        def keys(self):
            _note("environment")
            return super().keys()

        def items(self):
            _note("environment")
            return super().items()

        def values(self):
            _note("environment")
            return super().values()

        def copy(self):
            _note("environment")
            return super().copy()

        def __len__(self):
            _note("environment")
            return super().__len__()

        def __repr__(self):
            _note("environment")
            return super().__repr__()

    _safe_environment = dict(os.environ)

    def _audit(event, args):
        if event == "open" and args:
            try:
                path = os.fspath(args[0])
            except TypeError:
                path = ""
            text = str(path)
            lowered = text.lower()
            mode = str(args[1]) if len(args) > 1 else "r"
            if lowered in {"/var/run/docker.sock", "/run/docker.sock"}:
                _note("control_path")
            elif lowered.startswith("/proc/") and lowered.endswith("/environ"):
                _note("credential")
            elif ("evaluator" in lowered or "final-set" in lowered
                  or "final_set" in lowered):
                _note("evaluator_storage")
            elif (text.startswith("/candidate/")
                  and any(flag in mode for flag in ("w", "a", "x", "+"))):
                _note("filesystem")
            elif ((text.startswith("/") and not text.startswith((
                    "/candidate/", "/scratch/", "/usr/local/lib/python",
                    "/usr/lib/python", "/etc/ld.so", "/dev/null")))
                  or ":\\" in text):
                _note("filesystem")
        elif event in {
                "os.chdir", "os.chroot", "os.listdir", "os.scandir",
                "os.truncate", "os.walk"}:
            _note("filesystem")
        elif event.startswith("socket."):
            # Network namespaces enforce the boundary.  Record every socket
            # probe, including loopback and socket construction, because a
            # denied attempt is still material evaluator-boundary evidence.
            _note("network")
        elif event in {"os.exec", "os.posix_spawn", "os.spawn", "os.system",
                       "subprocess.Popen"}:
            _note("control_path")

    sys.addaudithook(_audit)
    os.environ = _ObservedEnvironment(_safe_environment)
    sys.path.insert(0, "/candidate")

    def _emit(status, output=None, artifacts=None):
        material = {
            "schema": "maverick-contained-candidate-result-v1",
            "status": status,
            "output": output,
            "artifact_exports": artifacts or {},
            "boundary_attempts": list(_attempts),
        }
        print(json.dumps(material, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False))

    try:
        with builtins.open(
                "/candidate/__lightwork_candidate_observations__.json",
                encoding="utf-8") as stream:
            payload = json.load(stream)
        namespace = runpy.run_path(
            "/candidate/__lightwork_candidate_entrypoint__.py",
            run_name="__lightwork_candidate__")
        candidate = namespace.get("evaluate")
        if not callable(candidate):
            raise TypeError("candidate must define evaluate(observations)")
        candidate_stdout = io.StringIO()
        candidate_stderr = io.StringIO()
        with contextlib.redirect_stdout(candidate_stdout), contextlib.redirect_stderr(
                candidate_stderr):
            raw = candidate(payload["observations"])
        if isinstance(raw, dict) and set(raw).issubset({"output", "artifacts"}):
            output = raw.get("output")
            artifacts = raw.get("artifacts") or {}
        else:
            output, artifacts = raw, {}
        # Candidate console text never crosses the boundary. Hashes make
        # unexpected writes diagnosable without reflecting attacker text.
        artifacts = dict(artifacts)
        if candidate_stdout.getvalue():
            artifacts.setdefault(
                "candidate_stdout_sha256",
                hashlib.sha256(candidate_stdout.getvalue().encode()).hexdigest())
        if candidate_stderr.getvalue():
            artifacts.setdefault(
                "candidate_stderr_sha256",
                hashlib.sha256(candidate_stderr.getvalue().encode()).hexdigest())
        _emit("ok", output=output, artifacts=artifacts)
    except BaseException:
        _note("error_message")
        _emit("candidate_error")
    '''
).strip().encode("utf-8")


@dataclass(frozen=True)
class ObservationProtocol:
    """Registered fields that make one private task observable and solvable."""

    protocol_id: str
    allowed_fields: tuple[str, ...]
    required_for_solution: tuple[str, ...]
    allowed_artifact_exports: tuple[str, ...] = ()
    max_input_bytes: int = 65_536
    max_output_bytes: int = 65_536
    timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        protocol_id = str(self.protocol_id or "").strip()
        if not _NAME.fullmatch(protocol_id):
            raise ValueError("protocol_id is invalid")
        allowed = _field_names(self.allowed_fields, label="allowed_fields")
        required = _field_names(
            self.required_for_solution, label="required_for_solution")
        exports = _field_names(
            self.allowed_artifact_exports, label="allowed_artifact_exports")
        if not required or not set(required).issubset(allowed):
            raise ValueError(
                "required_for_solution must be non-empty and permitted")
        for label, value in (
            ("max_input_bytes", self.max_input_bytes),
            ("max_output_bytes", self.max_output_bytes),
        ):
            if (isinstance(value, bool) or not isinstance(value, int)
                    or not 1 <= value <= 16 * 1024 * 1024):
                raise ValueError(f"{label} must be in [1, 16777216]")
        timeout = self.timeout_seconds
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(float(timeout))
                or not 0 < float(timeout) <= 86_400):
            raise ValueError("timeout_seconds must be finite and in (0, 86400]")
        object.__setattr__(self, "protocol_id", protocol_id)
        object.__setattr__(self, "allowed_fields", allowed)
        object.__setattr__(self, "required_for_solution", required)
        object.__setattr__(self, "allowed_artifact_exports", exports)

    @property
    def sha256(self) -> str:
        return fingerprint_manifest({
            "schema": "maverick-sealed-observation-protocol-v1",
            "protocol_id": self.protocol_id,
            "allowed_fields": list(self.allowed_fields),
            "required_for_solution": list(self.required_for_solution),
            "allowed_artifact_exports": list(self.allowed_artifact_exports),
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
            "timeout_seconds": float(self.timeout_seconds),
        })

    def candidate_payload(self, private_task: Mapping[str, object]) -> bytes:
        """Return only permitted observations, detached from evaluator memory."""
        if not isinstance(private_task, Mapping):
            raise EvaluationIsolationError("private task must be an object")
        missing = [
            field for field in self.required_for_solution
            if field not in private_task or private_task[field] is None
        ]
        if missing:
            raise EvaluationIsolationError(
                "permitted observations are insufficient for the declared task")
        observations = {
            field: private_task[field]
            for field in self.allowed_fields
            if field in private_task
        }
        payload = {
            "schema": "maverick-candidate-observations-v1",
            "protocol_id": self.protocol_id,
            "protocol_sha256": self.sha256,
            "observations": observations,
        }
        detached = _detached(
            payload, label="candidate observation payload",
            maximum=self.max_input_bytes,
        )
        return _canonical(detached).encode("utf-8")


@dataclass(frozen=True)
class CandidateExecution:
    """Attested candidate-sandbox result returned to the evaluator controller."""

    output: object
    exit_code: int = 0
    artifact_exports: Mapping[str, object] = field(default_factory=dict)
    resource_cost: EvaluationCost = field(default_factory=EvaluationCost)
    boundary_sha256: str = ""


@dataclass(frozen=True)
class EvaluatorVerdict:
    """Private evaluator response; only ``accepted`` crosses the boundary."""

    accepted: bool
    private_response: object = None
    resource_cost: EvaluationCost = field(default_factory=EvaluationCost)


@dataclass
class ResearchContainerCandidate:
    """A submitted Python evaluator candidate with one enforced run path.

    Construction copies and validates all submitted bytes. ``run_candidate``
    always adds the trusted bootstrap and observation document and invokes the
    repository's concrete :class:`ResearchContainerRunner`; callers cannot
    provide a host runner or weaken its Docker policy.
    """

    candidate_identity: str
    image: str
    files: Mapping[str, bytes]
    entrypoint: str = "main.py"
    limits: ResearchLimits | None = None
    _submitted: dict[str, bytes] = field(init=False, repr=False)
    _source_sha256: str = field(init=False, repr=False)
    _attempts: tuple[BoundaryAttempt, ...] = field(
        init=False, repr=False, default=())

    def __post_init__(self) -> None:
        identity = str(self.candidate_identity or "").strip()
        if not _NAME.fullmatch(identity):
            raise ValueError("candidate_identity is invalid")
        if type(self.image) is not str or not self.image.strip():
            raise ValueError("a reviewed local container image is required")
        copied = _inputs(self.files, self.entrypoint)
        reserved = {
            _BOOTSTRAP.casefold(), _OBSERVATIONS.casefold(),
            _CANDIDATE_ENTRYPOINT.casefold(),
        }
        if any(name.casefold() in reserved for name in copied):
            raise ValueError("candidate files use a reserved evaluator path")
        if self.limits is not None and not isinstance(self.limits, ResearchLimits):
            raise ValueError("limits must be ResearchLimits")
        self.candidate_identity = identity
        self.image = self.image.strip()
        self._submitted = dict(copied)
        self._source_sha256 = _input_digest(self._submitted)

    @property
    def source_sha256(self) -> str:
        return self._source_sha256

    @property
    def planned_boundary_sha256(self) -> str:
        return fingerprint_manifest({
            "schema": "maverick-research-candidate-boundary-v1",
            "container_policy": _CONTAINER_BOUNDARY,
            "candidate_identity": self.candidate_identity,
            "requested_image": self.image,
            "source_sha256": self.source_sha256,
        })

    def read_boundary_attempts(self) -> tuple[BoundaryAttempt, ...]:
        return self._attempts

    def _run_files(self, payload: bytes) -> dict[str, bytes]:
        if _input_digest(self._submitted) != self.source_sha256:
            raise EvaluationIsolationError(
                "candidate source changed after admission")
        files = {
            name: data for name, data in self._submitted.items()
            if name != self.entrypoint
        }
        files[_CANDIDATE_ENTRYPOINT] = self._submitted[self.entrypoint]
        files[_BOOTSTRAP] = _CONTAINER_BOOTSTRAP
        files[_OBSERVATIONS] = payload
        return _inputs(files, _BOOTSTRAP)

    @staticmethod
    def _verified_policy(result: object, expected_input: str) -> str:
        """Verify the runner's post-create evidence again at the broker edge."""
        try:
            policy = result.inspect_policy
            mounts = policy["mounts"]
            command = policy["command"]
            safe = (
                result.cleanup_verified is True
                and result.reason == "completed"
                and result.exit_code == 0
                and result.entrypoint == _BOOTSTRAP
                and result.input_sha256 == expected_input
                and re.fullmatch(r"sha256:[0-9a-f]{64}", result.image_id)
                and policy["schema"] == _CONTAINER_BOUNDARY
                and policy["image_id"] == result.image_id
                and policy["user"] == "65532:65532"
                and policy["network"] == "none"
                and policy["readonly_root"] is True
                and mounts == [{
                    "destination": "/candidate", "type": "bind", "rw": False,
                }]
                and policy["cap_drop"] == ["ALL"]
                and "no-new-privileges" in policy["security_opt"]
                and command[-1] == f"/candidate/{_BOOTSTRAP}"
                and result.policy_sha256 == fingerprint_manifest(policy)
            )
        except (AttributeError, KeyError, IndexError, TypeError):
            safe = False
        if not safe:
            raise EvaluationIsolationError(
                "container result does not prove the strict research policy")
        return fingerprint_manifest({
            "schema": "maverick-research-candidate-execution-v1",
            "container_policy_sha256": result.policy_sha256,
            "image_id": result.image_id,
            "input_sha256": result.input_sha256,
        })

    def run_candidate(
        self, payload: bytes, *, environment: Mapping[str, str], timeout: float,
    ) -> CandidateExecution:
        """Execute submitted code in the strict Linux Docker boundary."""
        if environment:
            raise EvaluationIsolationError(
                "candidate environment must remain fixed and credential-free")
        if type(payload) is not bytes:
            raise EvaluationIsolationError("candidate payload must be bytes")
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(float(timeout)) or float(timeout) <= 0):
            raise EvaluationIsolationError("candidate timeout is invalid")
        base = self.limits or ResearchLimits()
        limits = ResearchLimits(
            timeout_seconds=min(float(timeout), base.timeout_seconds),
            output_bytes=base.output_bytes,
            memory_bytes=base.memory_bytes,
            scratch_bytes=base.scratch_bytes,
            pids=base.pids,
            cpus=base.cpus,
        )
        files = self._run_files(payload)
        budget = Budget(
            max_input_tokens=0,
            max_output_tokens=0,
            max_dollars=0.0,
            max_wall_seconds=max(60.0, limits.timeout_seconds + 45.0),
            max_tool_calls=1,
        )
        runner = ResearchContainerRunner(self.image, limits=limits)
        try:
            result = runner.run(files, budget=budget, entrypoint=_BOOTSTRAP)
        except ResearchContainerError as exc:
            self._attempts = (
                BoundaryAttempt("error_message", "container-boundary-failed"),
            )
            raise EvaluationIsolationError(
                "candidate container boundary failed closed") from exc
        boundary_sha256 = self._verified_policy(result, _input_digest(files))
        try:
            parsed = json.loads(result.stdout)
            if (not isinstance(parsed, dict)
                    or set(parsed) != {
                        "schema", "status", "output", "artifact_exports",
                        "boundary_attempts",
                    }
                    or parsed["schema"] != _RESULT_SCHEMA
                    or parsed["status"] not in {"ok", "candidate_error"}
                    or not isinstance(parsed["artifact_exports"], dict)
                    or not isinstance(parsed["boundary_attempts"], list)
                    or len(parsed["boundary_attempts"]) > _MAX_ATTEMPTS):
                raise ValueError("invalid contained result")
            attempts = tuple(
                BoundaryAttempt(str(item["surface"]))
                for item in parsed["boundary_attempts"]
                if isinstance(item, dict) and set(item) == {"surface"}
            )
            if len(attempts) != len(parsed["boundary_attempts"]):
                raise ValueError("invalid contained boundary attempts")
            for attempt in attempts:
                attempt.event_fields()
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._attempts = (
                BoundaryAttempt("error_message", "invalid-container-output"),
            )
            raise EvaluationIsolationError(
                "candidate container returned an invalid result envelope") from exc
        self._attempts = attempts
        elapsed = result.inspect_policy.get("elapsed_seconds", 0.0)
        try:
            compute_millis = max(0, math.ceil(float(elapsed) * 1000))
            cost = EvaluationCost(compute_millis=compute_millis)
        except (TypeError, ValueError, OverflowError) as exc:
            raise EvaluationIsolationError(
                "candidate container returned invalid compute accounting") from exc
        return CandidateExecution(
            output=parsed["output"],
            exit_code=0 if parsed["status"] == "ok" else 1,
            artifact_exports=parsed["artifact_exports"],
            resource_cost=cost,
            boundary_sha256=boundary_sha256,
        )


@dataclass(frozen=True)
class PublicArtifact:
    name: str
    value: object
    sha256: str


@dataclass(frozen=True)
class IsolatedEvaluationResult:
    status: str
    accepted: bool | None
    artifacts: tuple[PublicArtifact, ...]
    boundary_sha256: str
    receipt: EvaluationReceipt


def isolation_problems(
    sandbox: object, *, evaluator_identity: str,
    final_set_generator_identity: str,
) -> list[str]:
    """Require the concrete, non-configurable container candidate type."""
    problems: list[str] = []
    if type(sandbox) is not ResearchContainerCandidate:
        return [
            "requires the concrete ResearchContainerCandidate boundary; "
            "candidate self-attestation is not accepted"
        ]
    candidate_identity = str(
        getattr(sandbox, "candidate_identity", "") or "").strip()
    reserved_identities = {
        evaluator_identity.casefold(), final_set_generator_identity.casefold(),
    }
    if not candidate_identity or candidate_identity.casefold() in reserved_identities:
        problems.append("requires a separate candidate process identity")
    return problems


def _read_attempts(
    sandbox: ResearchContainerCandidate,
) -> tuple[list[BoundaryAttempt], bool]:
    try:
        reported = sandbox.read_boundary_attempts()
        if (not isinstance(reported, (tuple, list))
                or len(reported) > _MAX_ATTEMPTS
                or any(not isinstance(value, BoundaryAttempt) for value in reported)):
            raise EvaluationIsolationError(
                "candidate boundary attempt readback is invalid")
        return list(reported), False
    except BaseException:
        return [BoundaryAttempt("error_message", "audit-unavailable")], True


def _collect_artifacts(
    execution: CandidateExecution,
    protocol: ObservationProtocol,
    attempts: list[BoundaryAttempt],
) -> tuple[PublicArtifact, ...]:
    try:
        exports = dict(execution.artifact_exports)
    except (TypeError, ValueError):
        exports = {}
        attempts.append(BoundaryAttempt("artifact_export", "invalid-exports"))
    allowed_exports = set(protocol.allowed_artifact_exports)
    public: list[PublicArtifact] = []
    for raw_name, raw_value in sorted(exports.items(), key=lambda item: str(item[0])):
        name = str(raw_name or "").strip()
        if name not in allowed_exports:
            attempts.append(BoundaryAttempt("artifact_export", name))
            continue
        try:
            value = _detached(
                raw_value, label="candidate artifact",
                maximum=protocol.max_output_bytes)
        except EvaluationIsolationError:
            attempts.append(BoundaryAttempt("artifact_export", name))
            continue
        public.append(PublicArtifact(
            name=name, value=value, sha256=fingerprint_manifest(value)))
    del attempts[_MAX_ATTEMPTS:]
    return tuple(public)


@dataclass
class IsolatedEvaluator:
    """Evaluator-side broker that never hands private state to candidate code."""

    ledger: HoldoutQueryLedger
    policy: AlphaBudget
    evaluator_identity: str
    final_set_generator_identity: str
    evaluator_epoch: str | None = None
    require_independent_custody: bool = False

    def __post_init__(self) -> None:
        identity = str(self.evaluator_identity or "").strip()
        if not _NAME.fullmatch(identity):
            raise ValueError("evaluator_identity is invalid")
        if not isinstance(self.ledger, HoldoutQueryLedger):
            raise ValueError("ledger must be a HoldoutQueryLedger")
        if not isinstance(self.policy, AlphaBudget):
            raise ValueError("policy must be an AlphaBudget")
        generator_identity = str(
            self.final_set_generator_identity or "").strip()
        if (not _NAME.fullmatch(generator_identity)
                or generator_identity.casefold() == identity.casefold()):
            raise ValueError(
                "final_set_generator_identity must be separate and valid")
        epoch = str(self.evaluator_epoch or identity).strip()
        if not _NAME.fullmatch(epoch):
            raise ValueError("evaluator_epoch is invalid")
        if not isinstance(self.require_independent_custody, bool):
            raise ValueError("require_independent_custody must be boolean")
        if self.require_independent_custody:
            self.ledger.require_independent_custody()
        self.evaluator_identity = identity
        self.final_set_generator_identity = generator_identity
        self.evaluator_epoch = epoch

    def evaluate(
        self,
        *,
        query: HoldoutQuery,
        private_task: Mapping[str, object],
        protocol: ObservationProtocol,
        sandbox: ResearchContainerCandidate,
        evaluator: Callable[[Mapping[str, object], object], EvaluatorVerdict],
        work_item_id: str | None = None,
        permit: QueryPermit | None = None,
    ) -> IsolatedEvaluationResult:
        """Run one candidate, evaluate privately, retire, and return a receipt.

        Nested provider calls share one stable work-item binding.  A production
        caller can supply its authoritative work item; the local default is
        deterministic for the query cycle and contains no private task data.
        """
        if not isinstance(query, HoldoutQuery):
            raise ValueError("query must be a HoldoutQuery")
        if not isinstance(protocol, ObservationProtocol):
            raise ValueError("protocol must be an ObservationProtocol")
        if query.evaluator_epoch != self.evaluator_epoch:
            raise EvaluationIsolationError(
                "query is not bound to this evaluator epoch")
        if not isinstance(private_task, Mapping):
            raise EvaluationIsolationError("private task must be an object")
        problems = isolation_problems(
            sandbox, evaluator_identity=self.evaluator_identity,
            final_set_generator_identity=self.final_set_generator_identity)
        if problems:
            raise EvaluationIsolationError(
                "candidate evaluator isolation is not ready: " + "; ".join(problems))
        boundary_sha256 = fingerprint_manifest({
            "schema": "maverick-sealed-evaluator-boundary-v1",
            "candidate_boundary_sha256": sandbox.planned_boundary_sha256,
            "evaluator_identity": self.evaluator_identity,
            "evaluator_epoch": self.evaluator_epoch,
            "final_set_generator_identity": self.final_set_generator_identity,
        })
        try:
            private_snapshot = _detached(
                dict(private_task), label="private evaluator task",
                maximum=_MAX_PRIVATE_TASK_BYTES,
            )
        except (TypeError, ValueError) as exc:
            raise EvaluationIsolationError("private task must be an object") from exc
        if not isinstance(private_snapshot, dict):  # canonical dict round-trip
            raise EvaluationIsolationError("private task must be an object")
        expected_final_set = fingerprint_manifest(private_snapshot)
        if query.final_set_sha256 != expected_final_set:
            raise EvaluationIsolationError(
                "query is not bound to the exact private final set")
        if query.protocol_sha256 != protocol.sha256:
            raise EvaluationIsolationError(
                "query is not bound to the observation protocol")
        receipt_context = {
            "boundary_sha256": boundary_sha256,
            "final_set_sha256": expected_final_set,
            "protocol_sha256": protocol.sha256,
        }
        payload = protocol.candidate_payload(private_snapshot)
        provider_work_item = (
            work_item_id
            if work_item_id is not None
            else f"self-harness-evaluation:{query.cycle_id}"
        )
        from .provider_cost_cap import provider_operation_scope, work_item_scope

        # Validate caller-supplied attribution before consuming scarce final-set
        # access. Entering and leaving an empty scope has no durable side effect.
        with work_item_scope(provider_work_item):
            pass
        if permit is None:
            permit = self.ledger.authorize(query, self.policy)
        elif (not isinstance(permit, QueryPermit)
              or permit.query_id != query.query_id
              or permit.holdout_sha256 != query.holdout_sha256
              or permit.final_set_sha256 != query.final_set_sha256
              or permit.protocol_sha256 != query.protocol_sha256):
            raise EvaluationIsolationError(
                "supplied permit is not bound to this exact final query")
        # The two-phase production runner carries permits across the scorer.
        # Revalidate the complete durable identity before candidate execution;
        # finalization repeats the check transactionally.
        self.ledger.validate_permit(permit)
        operation_digest = fingerprint_manifest({
            "schema": "maverick-sealed-provider-operation-v1",
            "ledger_id": permit.ledger_id,
            "query_id": query.query_id,
            "boundary_sha256": boundary_sha256,
        })

        execution = None
        execution_failed = False
        try:
            with provider_operation_scope(
                operation_id=f"self-harness.candidate:{operation_digest}",
                category="generation", service="sealed-candidate",
                work_item_id=provider_work_item,
            ):
                execution = sandbox.run_candidate(
                    payload, environment={}, timeout=float(protocol.timeout_seconds))
        except BaseException:
            execution_failed = True
        attempts, audit_failed = _read_attempts(sandbox)
        execution_failed = execution_failed or audit_failed
        if execution_failed or not isinstance(execution, CandidateExecution):
            receipt = self.ledger.finalize_evaluation(
                permit, outcome="candidate_error",
                public_result={"status": "candidate_error", **receipt_context},
                denied_attempts=tuple(attempts),
                actual_cost=permit.declared_cost)
            return IsolatedEvaluationResult(
                status="candidate_error", accepted=None, artifacts=(),
                boundary_sha256=boundary_sha256, receipt=receipt)

        if (not isinstance(execution.resource_cost, EvaluationCost)
                or not isinstance(execution.boundary_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", execution.boundary_sha256)):
            attempts.append(BoundaryAttempt("error_message", "invalid-accounting"))
            receipt = self.ledger.finalize_evaluation(
                permit, outcome="candidate_error",
                public_result={"status": "candidate_error", **receipt_context},
                denied_attempts=tuple(attempts[:_MAX_ATTEMPTS]),
                actual_cost=permit.declared_cost)
            return IsolatedEvaluationResult(
                status="candidate_error", accepted=None, artifacts=(),
                boundary_sha256=boundary_sha256, receipt=receipt)
        boundary_sha256 = fingerprint_manifest({
            "schema": "maverick-sealed-evaluator-boundary-v2",
            "planned_boundary_sha256": boundary_sha256,
            "execution_boundary_sha256": execution.boundary_sha256,
        })
        receipt_context["boundary_sha256"] = boundary_sha256

        output: object
        try:
            output = _detached(
                execution.output, label="candidate output",
                maximum=protocol.max_output_bytes)
        except EvaluationIsolationError:
            attempts.append(BoundaryAttempt("error_message", "invalid-output"))
            receipt = self.ledger.finalize_evaluation(
                permit, outcome="candidate_error",
                public_result={"status": "candidate_error", **receipt_context},
                denied_attempts=tuple(attempts[:_MAX_ATTEMPTS]),
                actual_cost=execution.resource_cost)
            return IsolatedEvaluationResult(
                status="candidate_error", accepted=None, artifacts=(),
                boundary_sha256=boundary_sha256, receipt=receipt)

        public_artifacts = _collect_artifacts(execution, protocol, attempts)
        if (isinstance(execution.exit_code, bool)
                or not isinstance(execution.exit_code, int)
                or execution.exit_code != 0):
            receipt = self.ledger.finalize_evaluation(
                permit, outcome="candidate_error",
                public_result={"status": "candidate_error", **receipt_context},
                denied_attempts=tuple(attempts),
                actual_cost=execution.resource_cost)
            return IsolatedEvaluationResult(
                status="candidate_error", accepted=None, artifacts=(),
                boundary_sha256=boundary_sha256, receipt=receipt)

        try:
            with provider_operation_scope(
                operation_id=f"self-harness.evaluator:{operation_digest}",
                category="evaluation", service="sealed-evaluator",
                work_item_id=provider_work_item,
            ):
                verdict = evaluator(private_snapshot, output)
            if (not isinstance(verdict, EvaluatorVerdict)
                    or not isinstance(verdict.accepted, bool)):
                raise EvaluationIsolationError("evaluator verdict is invalid")
        except BaseException:
            receipt = self.ledger.finalize_evaluation(
                permit, outcome="evaluator_error",
                public_result={"status": "evaluator_error", **receipt_context},
                denied_attempts=tuple(attempts),
                actual_cost=permit.declared_cost)
            return IsolatedEvaluationResult(
                status="evaluator_error", accepted=None, artifacts=(),
                boundary_sha256=boundary_sha256, receipt=receipt)

        if not isinstance(verdict.resource_cost, EvaluationCost):
            receipt = self.ledger.finalize_evaluation(
                permit, outcome="evaluator_error",
                public_result={"status": "evaluator_error", **receipt_context},
                denied_attempts=tuple(attempts),
                actual_cost=permit.declared_cost)
            return IsolatedEvaluationResult(
                status="evaluator_error", accepted=None, artifacts=(),
                boundary_sha256=boundary_sha256, receipt=receipt)
        actual_cost = execution.resource_cost.plus(verdict.resource_cost)
        status = "accepted" if verdict.accepted else "rejected"
        public_result = {
            "accepted": verdict.accepted,
            "artifact_sha256": {
                artifact.name: artifact.sha256 for artifact in public_artifacts
            },
            "status": status,
            **receipt_context,
        }
        receipt = self.ledger.finalize_evaluation(
            permit, outcome=status, public_result=public_result,
            denied_attempts=tuple(attempts), actual_cost=actual_cost)
        return IsolatedEvaluationResult(
            status=status, accepted=verdict.accepted,
            artifacts=public_artifacts, boundary_sha256=boundary_sha256,
            receipt=receipt)


__all__ = [
    "CandidateExecution", "EvaluationIsolationError", "EvaluatorVerdict",
    "IsolatedEvaluationResult", "IsolatedEvaluator", "ObservationProtocol",
    "PublicArtifact", "ResearchContainerCandidate", "isolation_problems",
]
