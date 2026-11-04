"""Local, tenant-bound guardrails for transient AI runtime content.

This module is deliberately default-off behind
``[ai_runtime_guardrails] enable = true``.  It composes the local Shield,
secret and PII redactors, and the current operational-policy preview without
writing prompts, outputs, action arguments, or detector payloads anywhere.

The public receipt is closed to non-content metadata and exact digests.  Raw
content exists only in the caller-owned request and the evaluation call frame;
the service is stateless and has no record store or network client.  This is a
local runtime enforcement primitive, not evidence of OneTrust or any other
third-party acceptance, certification, or live integration.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

RECEIPT_SCHEMA = "lightwork.ai-runtime-guardrail-receipt.v1"
MAX_BODY_BYTES = 64 * 1024
MAX_POLICY_ITEMS = 64
MAX_POLICY_PREVIEW_BYTES = 256 * 1024
_MAX_DYNAMIC_RISK_VALIDITY_SECONDS = 366 * 24 * 60 * 60
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

_ASSET_RE = re.compile(r"MAA-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")
_RULE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}\Z")

_DECISION_RANK = {
    "allow": 0,
    "redact": 1,
    "review": 2,
    "restrict": 3,
    "block": 4,
}
_POLICY_EFFECT = {
    "allow": "allow",
    "review": "review",
    "restrict": "restrict",
    "prohibit": "block",
}
_DYNAMIC_RISK_SEVERITY = {
    "allow": 0.0,
    "redact": 35.0,
    "review": 55.0,
    "restrict": 75.0,
    "block": 100.0,
}
_DYNAMIC_RISK_CATEGORIES = frozenset(
    {"quality", "safety", "performance", "privacy", "security"}
)
_POLICY_RISK_TIERS = frozenset({"unclassified", "low", "medium", "high", "critical"})
_POLICY_CONTEXT_FIELDS = frozenset({
    "asset_id",
    "risk_tier",
    "jurisdictions",
    "data_classes",
    "deployment_types",
    "asset_types",
    "tags",
    "use_case_tags",
})


class RuntimeGuardrailsError(RuntimeError):
    """Base error whose messages never contain evaluated content."""


class RuntimeGuardrailsConfigError(RuntimeGuardrailsError):
    """The explicit runtime-guardrail gate is disabled or unreadable."""


class RuntimeGuardrailsTenantError(RuntimeGuardrailsError):
    """No explicit tenant authority is available for the evaluation."""


class RuntimeGuardrailsInputError(RuntimeGuardrailsError, ValueError):
    """A runtime request is malformed or exceeds a closed input bound."""


class RuntimeStage(str, Enum):
    PROMPT = "prompt"
    OUTPUT = "output"
    ACTION = "action"


class RuntimeDecision(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    REVIEW = "review"
    RESTRICT = "restrict"
    BLOCK = "block"


@dataclass(frozen=True)
class RuntimeAssetBinding:
    """Exact current Model Risk asset revision evaluated at runtime."""

    asset_id: str
    asset_revision: int
    asset_version_digest: str


@dataclass(frozen=True)
class RuntimePolicyContext:
    """Bounded operational-policy facts; raw runtime content is excluded."""

    risk_tier: str = "unclassified"
    jurisdictions: tuple[str, ...] = ()
    data_classes: tuple[str, ...] = ()
    deployment_types: tuple[str, ...] = ()
    asset_types: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    use_case_tags: tuple[str, ...] = ()

    def as_mapping(self, asset_id: str) -> dict[str, object]:
        return {
            "asset_id": asset_id,
            "risk_tier": self.risk_tier,
            "jurisdictions": list(self.jurisdictions),
            "data_classes": list(self.data_classes),
            "deployment_types": list(self.deployment_types),
            "asset_types": list(self.asset_types),
            "tags": list(self.tags),
            "use_case_tags": list(self.use_case_tags),
        }


@dataclass(frozen=True)
class RuntimeGuardrailInput:
    """One transient prompt, output, or action evaluation.

    Sensitive fields are excluded from ``repr`` to reduce accidental logging.
    The evaluator never attaches this object to service state.
    """

    stage: RuntimeStage | str
    content: str = field(repr=False)
    asset: RuntimeAssetBinding
    policy_context: RuntimePolicyContext | Mapping[str, Any] | None = None
    action_name: str | None = None
    action_arguments: Mapping[str, Any] | None = field(default=None, repr=False)
    known_prompt: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class RuntimeGuardrailResult:
    """Safe decision plus an optional redacted replacement body."""

    decision: str
    receipt: dict[str, Any]
    redacted_content: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _Finding:
    decision: str
    categories: tuple[str, ...]
    rule_ids: tuple[str, ...]
    control_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class _PreparedRequest:
    stage: str
    content: str = field(repr=False)
    body: str = field(repr=False)
    body_bytes: bytes = field(repr=False)
    binding: dict[str, object]
    policy_context: dict[str, object]
    action_name: str | None = None
    action_arguments: dict[str, Any] | None = field(default=None, repr=False)
    known_prompt: str | None = field(default=None, repr=False)


def _canonical(value: object, *, label: str = "value") -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RuntimeGuardrailsInputError(
            f"{label} must be finite JSON-compatible data"
        ) from exc


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object) -> str:
    return _sha256_bytes(_canonical(value))


def _bounded_text(value: object, label: str) -> tuple[str, bytes]:
    if not isinstance(value, str):
        raise RuntimeGuardrailsInputError(f"{label} must be text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise RuntimeGuardrailsInputError(f"{label} is not valid UTF-8 text") from exc
    if len(encoded) > MAX_BODY_BYTES:
        raise RuntimeGuardrailsInputError(
            f"{label} exceeds the {MAX_BODY_BYTES}-byte limit"
        )
    return value, encoded


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise RuntimeGuardrailsInputError(f"{label} must be a bounded identifier")
    return value


def _rule_token(value: object, label: str) -> str:
    if not isinstance(value, str) or not _RULE_TOKEN_RE.fullmatch(value):
        raise RuntimeGuardrailsInputError(f"{label} must be a bounded identifier")
    return value


def _stage(value: RuntimeStage | str) -> str:
    raw = value.value if isinstance(value, RuntimeStage) else value
    try:
        return RuntimeStage(raw).value
    except (TypeError, ValueError) as exc:
        raise RuntimeGuardrailsInputError(
            "stage must be one of: action, output, prompt"
        ) from exc


def _binding(value: RuntimeAssetBinding) -> dict[str, object]:
    if not isinstance(value, RuntimeAssetBinding):
        raise RuntimeGuardrailsInputError(
            "asset must be a RuntimeAssetBinding"
        )
    if not isinstance(value.asset_id, str) or not _ASSET_RE.fullmatch(value.asset_id):
        raise RuntimeGuardrailsInputError(
            "asset_id must be an exact Model Risk asset id"
        )
    if (
        isinstance(value.asset_revision, bool)
        or not isinstance(value.asset_revision, int)
        or value.asset_revision <= 0
    ):
        raise RuntimeGuardrailsInputError("asset_revision must be a positive integer")
    digest = value.asset_version_digest
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise RuntimeGuardrailsInputError(
            "asset_version_digest must be a SHA-256 digest"
        )
    return {
        "asset_id": value.asset_id,
        "asset_revision": value.asset_revision,
        "asset_version_digest": digest.lower().removeprefix("sha256:"),
    }


def _feature_flags() -> tuple[bool, bool]:
    """Read both gates from one trusted configuration snapshot."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            raise RuntimeGuardrailsConfigError(
                "runtime AI guardrail configuration is unreadable"
            )
        config = load_config()
    except RuntimeGuardrailsConfigError:
        raise
    except Exception as exc:
        raise RuntimeGuardrailsConfigError(
            "runtime AI guardrail configuration is unavailable"
        ) from exc
    if not isinstance(config, Mapping):
        raise RuntimeGuardrailsConfigError(
            "runtime AI guardrail configuration is malformed"
        )
    runtime = config.get("ai_runtime_guardrails")
    policy = config.get("ai_policy_management")
    runtime_enabled = isinstance(runtime, Mapping) and runtime.get("enable") is True
    policy_enabled = isinstance(policy, Mapping) and policy.get("enable") is True
    return runtime_enabled, policy_enabled


def enabled() -> bool:
    """Return true only for an explicit, readable feature gate."""

    try:
        runtime_enabled, _ = _feature_flags()
    except RuntimeGuardrailsConfigError:
        return False
    return runtime_enabled


def require_enabled() -> None:
    runtime_enabled, _ = _feature_flags()
    if not runtime_enabled:
        raise RuntimeGuardrailsConfigError(
            "runtime AI guardrails are disabled; set "
            "[ai_runtime_guardrails] enable = true"
        )


def _tenant_ref() -> str:
    try:
        from .paths import current_tenant_id_strict

        tenant = current_tenant_id_strict()
    except Exception as exc:
        raise RuntimeGuardrailsTenantError(
            "runtime AI guardrails require an explicit tenant authority"
        ) from exc
    if not isinstance(tenant, str) or not tenant:
        raise RuntimeGuardrailsTenantError(
            "runtime AI guardrails require an explicit tenant authority"
        )
    return "TEN-" + hashlib.sha256(tenant.encode("utf-8")).hexdigest()[:24]


def _default_policy_context(asset_id: str) -> dict[str, object]:
    return RuntimePolicyContext().as_mapping(asset_id)


def _policy_context(
    value: RuntimePolicyContext | Mapping[str, Any] | None,
    asset_id: str,
) -> dict[str, object]:
    if value is None:
        raw: Mapping[str, Any] = _default_policy_context(asset_id)
    elif isinstance(value, RuntimePolicyContext):
        raw = value.as_mapping(asset_id)
    elif isinstance(value, Mapping):
        raw = value
    else:
        raise RuntimeGuardrailsInputError(
            "policy_context must be a RuntimePolicyContext or mapping"
        )
    unknown = sorted(set(raw) - _POLICY_CONTEXT_FIELDS)
    if unknown:
        raise RuntimeGuardrailsInputError(
            "policy_context contains unknown fields"
        )
    supplied_asset = raw.get("asset_id", asset_id)
    if supplied_asset != asset_id:
        raise RuntimeGuardrailsInputError(
            "policy_context asset_id does not match the exact asset binding"
        )
    risk_tier = raw.get("risk_tier", "unclassified")
    if not isinstance(risk_tier, str) or risk_tier.strip().lower() not in _POLICY_RISK_TIERS:
        raise RuntimeGuardrailsInputError("policy_context.risk_tier is unsupported")
    context: dict[str, object] = {
        "asset_id": asset_id,
        "risk_tier": risk_tier.strip().lower(),
    }
    for key in (
        "jurisdictions",
        "data_classes",
        "deployment_types",
        "asset_types",
        "tags",
        "use_case_tags",
    ):
        items = raw.get(key, ())
        if isinstance(items, (str, bytes)) or not isinstance(items, Sequence):
            raise RuntimeGuardrailsInputError(
                f"policy_context.{key} must be an array"
            )
        if len(items) > MAX_POLICY_ITEMS:
            raise RuntimeGuardrailsInputError(
                f"policy_context.{key} exceeds {MAX_POLICY_ITEMS} entries"
            )
        normalized: set[str] = set()
        for item in items:
            token = _rule_token(item, f"policy_context.{key}").lower()
            try:
                from .safety.secret_detector import scan as scan_secrets

                if scan_secrets(token):
                    raise RuntimeGuardrailsInputError(
                        f"policy_context.{key} contains secret material"
                    )
            except RuntimeGuardrailsInputError:
                raise
            except Exception as exc:
                raise RuntimeGuardrailsInputError(
                    f"policy_context.{key} could not be validated safely"
                ) from exc
            normalized.add(token)
        context[key] = sorted(normalized)
    # A closed JSON bound prevents custom Sequence implementations or nested
    # values from turning the policy preview into an unbounded body.
    if len(_canonical(context, label="policy_context")) > MAX_BODY_BYTES:
        raise RuntimeGuardrailsInputError(
            f"policy_context exceeds the {MAX_BODY_BYTES}-byte limit"
        )
    return context


def _action_body(request: RuntimeGuardrailInput) -> tuple[str, bytes, str, dict[str, Any]]:
    name = _token(request.action_name, "action_name")
    arguments = request.action_arguments
    if arguments is None:
        args: dict[str, Any] = {}
    elif isinstance(arguments, Mapping):
        try:
            args = dict(arguments)
        except Exception as exc:
            raise RuntimeGuardrailsInputError(
                "action_arguments could not be read safely"
            ) from exc
    else:
        raise RuntimeGuardrailsInputError("action_arguments must be an object")
    envelope = {"action_name": name, "arguments": args, "content": request.content}
    encoded = _canonical(envelope, label="action body")
    if len(encoded) > MAX_BODY_BYTES:
        raise RuntimeGuardrailsInputError(
            f"action body exceeds the {MAX_BODY_BYTES}-byte limit"
        )
    return encoded.decode("utf-8"), encoded, name, args


def _local_shield() -> object:
    """Construct the offline Shield backend; never select its remote SDK."""

    from maverick_shield import Shield  # type: ignore

    return Shield(backend=Shield.BACKEND_BUILTIN)


def _safe_rule_ids(values: object) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise RuntimeGuardrailsInputError("policy rule identifiers are malformed")
    if len(values) > MAX_POLICY_ITEMS * MAX_POLICY_ITEMS:
        raise RuntimeGuardrailsInputError("policy rule identifiers exceed their limit")
    return tuple(sorted({_rule_token(value, "rule_id") for value in values}))


def _safe_control_ids(values: object) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise RuntimeGuardrailsInputError("policy control identifiers are malformed")
    if len(values) > MAX_POLICY_ITEMS * MAX_POLICY_ITEMS:
        raise RuntimeGuardrailsInputError("policy control identifiers exceed their limit")
    return tuple(sorted({_rule_token(value, "control_id") for value in values}))


def _policy_finding(decision: Mapping[str, Any]) -> _Finding:
    effect = decision.get("final_effect")
    if effect not in _POLICY_EFFECT:
        raise RuntimeGuardrailsInputError("policy preview effect is malformed")
    statements = decision.get("matched_statements")
    if not isinstance(statements, Sequence) or isinstance(statements, (str, bytes)):
        raise RuntimeGuardrailsInputError("policy preview statements are malformed")
    if len(statements) > MAX_POLICY_ITEMS * MAX_POLICY_ITEMS:
        raise RuntimeGuardrailsInputError("policy preview statements exceed their limit")
    rules: list[str] = []
    for statement in statements:
        if not isinstance(statement, Mapping):
            raise RuntimeGuardrailsInputError("policy preview statement is malformed")
        policy_id = _rule_token(statement.get("policy_id"), "policy_id")
        statement_id = _rule_token(statement.get("statement_id"), "statement_id")
        rules.append(f"policy/{policy_id}/{statement_id}")
    if not rules:
        if decision.get("defaulted_to_review") is not True or effect != "review":
            raise RuntimeGuardrailsInputError("empty policy preview is malformed")
        rules.append("policy/default-review")
    controls = _safe_control_ids(decision.get("required_control_ids"))
    return _Finding(
        decision=_POLICY_EFFECT[str(effect)],
        categories=("policy",),
        rule_ids=tuple(sorted(set(rules))),
        control_ids=controls,
    )


def _strictest(findings: Sequence[_Finding]) -> str:
    return max(
        (finding.decision for finding in findings),
        key=_DECISION_RANK.__getitem__,
        default="allow",
    )


def _prepare_request(request: RuntimeGuardrailInput) -> _PreparedRequest:
    if not isinstance(request, RuntimeGuardrailInput):
        raise RuntimeGuardrailsInputError(
            "request must be a RuntimeGuardrailInput"
        )
    stage = _stage(request.stage)
    binding = _binding(request.asset)
    content, content_bytes = _bounded_text(request.content, "content")
    context = _policy_context(request.policy_context, str(binding["asset_id"]))

    action_name: str | None = None
    action_arguments: dict[str, Any] | None = None
    if stage == RuntimeStage.ACTION.value:
        body, body_bytes, action_name, action_arguments = _action_body(request)
    else:
        if request.action_name is not None or request.action_arguments is not None:
            raise RuntimeGuardrailsInputError(
                "action metadata is valid only for the action stage"
            )
        body, body_bytes = content, content_bytes
    if request.known_prompt is not None and stage != RuntimeStage.OUTPUT.value:
        raise RuntimeGuardrailsInputError(
            "known_prompt is valid only for the output stage"
        )
    known_prompt = None
    if request.known_prompt is not None:
        known_prompt, _ = _bounded_text(request.known_prompt, "known_prompt")
    return _PreparedRequest(
        stage=stage,
        content=content,
        body=body,
        body_bytes=body_bytes,
        binding=binding,
        policy_context=context,
        action_name=action_name,
        action_arguments=action_arguments,
        known_prompt=known_prompt,
    )


def _redaction_findings(body: str) -> tuple[str, list[_Finding]]:
    findings: list[_Finding] = []
    redacted = body
    try:
        from .safety.secret_detector import redact as redact_secrets

        candidate, secret_matches = redact_secrets(redacted)
        if not isinstance(candidate, str):
            raise RuntimeGuardrailsInputError("secret redactor output is malformed")
        redacted = candidate
        secret_rules = tuple(
            sorted({
                f"secret/{_rule_token(item.name, 'secret type')}"
                for item in secret_matches
            })
        )
        if secret_rules:
            findings.append(_Finding("redact", ("security",), secret_rules))
    except Exception:
        findings.append(
            _Finding("block", ("security",), ("secret-detector/error",))
        )

    try:
        from .safety.pii_detector import redact as redact_pii

        candidate, pii_matches = redact_pii(redacted)
        if not isinstance(candidate, str):
            raise RuntimeGuardrailsInputError("PII redactor output is malformed")
        redacted = candidate
        pii_rules = tuple(
            sorted({
                f"pii/{_rule_token(item.kind, 'PII type')}"
                for item in pii_matches
            })
        )
        if pii_rules:
            findings.append(_Finding("redact", ("privacy",), pii_rules))
    except Exception:
        findings.append(_Finding("block", ("privacy",), ("pii-detector/error",)))
    try:
        redacted_bytes = redacted.encode("utf-8")
    except UnicodeError:
        findings.append(
            _Finding("block", ("safety",), ("redacted-body/invalid",))
        )
        return "", findings
    if len(redacted_bytes) > MAX_BODY_BYTES:
        findings.append(
            _Finding("block", ("safety",), ("redacted-body/oversize",))
        )
        return "", findings
    return redacted, findings


def _shield_finding(
    prepared: _PreparedRequest,
    shield_factory: Callable[[], object],
) -> _Finding | None:
    try:
        shield = shield_factory()
        if prepared.stage == RuntimeStage.PROMPT.value:
            verdict = shield.scan_input(prepared.body)
        elif prepared.stage == RuntimeStage.OUTPUT.value:
            if prepared.known_prompt is None:
                verdict = shield.scan_output(prepared.body)
            else:
                verdict = shield.scan_output(
                    prepared.body,
                    known_prompt=prepared.known_prompt,
                )
        else:
            assert prepared.action_name is not None
            assert prepared.action_arguments is not None
            verdict = shield.scan_tool_call(
                prepared.action_name,
                {
                    "runtime_content": prepared.content,
                    "arguments": prepared.action_arguments,
                },
            )
        allowed = getattr(verdict, "allowed", None)
        if not isinstance(allowed, bool):
            raise RuntimeGuardrailsInputError("Shield verdict is malformed")
        if allowed:
            return None
        category = "security" if prepared.stage == "action" else "safety"
        return _Finding(
            "block",
            (category,),
            (f"shield/{prepared.stage}/blocked",),
        )
    except Exception:
        return _Finding(
            "block",
            ("safety",),
            (f"shield/{prepared.stage}/error",),
        )


def _policy_result(
    policy_enabled: bool,
    policy_factory: Callable[[], object] | None,
    context: Mapping[str, Any],
) -> tuple[str, _Finding | None]:
    if not policy_enabled:
        return _sha256({"status": "disabled"}), None
    try:
        from . import ai_policy_management

        if not ai_policy_management.enabled():
            raise RuntimeGuardrailsConfigError(
                "AI policy management is unavailable"
            )
        factory = policy_factory or ai_policy_management.configured_policy_management
        manager = factory()
        preview = manager.preview(context)
        if not isinstance(preview, Mapping):
            raise RuntimeGuardrailsInputError("policy preview is malformed")
        encoded_preview = _canonical(preview, label="policy preview")
        if len(encoded_preview) > MAX_POLICY_PREVIEW_BYTES:
            raise RuntimeGuardrailsInputError(
                "policy preview exceeds its closed byte limit"
            )
        return _sha256_bytes(encoded_preview), _policy_finding(preview)
    except Exception:
        return (
            _sha256({"status": "evaluation-error"}),
            _Finding(
                "block",
                ("policy",),
                ("policy-management/error",),
            ),
        )


class RuntimeGuardrails:
    """Stateless local runtime evaluator with injectable deterministic edges."""

    def __init__(
        self,
        *,
        shield: object | None = None,
        shield_factory: Callable[[], object] | None = None,
        policy_manager: object | None = None,
        policy_factory: Callable[[], object] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if shield is not None and shield_factory is not None:
            raise RuntimeGuardrailsInputError(
                "provide shield or shield_factory, not both"
            )
        if policy_manager is not None and policy_factory is not None:
            raise RuntimeGuardrailsInputError(
                "provide policy_manager or policy_factory, not both"
            )
        if shield_factory is not None and not callable(shield_factory):
            raise RuntimeGuardrailsInputError("shield_factory must be callable")
        if policy_factory is not None and not callable(policy_factory):
            raise RuntimeGuardrailsInputError("policy_factory must be callable")
        if clock is not None and not callable(clock):
            raise RuntimeGuardrailsInputError("clock must be callable")
        self._shield_factory = (
            (lambda: shield) if shield is not None else shield_factory or _local_shield
        )
        self._policy_factory = (
            (lambda: policy_manager)
            if policy_manager is not None
            else policy_factory
        )
        self._clock = clock or time.time

    def _now(self) -> float:
        try:
            value = self._clock()
        except Exception as exc:
            raise RuntimeGuardrailsError(
                "runtime AI guardrail clock is unavailable"
            ) from exc
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise RuntimeGuardrailsError(
                "runtime AI guardrail clock is invalid"
            )
        return float(value)

    def evaluate(self, request: RuntimeGuardrailInput) -> RuntimeGuardrailResult:
        """Evaluate one request without persisting any raw or redacted body."""

        runtime_enabled, policy_enabled = _feature_flags()
        if not runtime_enabled:
            raise RuntimeGuardrailsConfigError(
                "runtime AI guardrails are disabled; set "
                "[ai_runtime_guardrails] enable = true"
            )
        tenant_ref = _tenant_ref()
        prepared = _prepare_request(request)
        redacted, findings = _redaction_findings(prepared.body)
        shield_finding = _shield_finding(prepared, self._shield_factory)
        if shield_finding is not None:
            findings.append(shield_finding)
        policy_digest, policy_finding = _policy_result(
            policy_enabled,
            self._policy_factory,
            prepared.policy_context,
        )
        if policy_finding is not None:
            findings.append(policy_finding)

        decision = _strictest(findings)
        categories = sorted(
            {category for finding in findings for category in finding.categories}
        )
        rule_ids = sorted(
            {rule for finding in findings for rule in finding.rule_ids}
        )
        control_ids = sorted(
            {control for finding in findings for control in finding.control_ids}
        )

        released: str | None = None
        if decision == RuntimeDecision.ALLOW.value:
            output_digest = _sha256_bytes(prepared.body_bytes)
        elif decision == RuntimeDecision.REDACT.value and redacted != prepared.body:
            released = redacted
            output_digest = _sha256_bytes(redacted.encode("utf-8"))
        else:
            output_digest = _EMPTY_SHA256

        exact_binding = {"tenant_ref": tenant_ref, **prepared.binding}
        receipt = {
            "stage": prepared.stage,
            "decision": decision,
            "categories": categories,
            "rule_ids": rule_ids,
            "control_ids": control_ids,
            "input_sha256": _sha256_bytes(prepared.body_bytes),
            "output_sha256": output_digest,
            "policy_sha256": policy_digest,
            "evaluated_at": self._now(),
            "asset_binding": exact_binding,
        }
        return RuntimeGuardrailResult(
            decision=decision,
            redacted_content=released,
            receipt=receipt,
        )

    def evaluate_request(
        self,
        request: RuntimeGuardrailInput,
    ) -> RuntimeGuardrailResult:
        """Explicit typed-request alias for integration call sites."""

        return self.evaluate(request)


def evaluate_runtime(
    request: RuntimeGuardrailInput,
    *,
    shield: object | None = None,
    shield_factory: Callable[[], object] | None = None,
    policy_manager: object | None = None,
    policy_factory: Callable[[], object] | None = None,
    clock: Callable[[], float] | None = None,
) -> RuntimeGuardrailResult:
    """Evaluate one request using a fresh stateless local service."""

    return RuntimeGuardrails(
        shield=shield,
        shield_factory=shield_factory,
        policy_manager=policy_manager,
        policy_factory=policy_factory,
        clock=clock,
    ).evaluate(request)


def _validated_result_receipt(result: RuntimeGuardrailResult) -> Mapping[str, Any]:
    if not isinstance(result, RuntimeGuardrailResult):
        raise RuntimeGuardrailsInputError(
            "result must be a RuntimeGuardrailResult"
        )
    receipt = result.receipt
    required = {
        "stage",
        "decision",
        "categories",
        "rule_ids",
        "control_ids",
        "input_sha256",
        "output_sha256",
        "policy_sha256",
        "evaluated_at",
        "asset_binding",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != required:
        raise RuntimeGuardrailsInputError("runtime guardrail receipt is malformed")
    decision = receipt.get("decision")
    if decision not in _DYNAMIC_RISK_SEVERITY or result.decision != decision:
        raise RuntimeGuardrailsInputError("runtime decision is malformed")
    _stage(receipt.get("stage"))
    categories = receipt.get("categories")
    allowed_categories = {
        "performance", "policy", "privacy", "quality", "safety", "security",
    }
    if (
        not isinstance(categories, list)
        or categories != sorted(set(categories))
        or any(item not in allowed_categories for item in categories)
    ):
        raise RuntimeGuardrailsInputError("runtime categories are malformed")
    for key in ("rule_ids", "control_ids"):
        values = receipt.get(key)
        if (
            not isinstance(values, list)
            or values != sorted(set(values))
            or len(values) > MAX_POLICY_ITEMS * MAX_POLICY_ITEMS
        ):
            raise RuntimeGuardrailsInputError(f"runtime {key} are malformed")
        for value in values:
            _rule_token(value, key)
    for key in ("input_sha256", "output_sha256", "policy_sha256"):
        value = receipt.get(key)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or not re.fullmatch(r"[0-9a-f]{64}", value)
        ):
            raise RuntimeGuardrailsInputError(f"runtime {key} is malformed")
    observed_at = receipt.get("evaluated_at")
    if (
        isinstance(observed_at, bool)
        or not isinstance(observed_at, (int, float))
        or not math.isfinite(float(observed_at))
        or float(observed_at) <= 0
    ):
        raise RuntimeGuardrailsInputError("runtime evaluated_at is malformed")
    binding = receipt.get("asset_binding")
    if not isinstance(binding, Mapping) or set(binding) != {
        "tenant_ref", "asset_id", "asset_revision", "asset_version_digest",
    }:
        raise RuntimeGuardrailsInputError("runtime asset binding is malformed")
    tenant_ref = binding.get("tenant_ref")
    if not isinstance(tenant_ref, str) or not re.fullmatch(
        r"TEN-[0-9a-f]{24}", tenant_ref
    ):
        raise RuntimeGuardrailsInputError("runtime tenant binding is malformed")
    _binding(RuntimeAssetBinding(
        asset_id=binding.get("asset_id"),
        asset_revision=binding.get("asset_revision"),
        asset_version_digest=binding.get("asset_version_digest"),
    ))
    return receipt


def dynamic_risk_receipt(
    result: RuntimeGuardrailResult,
    *,
    validity_seconds: int = 3_600,
) -> dict[str, Any]:
    """Normalize a result for ``ai_dynamic_risk.RUNTIME_RECEIPT_SCHEMA``.

    The adapter validates its own closed output through the stable dynamic-risk
    adapter before returning it.  It does not ingest or persist the signal.
    """

    if (
        isinstance(validity_seconds, bool)
        or not isinstance(validity_seconds, int)
        or validity_seconds < 60
        or validity_seconds > _MAX_DYNAMIC_RISK_VALIDITY_SECONDS
    ):
        raise RuntimeGuardrailsInputError(
            "validity_seconds must be between 60 and 31622400"
        )
    receipt = _validated_result_receipt(result)
    binding = receipt["asset_binding"]
    asset_id = binding["asset_id"]
    decision = receipt.get("decision")
    categories = receipt.get("categories")
    category = next(
        (
            item
            for item in ("security", "privacy", "safety", "performance", "quality")
            if item in categories
        ),
        "safety" if "policy" in categories else "quality",
    )
    if category not in _DYNAMIC_RISK_CATEGORIES:  # defensive closed-world check
        raise RuntimeGuardrailsInputError("runtime risk category is unsupported")
    observed_at = receipt["evaluated_at"]
    stage = _stage(receipt.get("stage"))
    try:
        from . import ai_dynamic_risk
    except Exception as exc:
        raise RuntimeGuardrailsError(
            "dynamic-risk runtime receipt adapter is unavailable"
        ) from exc
    payload = {
        "schema": ai_dynamic_risk.RUNTIME_RECEIPT_SCHEMA,
        "asset_id": asset_id,
        "receipt_id": "runtime-" + _sha256(receipt)[:32],
        "signal_code": f"runtime_{stage}_{decision}",
        "severity": _DYNAMIC_RISK_SEVERITY[str(decision)],
        "confidence": 1.0,
        "observed_at": float(observed_at),
        "expires_at": float(observed_at) + validity_seconds,
        "category": category,
    }
    normalized = {**payload, "receipt_sha256": _sha256(payload)}
    try:
        ai_dynamic_risk.signal_from_runtime_receipt(normalized)
    except Exception as exc:
        raise RuntimeGuardrailsInputError(
            "normalized dynamic-risk runtime receipt is invalid"
        ) from exc
    return normalized


to_dynamic_risk_receipt = dynamic_risk_receipt
RuntimeGuardrailService = RuntimeGuardrails
default_service = RuntimeGuardrails()


__all__ = [
    "MAX_BODY_BYTES",
    "RECEIPT_SCHEMA",
    "RuntimeAssetBinding",
    "RuntimeDecision",
    "RuntimeGuardrailInput",
    "RuntimeGuardrailResult",
    "RuntimeGuardrailService",
    "RuntimeGuardrails",
    "RuntimeGuardrailsConfigError",
    "RuntimeGuardrailsError",
    "RuntimeGuardrailsInputError",
    "RuntimeGuardrailsTenantError",
    "RuntimePolicyContext",
    "RuntimeStage",
    "default_service",
    "dynamic_risk_receipt",
    "enabled",
    "evaluate_runtime",
    "require_enabled",
    "to_dynamic_risk_receipt",
]
