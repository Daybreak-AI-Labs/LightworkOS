"""Portable service-attested action evidence with independently supplied trust.

Signatures attest to the issuer's recorded observations and authenticated review,
not external business correctness or isolated signer custody. Offline verification
never asserts current review/source eligibility. UTF-8 bundle/recipe commitments
and legacy ASCII-escaped governed-record commitments are deliberately distinct.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

from ..audit import signing
from ..governed_operations import digest as governed_digest

SCHEMA = "lightwork.reviewed-action-episode.v1"
TEACHING_SCHEMA = "lightwork.reviewed-action-episode.v2"
TRUST_SCHEMA = "lightwork.action-evidence-trust.v1"
GRANT_SCHEMA = "lightwork.action-evidence-grant.v1"
PURPOSE = "action_recipe_training_evidence"
CANONICALIZATION = "json-sort-keys-compact-utf8-v1"
MAX_BUNDLE_BYTES = 262_144
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_KEY = re.compile(r"[0-9a-f]{16}\Z")
_SOURCE_FIELDS = {"family", "tenant_sha256", "owner", "flow_id", "run_id", "definition_digest",
                  "definition_version", "definition_revision", "release_digest", "release_id", "plan_sha256",
                  "original_input_sha256", "execution_identity_sha256"}
_REVIEW_FIELDS = {"reviewed", "accepted", "authenticated", "reviewer", "rationale", "reviewed_at",
                  "authority", "authority_sha256", "episode_sha256", "request_sha256"}
_BODY_FIELDS = {"schema", "issuer", "tenant", "purpose", "canonicalization", "episode", "episode_sha256",
                "capture_episode_sha256", "source", "record_id", "review_revision", "review", "review_sha256",
                "contract", "contract_sha256", "enrollment", "enrollment_sha256", "enrollment_request_sha256",
                "steps", "issued_at", "retain_until", "grant", "grant_sha256", "bundle_id", "issuance_status",
                "source_current_at_issue"}


def canonical(value, *, max_bytes=None):
    # The larger option is only for an encrypted source+bundle envelope. Public
    # bundle parsing, signatures and verification always use the default cap.
    limit = MAX_BUNDLE_BYTES if max_bytes is None else max_bytes
    if type(limit) is not int or not 1 <= limit <= 524_288:
        raise ValueError("invalid bounded evidence serialization limit")
    remaining, active = limit, set()

    def walk(item, depth=0):
        nonlocal remaining
        remaining -= 8
        if depth > 32 or remaining < 0:
            raise ValueError("evidence JSON exceeds depth or size limit")
        kind = type(item)
        if kind is str:
            if len(item) > 4096:
                raise ValueError("evidence string exceeds limit")
            remaining -= len(item.encode("utf-8"))
        elif kind is int:
            if abs(item) > 10**24:
                raise ValueError("evidence integer exceeds limit")
        elif kind is float:
            if not math.isfinite(item) or abs(item) > 10**24:
                raise ValueError("evidence number must be finite and bounded")
        elif item is None or kind is bool:
            pass
        elif kind in (dict, list):
            if id(item) in active:
                raise ValueError("evidence JSON must not contain cycles")
            active.add(id(item))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ValueError("evidence JSON keys must be strings")
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            else:
                for child in item:
                    walk(child, depth + 1)
            active.remove(id(item))
        else:
            raise ValueError("evidence requires strict JSON data")
        if remaining < 0:
            raise ValueError("evidence JSON exceeds size limit")

    walk(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(raw.encode("utf-8")) > limit:
        raise ValueError("evidence JSON exceeds byte limit")
    return raw


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key in evidence")
        value[key] = item
    return value


def _constant(value):
    raise ValueError("evidence requires finite JSON")


def snapshot(value):
    """Accept strict JSON bytes/text or a typed object and return a bounded copy."""
    if type(value) in (bytes, str):
        if len(value) > MAX_BUNDLE_BYTES:
            raise ValueError("evidence JSON exceeds byte limit")
        raw = value.decode("utf-8", errors="strict") if type(value) is bytes else value
        if len(raw.encode("utf-8")) > MAX_BUNDLE_BYTES:
            raise ValueError("evidence JSON exceeds byte limit")
        try:
            value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        except RecursionError as exc:
            raise ValueError("evidence JSON exceeds depth limit") from exc
    return json.loads(canonical(value))


def _fields(value, fields, label):
    if type(value) is not dict or set(value) != fields:
        raise ValueError(f"invalid {label} fields")


def _text(value, label, *, empty=False, maximum=256):
    if type(value) is not str or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError(f"invalid {label}")
    return value


def _hash(value):
    if type(value) is not str or not _HEX.fullmatch(value):
        raise ValueError("invalid evidence SHA-256 commitment")


def _issuer(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
        raise ValueError("evidence issuer must be an explicit bounded deployment identity")


def _time(value):
    if type(value) not in (int, float) or not 0 <= value <= 10**24 or not math.isfinite(value):
        raise ValueError("evidence time must be a finite nonnegative number")
    return value


def validate_trust(trust):
    trust = snapshot(trust)
    _fields(trust, {"schema", "issuer", "tenant", "purpose", "keys", "revoked_keys"}, "trust policy")
    if trust["schema"] != TRUST_SCHEMA or trust["purpose"] != PURPOSE:
        raise ValueError("untrusted evidence purpose or trust schema")
    _issuer(trust["issuer"])
    _text(trust["tenant"], "tenant")
    keys, revoked = trust["keys"], trust["revoked_keys"]
    if type(keys) is not dict or not 1 <= len(keys) <= 256:
        raise ValueError("trust policy requires a bounded independent key map")
    for key, public in keys.items():
        if (type(key) is not str or not _KEY.fullmatch(key) or type(public) is not str
                or not _HEX.fullmatch(public) or hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16] != key):
            raise ValueError("trust policy key identity does not match its full public key")
    if (type(revoked) is not list or len(revoked) > 256
            or any(type(key) is not str or not _KEY.fullmatch(key) for key in revoked)
            or len(set(revoked)) != len(revoked)):
        raise ValueError("invalid revoked-key policy")
    return trust


def local_trust(tenant):
    """Snapshot same-deployment protected keys; never enroll bundle-provided keys."""
    from ..config import get_flows
    from ..paths import tenant_scope

    _text(tenant, "tenant")
    with tenant_scope(tenant=tenant):
        config = get_flows()
        return validate_trust({"schema": TRUST_SCHEMA, "issuer": config.get("action_evidence_issuer", ""),
            "tenant": tenant, "purpose": PURPOSE, "keys": signing.trusted_audit_public_keys(),
            "revoked_keys": config.get("action_evidence_revoked_keys", [])})


def _validate_source(body):
    source = body["source"]
    _fields(source, _SOURCE_FIELDS, "source")
    from .action_episodes import TEACHING_FAMILY

    expected_family = TEACHING_FAMILY if body["schema"] == TEACHING_SCHEMA else "native_governed_flow_actions_v1"
    if source["family"] != expected_family or source["tenant_sha256"] != governed_digest(body["tenant"]):
        raise ValueError("evidence source tenant or family changed")
    for key in ("owner", "flow_id", "run_id", "definition_revision"):
        _text(source[key], key)
    for key in ("definition_digest", "plan_sha256", "original_input_sha256", "execution_identity_sha256"):
        _hash(source[key])
    _text(source["release_id"], "release_id", empty=True)
    if source["release_digest"]:
        _hash(source["release_digest"])
    elif source["release_digest"] != "":
        raise ValueError("invalid release digest")
    if type(source["definition_version"]) is not int or source["definition_version"] < 1:
        raise ValueError("invalid source definition version")
    expected_record = "LAE-" + governed_digest({"tenant": body["tenant"], "flow_id": source["flow_id"],
                                               "run_id": source["run_id"]})[:32]
    if body["record_id"] != expected_record or type(body["review_revision"]) is not int or body["review_revision"] < 1:
        raise ValueError("invalid source record or review revision")
    return source


def validate_teaching(teaching, *, source, inputs, prefix_result):
    """Check portable teaching commitments, not unstated native execution facts.

    The source service also reconstructs the question against the immutable
    parent artifact and verifies the actual paused approval before recording it.
    Detached decision signatures are checked under independently supplied trust
    by verify_bundle, never by trusting a key carried in this object.
    """
    from . import action_recipe_transforms as transforms
    from .action_episodes import _object

    _fields(teaching, {"schema", "decision_origin", "parent_lineage", "question", "question_sha256",
        "route", "tool", "actor", "decided_at", "approval_binding_sha256", "authority_binding_sha256",
        "decision_material", "decision_attestation"}, "native teaching")
    if (teaching["schema"] != "lightwork.native-choice-teaching-decision.v1"
            or teaching["decision_origin"] != "authenticated_human"
            or type(teaching["route"]) is not str or teaching["route"] not in {"0", "1"}):
        raise ValueError("invalid native teaching decision origin or route")
    _text(teaching["actor"], "teaching actor")
    _time(teaching["decided_at"])
    _hash(teaching["approval_binding_sha256"])
    if teaching["authority_binding_sha256"] != "":
        _hash(teaching["authority_binding_sha256"])
    question = teaching["question"]
    _fields(question, {"schema", "artifact_sha256", "guard_artifact_sha256", "observation", "input_sha256",
        "prefix_sha256", "guard_candidate_count", "guard_partitions", "options", "question_sha256"}, "teaching question")
    if (question["schema"] != "lightwork.action-choice-teaching-question.v1"
            or canonical(question["observation"]) != canonical({"inputs": inputs, "prefix_result": prefix_result})
            or question["input_sha256"] != transforms._digest(inputs)
            or question["prefix_sha256"] != transforms._digest({"input": inputs, "prior_results": [prefix_result]})
            or question["question_sha256"] != transforms._digest({key: value for key, value in question.items()
                                                                  if key != "question_sha256"})
            or teaching["question_sha256"] != question["question_sha256"]):
        raise ValueError("native teaching question commitment changed")
    for key in ("artifact_sha256", "guard_artifact_sha256"):
        _hash(question[key])
    reference = teaching["parent_lineage"]
    _fields(reference, {"schema", "id", "package_sha256", "artifact_sha256"}, "parent admission")
    if (reference["schema"] != "lightwork.action-recipe-admission-ref.v1"
            or type(reference["id"]) is not str or not re.fullmatch(r"LRA-[0-9a-f]{32}", reference["id"])
            or reference["artifact_sha256"] != question["artifact_sha256"]):
        raise ValueError("teaching parent admission changed")
    _hash(reference["package_sha256"])
    partitions = question["guard_partitions"]
    if (type(partitions) is not list or len(partitions) != 2
            or any(type(item) is not dict or set(item) != {"output", "candidate_count"}
                   or type(item["output"]) is not bool or type(item["candidate_count"]) is not int
                   or item["candidate_count"] < 1 for item in partitions)
            or {item["output"] for item in partitions} != {False, True}
            or type(question["guard_candidate_count"]) is not int
            or sum(item["candidate_count"] for item in partitions) != question["guard_candidate_count"]):
        raise ValueError("teaching question does not contain two complete guard partitions")
    options = question["options"]
    if type(options) is not list or len(options) != 2:
        raise ValueError("teaching question must offer exactly two continuations")
    for index, option in enumerate(options):
        _fields(option, {"route", "tool", "arguments", "arguments_sha256"}, "teaching option")
        if (option["route"] != str(index) or type(option["arguments"]) is not dict
                or option["arguments_sha256"] != transforms._digest(option["arguments"])):
            raise ValueError("native teaching option changed")
        _text(option["tool"], "teaching tool")
        _object(option["arguments"])
    if options[0]["tool"] == options[1]["tool"]:
        raise ValueError("teaching options require distinct terminal tools")
    selected = options[int(teaching["route"])]
    if teaching["tool"] != selected["tool"]:
        raise ValueError("teaching selected tool changed")
    material = teaching["decision_material"]
    _fields(material, {"schema", "run_id", "flow_id", "cursor", "updated", "card_binding_sha256", "workspace",
        "operation_binding_sha256", "authority_binding_sha256", "inputs_sha256", "decision", "decided_by"},
        "teaching approval material")
    if (material["schema"] != "lightwork.flow-decision-material.v1" or material["run_id"] != source["run_id"]
            or material["flow_id"] != source["flow_id"] or material["cursor"] != "teaching_review"
            or material["operation_binding_sha256"] != teaching["approval_binding_sha256"]
            or material["authority_binding_sha256"] != teaching["authority_binding_sha256"]
            or material["inputs_sha256"] != governed_digest({})
            or material["decision"] != "route:" + teaching["route"] or material["decided_by"] != teaching["actor"]):
        raise ValueError("native teaching approval material changed")
    _hash(material["card_binding_sha256"])
    _text(material["workspace"], "teaching workspace")
    _time(material["updated"])
    attestation = teaching["decision_attestation"]
    _fields(attestation, {"schema", "principal", "tenant", "action", "resource", "issued_at", "expires_at",
                          "material_sha256", "signature"}, "teaching decision attestation")
    if (attestation["schema"] != "lightwork.flow-decision-attestation.v1"
            or attestation["principal"] != teaching["actor"] or attestation["tenant"] != material["workspace"]
            or attestation["action"] != "flow.approval.decide" or attestation["resource"] != source["run_id"]
            or attestation["material_sha256"] != governed_digest(material)
            or _time(attestation["issued_at"]) > teaching["decided_at"] + 30
            or not teaching["decided_at"] < _time(attestation["expires_at"])):
        raise ValueError("teaching attestation does not bind the native human decision")
    return selected


def verify_teaching_signature(teaching, *, trust, tenant):
    """Verify historical authenticated choice under current independent key policy."""
    attestation = teaching["decision_attestation"]
    signature = attestation["signature"]
    _fields(signature, {"algorithm", "digest", "key_id", "message_version", "signature"}, "teaching signature")
    signed = governed_digest({key: value for key, value in attestation.items() if key != "signature"})
    key = signature["key_id"]
    if (attestation["tenant"] != tenant or type(key) is not str or key not in trust["keys"]
            or key in trust["revoked_keys"] or signature["algorithm"] != "Ed25519-SHA256"
            or signature["message_version"] != signing.DETACHED_DIGEST_MESSAGE_VERSION
            or signature["digest"] != signed or type(signature["signature"]) is not str
            or not re.fullmatch(r"[0-9a-f]{128}", signature["signature"])
            or not signing.verify_detached_digest(trust["keys"][key], signed, signature["signature"])):
        raise ValueError("native teaching decision signature is not trusted")


def _validate_teaching_body(body, source, episode, steps, contract):
    from .action_episode_review import _matches

    if len(steps) != 2 or body["teaching_sha256"] != governed_digest(body["teaching"]):
        raise ValueError("native teaching episode or decision commitment changed")
    selected = validate_teaching(body["teaching"], source=source, inputs=episode["inputs"],
                                 prefix_result=episode["steps"][0]["result"])
    if (steps[0]["node_id"] != "action_0" or steps[1]["node_id"] != "action_1_" + selected["route"]
            or episode["steps"][1]["tool"] != selected["tool"]
            or canonical(episode["steps"][1]["arguments"]) != canonical(selected["arguments"])):
        raise ValueError("captured native action does not match the taught continuation")
    for option in body["teaching"]["question"]["options"]:
        if option["tool"] not in contract["allowed_tools"]:
            raise ValueError("teaching option is outside capture retention contract")
        _matches(option["arguments"], contract["tool_data_schemas"][option["tool"]]["arguments"])


def validate_body(body):
    """Check all internally reconstructible commitments before signing/verifying."""
    from . import action_recipe as recipe
    from .action_episode_review import _contract, _matches

    body = snapshot(body)
    teaching_body = type(body) is dict and body.get("schema") == TEACHING_SCHEMA
    _fields(body, _BODY_FIELDS | ({"teaching", "teaching_sha256"} if teaching_body else set()), "signed body")
    if (body["schema"] not in (SCHEMA, TEACHING_SCHEMA) or body["purpose"] != PURPOSE or body["canonicalization"] != CANONICALIZATION
            or body["issuance_status"] != "accepted_audited" or type(body["source_current_at_issue"]) is not bool):
        raise ValueError("invalid evidence schema, purpose or issuance assertion")
    _issuer(body["issuer"])
    _text(body["tenant"], "tenant")
    source = _validate_source(body)
    episode, review = body["episode"], body["review"]
    _fields(episode, {"id", "inputs", "steps"}, "episode")
    if episode["id"] != source["run_id"] or type(episode["inputs"]) is not dict:
        raise ValueError("episode is not bound to its source run")
    if type(episode["steps"]) is not list or not 2 <= len(episode["steps"]) <= 8:
        raise ValueError("invalid episode step sequence")
    if body["episode_sha256"] != recipe._digest(episode) or body["capture_episode_sha256"] != governed_digest(episode):
        raise ValueError("episode commitment changed")
    _fields(review, _REVIEW_FIELDS, "review")
    if (any(review[key] is not True for key in ("reviewed", "accepted", "authenticated"))
            or review["authority"] != "authenticated_service_context"
            or review["episode_sha256"] != body["capture_episode_sha256"]):
        raise ValueError("evidence requires an authenticated accepted review of this episode")
    _text(review["reviewer"], "reviewer")
    _text(review["rationale"], "review rationale", maximum=2000)
    _hash(review["authority_sha256"])
    if (review["request_sha256"] != governed_digest({"episode": review["episode_sha256"], "accepted": True,
            "rationale": review["rationale"], "reviewer": review["reviewer"]})
            or body["review_sha256"] != governed_digest(review)):
        raise ValueError("review commitment changed")
    contract = body["contract"]
    _fields(contract, {"allowed_tools", "input_schema", "tool_data_schemas"}, "capture contract")
    normalized = _contract(contract["allowed_tools"], contract["input_schema"], contract["tool_data_schemas"])
    if normalized != contract or body["contract_sha256"] != governed_digest(contract):
        raise ValueError("capture contract commitment changed")
    _matches(episode["inputs"], contract["input_schema"])
    steps = body["steps"]
    if type(steps) is not list or len(steps) != len(episode["steps"]):
        raise ValueError("native observation sequence changed")
    seen_calls, seen_nodes = set(), set()
    for observed, step in zip(steps, episode["steps"], strict=True):
        _fields(step, {"tool", "arguments", "result"}, "episode step")
        if type(step["tool"]) is not str or step["tool"] not in contract["allowed_tools"]:
            raise ValueError("episode tool is outside its capture contract")
        recipe.require_complete_result(step["result"])
        declared = contract["tool_data_schemas"][step["tool"]]
        _matches(step["arguments"], declared["arguments"])
        _matches(step["result"], declared["result"])
        _fields(observed, {"node_id", "call_id", "principal", "tool_schema_sha256", "step_sha256"}, "native observation")
        _text(observed["node_id"], "node_id")
        _text(observed["principal"], "principal", empty=True)
        if (type(observed["call_id"]) is not str or not re.fullmatch(r"[0-9a-f]{24}", observed["call_id"])
                or observed["call_id"] in seen_calls or observed["node_id"] in seen_nodes
                or observed["step_sha256"] != governed_digest(step)):
            raise ValueError("native invocation commitment changed")
        _hash(observed["tool_schema_sha256"])
        seen_calls.add(observed["call_id"])
        seen_nodes.add(observed["node_id"])
    if teaching_body:
        _validate_teaching_body(body, source, episode, steps, contract)
    enrollment = body["enrollment"]
    _fields(enrollment, {"actor", "authority_sha256", "enrolled_at"}, "enrollment")
    _text(enrollment["actor"], "enrollment actor")
    _hash(enrollment["authority_sha256"])
    _hash(body["enrollment_request_sha256"])
    if body["enrollment_sha256"] != governed_digest(enrollment):
        raise ValueError("enrollment commitment changed")
    grant = body["grant"]
    _fields(grant, {"schema", "purpose", "tenant", "actor", "granted_at", "use_until", "retain_derived_copies",
                    "rationale", "authority_sha256", "episode_sha256", "review_sha256", "request_sha256"}, "training grant")
    if (grant["schema"] != GRANT_SCHEMA or grant["purpose"] != PURPOSE or grant["tenant"] != body["tenant"]
            or grant["retain_derived_copies"] is not True or grant["episode_sha256"] != body["capture_episode_sha256"]
            or grant["review_sha256"] != body["review_sha256"]):
        raise ValueError("training grant scope changed")
    _text(grant["actor"], "grant actor")
    _text(grant["rationale"], "grant rationale", maximum=2000)
    _hash(grant["authority_sha256"])
    if (grant["request_sha256"] != governed_digest({"episode": grant["episode_sha256"], "review": grant["review_sha256"],
            "actor": grant["actor"], "use_until": grant["use_until"], "retain_derived_copies": True,
            "rationale": grant["rationale"]}) or body["grant_sha256"] != governed_digest(grant)):
        raise ValueError("training grant commitment changed")
    times = [_time(value) for value in (enrollment["enrolled_at"], review["reviewed_at"], grant["granted_at"],
                                       body["issued_at"], grant["use_until"], body["retain_until"])]
    if times != sorted(times) or body["issued_at"] >= grant["use_until"]:
        raise ValueError("evidence time/retention ordering is invalid")
    if teaching_body and not enrollment["enrolled_at"] <= body["teaching"]["decided_at"] <= review["reviewed_at"]:
        raise ValueError("teaching decision was not recorded between enrollment and review")
    expected_id = "AEB-" + digest({"record_id": body["record_id"], "review_sha256": body["review_sha256"],
                                   "grant_sha256": body["grant_sha256"]})[:32]
    if body["bundle_id"] != expected_id:
        raise ValueError("bundle identity does not match source/review/grant")
    return body


def verify_bundle(bundle, *, trust, expected_tenant, now):
    """Verify under explicit trust and clock; live revocation remains not_checked."""
    bundle, trust = snapshot(bundle), validate_trust(trust)
    _fields(bundle, {"body", "signature"}, "bundle")
    body = validate_body(bundle["body"])
    _text(expected_tenant, "expected tenant")
    if (body["tenant"] != expected_tenant or trust["tenant"] != expected_tenant
            or body["issuer"] != trust["issuer"] or body["purpose"] != trust["purpose"]):
        raise ValueError("bundle issuer, tenant or purpose is outside trusted scope")
    signature = bundle["signature"]
    _fields(signature, {"algorithm", "digest", "key_id", "message_version", "signature"}, "detached signature")
    key = signature["key_id"]
    if (type(key) is not str or key not in trust["keys"] or key in trust["revoked_keys"]
            or signature["algorithm"] != "Ed25519-SHA256"
            or signature["message_version"] != signing.DETACHED_DIGEST_MESSAGE_VERSION
            or signature["digest"] != digest(body)
            or type(signature["signature"]) is not str or not re.fullmatch(r"[0-9a-f]{128}", signature["signature"])
            or not signing.verify_detached_digest(trust["keys"][key], signature["digest"], signature["signature"])):
        raise ValueError("bundle signature is not trusted")
    if not body["issued_at"] <= _time(now) < body["grant"]["use_until"]:
        raise ValueError("bundle is outside its permitted time window")
    if body["schema"] == TEACHING_SCHEMA:
        verify_teaching_signature(body["teaching"], trust=trust, tenant=expected_tenant)
    return {"body": body, "body_sha256": signature["digest"], "signature": signature,
            "signature_sha256": digest(signature), "trust_sha256": digest(trust),
            "key_fingerprint": hashlib.sha256(bytes.fromhex(trust["keys"][key])).hexdigest(),
            "signature_status": "trusted", "commitments_status": "consistent", "time_status": "valid",
            "live_status": "not_checked"}
