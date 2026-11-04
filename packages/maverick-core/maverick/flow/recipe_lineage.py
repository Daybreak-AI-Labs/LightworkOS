"""Complete signed training lineage and tenant-scoped governed recipe admission.

Signatures attest service-recorded evidence, not the correctness of a learned
rule. Live checks are point-in-time checks across records, not a distributed
revocation fence. Admission never grants connector execution authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import time

from .. import crypto_at_rest
from ..audit.errors import AuditRefused
from ..governed_operations import ServiceContext, audit_authority_denial, digest
from ..governed_records import GovernedRecordStore, RecordConflict
from ..paths import current_tenant_id_strict, tenant_scope
from . import action_recipe, recipe_flow, store

SCHEMA = "lightwork.action-recipe-lineage.v1"
REFERENCE_SCHEMA = "lightwork.action-recipe-admission-ref.v1"
ADMISSION_SCHEMA = "lightwork.action-recipe-admission.v1"
ENVELOPE_SCHEMA = "lightwork.action-recipe-admission-envelope.v1"
MAX_PACKAGE_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 1000
_ID = re.compile(r"LRA-[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_RECORDS = GovernedRecordStore("flow_recipe_lineage", "LRA", "flow_recipe_lineage")
_META = ("schema", "id", "tenant_sha256", "owner", "package_sha256", "artifact_sha256",
         "issuer", "use_until", "status", "payload_revision", "admitted_by", "admitted_at",
         "authority_sha256", "admitted_trust_sha256")


class RecipeLineageConflict(RecordConflict):
    """An admission, source or exact retained package changed."""


class RecipeLineageAuditPending(AuditRefused):
    def __init__(self, record_id):
        super().__init__("recipe lineage has a pending audit receipt")
        self.record_id = record_id


def _canonical(value):
    remaining, active = MAX_PACKAGE_BYTES, set()

    def walk(item, depth=0):
        nonlocal remaining
        remaining -= 8
        if depth > 48 or remaining < 0:
            raise ValueError("lineage package exceeds size or depth limit")
        kind = type(item)
        if kind is str:
            remaining -= len(item.encode("utf-8"))
        elif kind is int:
            if item.bit_length() > 256:
                raise ValueError("lineage integer exceeds limit")
        elif kind is float:
            if not math.isfinite(item):
                raise ValueError("lineage requires finite numbers")
        elif item is None or kind is bool:
            pass
        elif kind in (list, dict):
            if id(item) in active:
                raise ValueError("lineage requires acyclic JSON")
            active.add(id(item))
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ValueError("lineage object keys must be strings")
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            else:
                for child in item:
                    walk(child, depth + 1)
            active.remove(id(item))
        else:
            raise ValueError("lineage requires strict JSON values")
        if remaining < 0:
            raise ValueError("lineage package exceeds size limit")

    walk(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(raw.encode("utf-8")) > MAX_PACKAGE_BYTES:
        raise ValueError("lineage package exceeds byte limit")
    return raw


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _text(value, label):
    if (type(value) is not str or not value.strip() or len(value) > 256
            or any(ord(char) < 32 for char in value)):
        raise ValueError(f"{label} must be a nonempty bounded string")
    return value


def _hash(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ValueError("invalid lineage commitment")
    return value


def _verified(bundles, *, trust, expected_tenant, now):
    from .action_provenance import validate_trust, verify_bundle

    if type(bundles) is not list or not 2 <= len(bundles) <= action_recipe.MAX_EPISODES:
        raise ValueError("lineage requires two to 32 signed reviewed bundles")
    bundles = json.loads(_canonical(bundles))
    trust = validate_trust(trust)
    entries, seen = [], set()
    scope = None
    for bundle in bundles:
        checked = verify_bundle(bundle, trust=trust, expected_tenant=expected_tenant, now=now)
        body = checked["body"]
        identity = body["episode"]["id"]
        current_scope = (body["tenant"], body["source"]["owner"], body["issuer"])
        if identity in seen or (scope is not None and scope != current_scope):
            raise ValueError("lineage requires unique episodes from one tenant, owner and issuer")
        scope = current_scope
        seen.add(identity)
        entries.append((identity, bundle, checked))
    return sorted(entries, key=lambda entry: entry[0])


def _manifest(entries):
    return [{"episode_id": identity, "episode_sha256": verified["body"]["episode_sha256"],
             "record_id": verified["body"]["record_id"],
             "review_revision": verified["body"]["review_revision"],
             "body_sha256": verified["body_sha256"],
             "signature_sha256": verified["signature_sha256"],
             "key_fingerprint": verified["key_fingerprint"]}
            for identity, _bundle, verified in entries]


def _assemble(artifact, entries, batches, ancestors):
    body = entries[0][2]["body"]
    package = {"schema": SCHEMA, "artifact": artifact,
               "bundles": [bundle for _, bundle, _ in entries], "manifest": _manifest(entries),
               "tenant": body["tenant"], "owner": body["source"]["owner"], "issuer": body["issuer"],
               "use_until": min(item[2]["body"]["grant"]["use_until"] for item in entries),
               "batches": batches, "ancestors": ancestors}
    package["package_sha256"] = _digest(package)
    _canonical(package)
    return package


def learn_from_verified_bundles(bundles, *, trust, expected_tenant, now, allowed_tools,
                                domain=None, max_operations=2, operators=None, constants=None):
    """Learn from every verified episode; no partially verified batch is usable."""
    entries = _verified(bundles, trust=trust, expected_tenant=expected_tenant, now=now)
    episodes = [entry[2]["body"]["episode"] for entry in entries]
    if domain is None:
        if operators is not None or constants is not None or max_operations != 2:
            raise ValueError("copy-only lineage does not accept a transformation grammar")
        artifact = action_recipe.synthesize(episodes, allowed_tools=allowed_tools)
    else:
        from .action_recipe_transforms import synthesize_transformed
        artifact = synthesize_transformed(episodes, allowed_tools=allowed_tools, domain=domain,
                                         max_operations=max_operations, operators=operators, constants=constants)
    return _assemble(artifact, entries, [[entry[0] for entry in entries]], [])


def learn_choice_from_verified_bundles(bundles, *, trust, expected_tenant, now, allowed_tools,
                                       domain, max_operations=2, operators=None, constants=None):
    """Learn a bounded binary continuation from complete signed native episodes.

    The observed terminal tools supply labels. Signatures attest recorded
    examples, not the correctness of the demonstrated business choices.
    """
    from .action_choice import synthesize_choice

    entries = _verified(bundles, trust=trust, expected_tenant=expected_tenant, now=now)
    artifact = synthesize_choice([entry[2]["body"]["episode"] for entry in entries],
        allowed_tools=allowed_tools, domain=domain, max_operations=max_operations,
        operators=operators, constants=constants)
    return _assemble(artifact, entries, [[entry[0] for entry in entries]], [])


def learn_transducer_from_verified_bundles(bundles, *, trust, expected_tenant, now, allowed_tools,
                                          domain, max_operations=1, operators=None, constants=None, max_steps=8):
    """Learn next-action and stopping alternatives from complete signed traces.

    Verification binds recorded native evidence to one tenant, owner and issuer.
    It neither establishes business correctness nor grants execution authority.
    """
    from .workflow_transducer import synthesize

    entries = _verified(bundles, trust=trust, expected_tenant=expected_tenant, now=now)
    artifact = synthesize([entry[2]["body"]["episode"] for entry in entries],
        allowed_tools=allowed_tools, domain=domain, max_operations=max_operations,
        operators=operators, constants=constants, max_steps=max_steps)
    return _assemble(artifact, entries, [[entry[0] for entry in entries]], [])


def learn_memory_from_verified_bundles(bundles, *, trust, expected_tenant, now, allowed_tools,
                                      domain, max_operations=1, operators=None, constants=None, max_steps=8):
    """Jointly infer bounded history summaries and decisions from signed traces.

    Every surviving summary remains paired with its own decision alternatives.
    Reviewed evidence authenticates the recorded examples, not a business rule.
    """
    from .workflow_memory import synthesize

    entries = _verified(bundles, trust=trust, expected_tenant=expected_tenant, now=now)
    artifact = synthesize([entry[2]["body"]["episode"] for entry in entries],
        allowed_tools=allowed_tools, domain=domain, max_operations=max_operations,
        operators=operators, constants=constants, max_steps=max_steps)
    return _assemble(artifact, entries, [[entry[0] for entry in entries]], [])


def _rebuild(package, *, trust, expected_tenant, now):
    package = json.loads(_canonical(package))
    fields = {"schema", "artifact", "bundles", "manifest", "tenant", "owner", "issuer", "use_until",
              "batches", "ancestors", "package_sha256"}
    if type(package) is not dict or set(package) != fields or package["schema"] != SCHEMA:
        raise ValueError("invalid recipe lineage package schema")
    entries = _verified(package["bundles"], trust=trust, expected_tenant=expected_tenant, now=now)
    batches = package["batches"]
    if (type(batches) is not list or not batches or len(batches) > 31
            or any(type(batch) is not list or not batch or any(type(identity) is not str for identity in batch)
                   or batch != sorted(set(batch)) for batch in batches)
            or len(batches[0]) < 2):
        raise ValueError("lineage requires exact ordered evidence batches")
    identities = [identity for batch in batches for identity in batch]
    if len(set(identities)) != len(identities) or sorted(identities) != [entry[0] for entry in entries]:
        raise ValueError("lineage batches must cover every episode exactly once")
    if type(package["ancestors"]) is not list or len(package["ancestors"]) != len(batches) - 1:
        raise ValueError("lineage ancestor chain is incomplete")
    artifact = package["artifact"]
    action_recipe.validate_artifact(artifact)
    by_id = {entry[0]: entry for entry in entries}
    initial = [by_id[identity] for identity in batches[0]]
    options = {"allowed_tools": artifact["allowed_tools"]}
    learner = learn_from_verified_bundles
    if artifact["schema"] == action_recipe.CHOICE_SCHEMA:
        learner = learn_choice_from_verified_bundles
    elif artifact["schema"] in action_recipe.WORKFLOW_SCHEMAS:
        learner = (learn_memory_from_verified_bundles if artifact["schema"] == action_recipe.MEMORY_SCHEMA
                   else learn_transducer_from_verified_bundles)
        options["max_steps"] = artifact["max_steps"]
    if artifact["schema"] in {action_recipe.TRANSFORM_SCHEMA, action_recipe.CHOICE_SCHEMA,
                             *action_recipe.WORKFLOW_SCHEMAS}:
        grammar = artifact["grammar"]
        options.update(domain=artifact["domain"], max_operations=grammar["max_operations"],
                       operators=grammar["operators"], constants=grammar["constants"])
    rebuilt = learner([entry[1] for entry in initial], trust=trust,
        expected_tenant=expected_tenant, now=now, **options)
    cumulative = set(batches[0])
    for index, batch in enumerate(batches[1:]):
        parent = {"package_sha256": rebuilt["package_sha256"],
                  "artifact_sha256": rebuilt["artifact"]["artifact_sha256"]}
        if package["ancestors"][index] != parent:
            raise ValueError("lineage parent package commitment changed")
        refined = action_recipe.refine(rebuilt["artifact"], [by_id[identity][2]["body"]["episode"] for identity in batch])
        cumulative.update(batch)
        rebuilt = _assemble(refined, [entry for entry in entries if entry[0] in cumulative],
                            batches[:index + 2], [*rebuilt["ancestors"], parent])
    if _canonical(rebuilt) != _canonical(package):
        raise ValueError("lineage package does not match its complete signed evidence derivation")
    return rebuilt


def validate_package(package, *, trust, expected_tenant, now):
    """Reverify signatures and reconstruct every ancestor and all alternatives."""
    _rebuild(package, trust=trust, expected_tenant=expected_tenant, now=now)


def refine_package(package, new_bundles, *, trust, expected_tenant, now):
    original = _rebuild(package, trust=trust, expected_tenant=expected_tenant, now=now)
    if type(new_bundles) is not list or not new_bundles:
        raise ValueError("refinement requires new signed reviewed evidence")
    entries = _verified([*original["bundles"], *new_bundles], trust=trust, expected_tenant=expected_tenant, now=now)
    old_ids = {entry["episode_id"] for entry in original["manifest"]}
    new = [entry for entry in entries if entry[0] not in old_ids]
    refined = action_recipe.refine(original["artifact"], [entry[2]["body"]["episode"] for entry in new])
    parent = {"package_sha256": original["package_sha256"], "artifact_sha256": original["artifact"]["artifact_sha256"]}
    return _assemble(refined, entries, [*original["batches"], [entry[0] for entry in new]],
                     [*original["ancestors"], parent])


def _identifier(tenant, owner, package_sha256):
    return "LRA-" + digest({"tenant": tenant, "owner": owner, "package_sha256": package_sha256})[:32]


def _reference(row):
    return {"schema": REFERENCE_SCHEMA, "id": row["id"], "package_sha256": row["package_sha256"],
            "artifact_sha256": row["artifact_sha256"]}


def validate_reference(reference, artifact):
    """Structural binding only; current eligibility requires runtime_reference."""
    if (type(reference) is not dict or set(reference) != {"schema", "id", "package_sha256", "artifact_sha256"}
            or reference["schema"] != REFERENCE_SCHEMA or type(reference["id"]) is not str
            or not _ID.fullmatch(reference["id"])):
        raise ValueError("invalid recipe lineage admission reference")
    _hash(reference["package_sha256"])
    _hash(reference["artifact_sha256"])
    action_recipe.validate_artifact(artifact)
    if reference["artifact_sha256"] != artifact["artifact_sha256"]:
        raise ValueError("lineage reference belongs to a different recipe artifact")


def _gate(artifact=None):
    from ..config import get_flows
    from ..learning_guard import check_learning_halt
    from . import enabled

    flags = get_flows()
    if not enabled() or flags.get("action_recipe_lineage") is not True:
        raise PermissionError("governed recipe lineage is disabled")
    if (type(artifact) is dict and artifact.get("schema") in action_recipe.WORKFLOW_SCHEMAS
            and any(flags.get(key) is not True for key in
                    ("action_recipes", "action_recipe_transforms", "action_workflow_learning"))):
        raise PermissionError("governed workflow transducer learning is disabled")
    if (type(artifact) is dict and artifact.get("schema") == action_recipe.MEMORY_SCHEMA
            and flags.get("action_workflow_memory_learning") is not True):
        raise PermissionError("governed workflow memory learning is disabled")
    check_learning_halt("flow_recipe_lineage", "current_eligibility")


def _seal(row, payload):
    if not crypto_at_rest.at_rest_enabled():
        raise crypto_at_rest.EncryptionUnavailable("recipe lineage requires encrypted retention")
    envelope = {"schema": ENVELOPE_SCHEMA, "metadata_sha256": digest({key: row[key] for key in _META}),
                "payload": payload}
    token = crypto_at_rest.seal_to_str(_canonical(envelope))
    if not crypto_at_rest.is_sealed_str(token):
        raise crypto_at_rest.EncryptionUnavailable("lineage encryption did not produce ciphertext")
    row["sensitive_envelope"] = token


def _open(ctx, row):
    if (row.get("schema") != ADMISSION_SCHEMA or row.get("tenant_sha256") != digest(ctx.tenant)
            or row.get("owner") != ctx.resource_owner
            or row.get("id") != _identifier(ctx.tenant, ctx.resource_owner, row.get("package_sha256"))):
        raise PermissionError("lineage admission belongs to another tenant or owner")
    if row.get("payload_revision") != row.get("revision", 1):
        raise ValueError("lineage encrypted revision binding changed")
    if row.get("status") == "expired":
        if "sensitive_envelope" in row:
            raise ValueError("expired lineage retained sensitive content")
        return None
    if row.get("status") != "admitted" or not crypto_at_rest.is_sealed_str(row.get("sensitive_envelope")):
        raise ValueError("lineage admission requires a sealed admitted envelope")
    envelope = json.loads(crypto_at_rest.unseal_from_str(row["sensitive_envelope"]))
    _canonical(envelope)
    if (type(envelope) is not dict or set(envelope) != {"schema", "metadata_sha256", "payload"}
            or envelope["schema"] != ENVELOPE_SCHEMA
            or envelope["metadata_sha256"] != digest({key: row[key] for key in _META})):
        raise ValueError("lineage encrypted envelope binding changed")
    payload = envelope["payload"]
    if type(payload) is not dict or set(payload) != {"package", "authority"}:
        raise ValueError("invalid lineage encrypted payload")
    package = payload["package"]
    material = {key: value for key, value in package.items() if key != "package_sha256"}
    if (_digest(material) != row["package_sha256"] or package.get("package_sha256") != row["package_sha256"]
            or package.get("owner") != ctx.resource_owner or package.get("tenant") != ctx.tenant
            or package.get("use_until") != row["use_until"] or package.get("issuer") != row["issuer"]
            or package["artifact"]["artifact_sha256"] != row["artifact_sha256"]
            or digest(payload["authority"]) != row["authority_sha256"]):
        raise ValueError("lineage retained package commitment changed")
    return payload


class RecipeLineageService:
    """Fresh authoritative callbacks and encrypted CAS/outbox admission.

    Callback signature is authorize(ctx, capability, resource) -> literal True.
    Recipe capabilities use package digest/admission ID. flow.episode.current
    uses each source Flow ID. No caller-provided verification flag is trusted.
    """
    def __init__(self, authorize, *, records=None, clock=time.time):
        if not callable(authorize) or not callable(clock):
            raise TypeError("lineage requires authoritative authorization and clock callbacks")
        self.authorize = authorize
        self.records = _RECORDS if records is None else records
        self.clock = clock

    def _permit(self, ctx, capability, resource, *, human=False):
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        if (human and ctx.human is not True) or self.authorize(ctx, capability, resource) is not True:
            audit_authority_denial(ctx, capability, resource, "lineage_authority_denied")
            raise PermissionError("current authority denied recipe lineage access")

    def _recover(self, row):
        if row.get("_audit_pending"):
            self.records.retry_pending(limit=MAX_RECORDS)
            row = self.records.get(row["id"])
            if row is None:
                raise LookupError("lineage admission is unavailable")
        return row

    def _current(self, ctx, package):
        from .action_episode_review import ActionEpisodeReviewService
        from .action_provenance import digest as trust_digest
        from .action_provenance import local_trust

        if package["tenant"] != ctx.tenant or package["owner"] != ctx.resource_owner:
            raise PermissionError("lineage package belongs to another tenant or owner")
        _gate(package["artifact"])
        trust = local_trust(ctx.tenant)
        policy_sha256 = trust_digest(trust)
        _rebuild(package, trust=trust, expected_tenant=ctx.tenant, now=self.clock())
        service = ActionEpisodeReviewService(self.authorize, clock=self.clock)
        for bundle in package["bundles"]:
            checked = service.assert_bundle_current(ctx, bundle)
            if (checked.get("live_status") != "accepted" or checked.get("trust_sha256") != policy_sha256):
                raise RecipeLineageConflict("reviewed source is no longer eligible")
        if trust_digest(local_trust(ctx.tenant)) != policy_sha256:
            raise RecipeLineageConflict("evidence trust policy changed during eligibility check")
        _gate(package["artifact"])
        return {"checked_at": self.clock(), "trust_sha256": policy_sha256, "issuer": trust["issuer"]}

    def _present(self, row, *, package=None, checked_at=None, detail=False):
        result = {key: copy.deepcopy(row[key]) for key in
                  ("schema", "id", "revision", "owner", "package_sha256", "artifact_sha256", "issuer", "use_until")}
        result.update(status=row["status"], audit_status="delivered", reference=_reference(row))
        if row.get("_audit_pending"):
            result.update(status="audit_pending", committed_status=row["status"], audit_status="pending")
        elif checked_at is not None:
            result.update(current_eligibility="accepted", **checked_at)
            if detail:
                result["package"] = copy.deepcopy(package)
        return result

    def _load(self, ctx, identity, capability, *, human=False):
        if type(identity) is not str or not _ID.fullmatch(identity):
            raise ValueError("invalid lineage admission ID")
        self._permit(ctx, capability, identity, human=human)
        row = self.records.get(identity)
        if row is None:
            raise LookupError("lineage admission is unavailable")
        _open(ctx, row)
        row = self._recover(row)
        payload = _open(ctx, row)
        self._permit(ctx, capability, identity, human=human)
        if row["status"] != "expired" and self.clock() >= row["use_until"] and not row.get("_audit_pending"):
            def expire(current):
                _open(ctx, current)
                self._permit(ctx, capability, identity, human=human)
                current.update(status="expired", payload_revision=current["revision"] + 1)
                current.pop("sensitive_envelope", None)
            row = self.records.update(identity, expire, expected_revision=row["revision"],
                                      action="recipe_lineage_expired", actor=ctx.actor)
            if row is None:
                raise LookupError("lineage admission is unavailable")
            payload = None
        if row.get("_audit_pending") or payload is None:
            return row, None, None
        checked_at = self._current(ctx, payload["package"])
        self._permit(ctx, capability, identity, human=human)
        return row, payload["package"], checked_at

    def admit(self, ctx, package):
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        with tenant_scope(tenant=ctx.tenant):
            _gate()
            package = json.loads(_canonical(package))
            claimed = _hash(package.get("package_sha256"))
            if _digest({key: value for key, value in package.items() if key != "package_sha256"}) != claimed:
                raise ValueError("lineage package commitment changed")
            self._permit(ctx, "flow.recipe.admit", claimed, human=True)
            identity = _identifier(ctx.tenant, ctx.resource_owner, claimed)
            existing = self.records.get(identity)
            if existing is not None:
                # Recover the same committed outbox before checking later source
                # withdrawal/expiry; recovery never exposes raw package contents.
                _open(ctx, existing)
                existing = self._recover(existing)
                _open(ctx, existing)
                if existing.get("_audit_pending"):
                    return self._present(existing)
                if existing["status"] == "expired":
                    raise RecipeLineageConflict("lineage reuse grant expired")
                checked = self._current(ctx, package)
                return self._present(existing, checked_at=checked)
            current = self._current(ctx, package)
            row = {"schema": ADMISSION_SCHEMA, "id": identity, "tenant_sha256": digest(ctx.tenant),
                   "owner": ctx.resource_owner, "package_sha256": claimed,
                   "artifact_sha256": package["artifact"]["artifact_sha256"], "issuer": package["issuer"],
                   "use_until": package["use_until"], "status": "admitted", "payload_revision": 1,
                   "admitted_by": ctx.actor, "admitted_at": self.clock(), "authority_sha256": digest(ctx.binding()),
                   "admitted_trust_sha256": current["trust_sha256"]}
            _seal(row, {"package": package, "authority": ctx.binding()})
            self._permit(ctx, "flow.recipe.admit", claimed, human=True)
            if self._current(ctx, package)["trust_sha256"] != row["admitted_trust_sha256"]:
                raise RecipeLineageConflict("evidence trust policy changed before admission commit")
            try:
                saved = self.records.create(row, action="recipe_lineage_admitted", actor=ctx.actor, max_records=MAX_RECORDS)
            except RecordConflict:
                saved = self.records.get(identity)
                if saved is None:
                    raise
                _open(ctx, saved)
                saved = self._recover(saved)
            if saved.get("_audit_pending"):
                return self._present(saved)
            self._permit(ctx, "flow.recipe.admit", claimed, human=True)
            checked = self._current(ctx, package)
            return self._present(saved, checked_at=checked)

    def get(self, ctx, identity, *, detail=False):
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        if type(detail) is not bool:
            raise ValueError("detail must be a boolean")
        with tenant_scope(tenant=ctx.tenant):
            _gate()
            row, package, checked = self._load(ctx, identity, "flow.recipe.detail" if detail else "flow.recipe.read")
            return self._present(row, package=package, checked_at=checked, detail=detail)

    def draft(self, ctx, identity, *, flow_id, name, teaching=False):
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        if type(teaching) is not bool:
            raise ValueError("teaching must be a boolean")
        _text(flow_id, "flow_id")
        _text(name, "name")
        with tenant_scope(tenant=ctx.tenant):
            _gate()
            row, package, _checked = self._load(ctx, identity, "flow.recipe.draft", human=True)
            if row.get("_audit_pending"):
                raise RecipeLineageAuditPending(identity)
            if package is None:
                raise RecipeLineageConflict("lineage reuse grant expired")
            existing = store.load_flow(flow_id)
            if existing is not None and existing.owner != ctx.resource_owner:
                raise PermissionError("draft destination belongs to another owner")
            flow = recipe_flow.make_flow(package["artifact"], flow_id=flow_id, name=name, teaching=teaching)
            flow.owner = ctx.resource_owner
            result = flow.to_dict()
            result["recipe_lineage"] = _reference(row)
            if package["artifact"]["schema"] == action_recipe.MEMORY_SCHEMA:
                # The pure artifact ceiling does not enlarge native Flow storage.
                store._assert_safe_definition(result)
            self._permit(ctx, "flow.recipe.draft", identity, human=True)
            self._current(ctx, package)
            return result


def runtime_reference(reference, artifact, *, owner):
    """Check current local evidence using trusted tenant + pinned Flow owner.

    No caller identity or trusted keys are taken from the reference/package.
    Source checks happen before this return, not atomically with connector I/O.
    """
    validate_reference(reference, artifact)
    _text(owner, "owner")
    tenant = current_tenant_id_strict()
    if not tenant:
        raise PermissionError("governed recipe execution requires an explicit tenant")
    ctx = ServiceContext(tenant=tenant, actor=owner, resource_owner=owner, human=False,
                         credential_authority="native_recipe_lineage_runtime", credential_ref="not_applicable")

    def authorize(context, capability, resource):
        from ..tenant.registry import assert_tenant_active
        assert_tenant_active(tenant)
        if context != ctx or current_tenant_id_strict() != tenant:
            return False
        if capability == "flow.recipe.read":
            return resource == reference["id"]
        if capability == "flow.episode.current":
            source = store.load_flow(resource)
            return source is not None and source.owner == owner
        return False

    service = RecipeLineageService(authorize)
    with tenant_scope(tenant=tenant):
        _gate(artifact)
        row, package, checked = service._load(ctx, reference["id"], "flow.recipe.read")
        if row.get("_audit_pending"):
            raise RecipeLineageAuditPending(reference["id"])
        if package is None:
            raise RecipeLineageConflict("lineage reuse grant expired")
        if _reference(row) != reference or _canonical(package["artifact"]) != _canonical(artifact):
            raise RecipeLineageConflict("runtime recipe does not match its admitted evidence")
        return {"id": row["id"], "package_sha256": row["package_sha256"],
                "artifact_sha256": row["artifact_sha256"], "use_until": row["use_until"],
                **checked, "current_eligibility": "accepted"}
