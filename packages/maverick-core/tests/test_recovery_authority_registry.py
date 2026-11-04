"""Recovery authority coverage and intrinsic no-replay transformations."""
from __future__ import annotations

import ast
import hashlib
import json
import sqlite3
from pathlib import Path

from maverick import file_lock
from maverick import workspace_recovery as recovery
from maverick.channel_recovery import NAMESPACES as CHANNEL_NAMESPACES
from maverick.recovery_authorities import (
    APPLICATION_VALIDATED_JSON_AUTHORITY_POLICIES,
    AUTHORITY_SAMPLES,
    DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES,
    DYNAMIC_JSON_AUTHORITY_POLICIES,
    GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES,
    GLOBAL_START_JSON_AUTHORITY_POLICIES,
    NON_AUTHORIZING_GOVERNED_NAMESPACES,
    PERSONAL_PUSH_AUTHORITY_POLICIES,
    authority_policy,
)


def _write(root: Path, relative: str, value: object) -> Path:
    path = root.joinpath(*relative.split("/"))
    file_lock.ensure_private_directory(path.parent)
    file_lock.atomic_create_text(path, json.dumps(value, sort_keys=True))
    return path


def _canonical(value: object) -> tuple[str, str]:
    rendered = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return rendered, hashlib.sha256(rendered.encode("ascii")).hexdigest()


def test_canonical_authority_registry_covers_every_declared_store() -> None:
    for relative, expected in AUTHORITY_SAMPLES.items():
        sqlite = relative.endswith((".db", ".sqlite3"))
        assert authority_policy(relative, is_sqlite=sqlite) == expected
        assert authority_policy(relative.swapcase(), is_sqlite=sqlite) == expected
    assert authority_policy("ordinary.json", is_sqlite=False) is None
    assert authority_policy("ordinary.lock", is_sqlite=False) is None
    assert authority_policy("future-authority.lock", is_sqlite=True) == "unknown_sqlite"


def test_all_starter_team_stores_retain_recovery_authority(tmp_path: Path) -> None:
    expected = {
        "starter_team_setups": "starter_team_setup_authority",
        "starter_team_reviews": "starter_team_review_authority",
        "starter_team_cases": "starter_team_case_authority",
        "starter_team_schedules": "starter_team_schedule_authority",
        "starter_team_inbox": "starter_team_input_approval_authority",
        "starter_team_ticks": "starter_team_tick_receipt_authority",
        "starter_team_runtime": "starter_team_runtime_authority",
        "starter_team_runtime_reviews": "starter_team_runtime_review_authority",
        "starter_team_goal_bindings": "starter_team_goal_binding_authority",
    }
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    originals = {}
    policies = {}
    for namespace, policy in expected.items():
        assert GLOBAL_START_JSON_AUTHORITY_POLICIES[namespace] == policy
        assert GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES[f"{namespace}/recovered.json"] == policy
        assert namespace not in NON_AUTHORIZING_GOVERNED_NAMESPACES
        for relative in (
            f"{namespace}/recovered.json",
            f"tenants/acme/{namespace}/recovered.json",
            f"tenants/acme/{namespace}/archive/recovered.json",
        ):
            assert authority_policy(relative.swapcase(), is_sqlite=False) == policy
            assert authority_policy(relative + ".lock", is_sqlite=False) is None
            path = _write(stage, relative, {
                "id": "restored-record", "owner": "user:alice",
                "status": "approved", "idempotency_key": "consumed-before-backup",
            })
            originals[relative] = path.read_bytes()
            policies[relative] = policy

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == set()
    assert report["queued_work"]["automatic_replay_blocked"] is True
    assert report["protected_authority"]["classification_complete"] is True
    assert report["protected_authority"]["file_count"] == len(originals)
    assert report["protected_authority"]["classified_count"] == len(originals)
    assert {item["source"] for item in report["items"]} == set(originals)
    for item in report["items"]:
        relative = item["source"]
        assert item["prior_state"] == f"unclassified:{policies[relative]}"
        assert item["state"] == "unresolved"
        assert item["safe_state"] == "global_start_blocked"
        assert item["requires_external_readback"] is True
        assert item["content_sha256"] == hashlib.sha256(originals[relative]).hexdigest()
        assert (stage / relative).read_bytes() == originals[relative]


def test_retained_knowledge_rights_are_protected_recovery_authority(tmp_path: Path) -> None:
    relative = "tenants/acme/knowledge-rights-archive/recovered.json"
    assert authority_policy(relative, is_sqlite=False) == "knowledge_access_authority"
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    record = _write(stage, relative, {"schema": "lightwork.knowledge-rights-archive.v1"})
    original = record.read_bytes()

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == set()
    assert record.read_bytes() == original
    item, = [row for row in report["items"] if row["source"] == relative]
    assert item["prior_state"] == "unclassified:knowledge_access_authority"
    assert item["safe_state"] == "global_start_blocked"
    assert item["requires_external_readback"] is True


def test_non_authorizing_preferences_and_warnings_restore_as_data(tmp_path: Path) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    originals = {}
    for namespace in NON_AUTHORIZING_GOVERNED_NAMESPACES:
        relative = f"tenants/acme/{namespace}/record.json"
        path = _write(stage, relative, {"revision": 1, "owner": "user:alice"})
        originals[relative] = path.read_bytes()
        assert authority_policy(relative.swapcase(), is_sqlite=False) is None
        # A file's SQLite identity still wins over a data-only directory name.
        assert authority_policy(relative, is_sqlite=True) == "unknown_sqlite"

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == set()
    assert report["items"] == []
    assert report["protected_authority"]["classification_complete"] is True
    assert all((stage / relative).read_bytes() == payload for relative, payload in originals.items())


def test_shared_a2a_binding_is_retained_and_blocks_restored_admission(tmp_path: Path) -> None:
    """An opaque anti-downgrade receipt cannot be discarded as an ordinary cache."""
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    relative = "tenants/tenant-a/a2a/tasks.authority.sealed"
    marker = stage.joinpath(*relative.split("/"))
    file_lock.ensure_private_directory(marker.parent)
    file_lock.atomic_create_bytes(marker, b"opaque authenticated binding retained verbatim")
    original = marker.read_bytes()

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == set()
    assert marker.read_bytes() == original
    item, = [item for item in report["items"] if item["source"] == relative]
    assert item["safe_state"] == "global_start_blocked"
    assert item["prior_state"] == "unclassified:a2a_shared_authority_binding"
    assert item["requires_external_readback"] is True
    assert authority_policy(relative.swapcase(), is_sqlite=False) == "a2a_shared_authority_binding"
    assert authority_policy(relative + ".lock", is_sqlite=False) is None


def test_every_literal_local_governed_json_store_has_recovery_policy() -> None:
    """Make adding a default governed store without recovery policy fail CI."""
    packages = Path(__file__).parents[2]
    source_roots = (packages / "maverick-core" / "maverick",
                    packages / "maverick-channels" / "maverick_channels",
                    packages / "maverick-dashboard" / "maverick_dashboard")
    declarations: dict[str, str] = {}
    dynamic_declarations: set[str] = set()
    for source in (path for root in source_roots for path in root.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        constants = {
            target.id: node.value
            for node in tree.body if isinstance(node, ast.Assign)
            for target in node.targets if isinstance(target, ast.Name)
            and target.id.isupper() and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            name = (
                function.id
                if isinstance(function, ast.Name)
                else function.attr
                if isinstance(function, ast.Attribute)
                else ""
            )
            if name not in {"GovernedRecordStore", "_RecordStore"} or not node.args:
                continue
            namespace = node.args[0]
            if isinstance(namespace, ast.Name) and namespace.id in constants:
                namespace = constants[namespace.id]
            if not (
                isinstance(namespace, ast.Constant)
                and isinstance(namespace.value, str)
            ):
                # The reusable backend's ``_RecordStore(namespace, ...)`` call
                # receives a previously reviewed declaration; it is not a new
                # default store.  Every actual dynamic factory must be a known,
                # bounded expansion below.
                if source.name != "governed_records.py":
                    dynamic_declarations.add(ast.unparse(namespace))
                continue
            relative = f"{namespace.value}/recovered.json"
            declarations[relative] = f"{source.relative_to(packages)}:{node.lineno}"

    missing = {
        relative: location
        for relative, location in declarations.items()
        if relative.split("/")[0] not in NON_AUTHORIZING_GOVERNED_NAMESPACES
        and authority_policy(relative, is_sqlite=False) is None
    }
    assert missing == {}
    for namespace in NON_AUTHORIZING_GOVERNED_NAMESPACES:
        assert f"{namespace}/recovered.json" in declarations
        assert authority_policy(f"{namespace}/recovered.json", is_sqlite=False) is None
    for namespace, policy in GLOBAL_START_JSON_AUTHORITY_POLICIES.items():
        relative = f"{namespace}/recovered.json"
        assert relative in declarations
        assert GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES[relative] == policy
    for namespace, policy in APPLICATION_VALIDATED_JSON_AUTHORITY_POLICIES.items():
        relative = f"{namespace}/recovered.json"
        assert relative in declarations
        assert authority_policy(relative, is_sqlite=False) == policy
        assert relative not in GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES
    assert dynamic_declarations == {
        "f'identity_governance_{sink}_outcomes'",
        "f'identity_governance_{sink}_requests'",
        "'conversation-organization-' + context_for(request)",
        # personal_push_devices.store: "<kind>-<32 hex owner digest>".
        "kind + '-' + scope",
    }
    for kind, policy in PERSONAL_PUSH_AUTHORITY_POLICIES.items():
        relative = f"{kind}-{'c' * 32}/recovered.json"
        assert authority_policy(relative, is_sqlite=False) == policy
        assert authority_policy(relative.upper(), is_sqlite=False) == policy
        assert GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES[relative] == policy
        # Only the exact bounded expansion is classified this way.
        assert authority_policy(f"{kind}-short/recovered.json", is_sqlite=False) is None
    for namespace, policy in DYNAMIC_JSON_AUTHORITY_POLICIES.items():
        relative = f"{namespace}/recovered.json"
        assert authority_policy(relative, is_sqlite=False) == policy
        if policy == "identity_change_request":
            assert relative not in GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES
        else:
            assert GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES[relative] == policy


def test_untrusted_secret_and_derived_authorities_are_discarded_before_publication(
    tmp_path: Path,
) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    source_hashes: dict[str, str] = {}
    for index, relative in enumerate(DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES):
        path = stage.joinpath(*relative.split("/"))
        file_lock.ensure_private_directory(path.parent)
        # Deliberately use opaque/non-JSON bytes.  These stores are never
        # interpreted because no reviewed source custody can authenticate
        # secrets and replay-derived state must not influence the new install.
        payload = f"untrusted-restored-authority:{index}\x00".encode()
        file_lock.atomic_create_bytes(path, payload)
        source_hashes[relative] = hashlib.sha256(payload).hexdigest()

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == set(DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES)
    assert all(not stage.joinpath(*relative.split("/")).exists() for relative in removed)
    receipts = {item["source"]: item for item in report["items"]}
    assert set(receipts) == set(DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES)
    for relative, expected_policy in DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES.items():
        item = receipts[relative]
        assert item["content_sha256"] == source_hashes[relative]
        assert item["state"] == "resolved"
        assert item["requires_external_readback"] is False
        assert item["safe_source"] == {"kind": "absent"}
        if expected_policy == "privacy_identity_key_authority":
            assert item["category"] == "privacy_identity_key"
            assert item["safe_state"] == "discarded_rotation_required"
            assert item["disposition"] == "fresh_rotation_required"
        elif expected_policy == "browser_vault_credential_authority":
            assert item["category"] == "credential_custody"
            assert item["safe_state"] == "discarded_before_publication"
            assert item["disposition"] == "discarded_before_publication"
        else:
            assert item["category"] == "derived_learning_state"
            assert item["safe_state"] == "discarded_before_publication"
            assert item["disposition"] == "discarded_before_publication"
    assert report["protected_authority"]["classification_complete"] is True
    assert not any(
        item["safe_state"] == "global_start_blocked" for item in report["items"]
    )


def test_json_authorities_are_terminal_before_publication(tmp_path: Path) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    _write(stage, "flows/runs/run.json", {
        "run_id": "run-1", "status": "running", "human": {"approval": True},
        "decided_by": "old-admin", "revision": 1,
    })
    publication = _write(stage, "flows/published/flow.json", {"flow_id": "flow"})
    _write(stage, "flows/idempotency/claim.json", {"run_id": "run-1"})
    trust = _write(stage, "agent_trust.json", [{"id": "agent-a", "rest_token": "sha256:x"}])
    agents = _write(stage, "external_agents.json", {
        "agent-a": {
            "contained": False, "spent_dollars": 11.0,
            "executions": {
                "pending": {"status": "pending", "digest": "a" * 64},
                "executing": {"status": "executing", "digest": "b" * 64},
            },
        },
    })
    outbox = _write(stage, "channel_federation_outbox.json", {
        "items": [{"message": "digest-only fixture"}], "dropped": 2,
    })
    team_budget = _write(stage, "llm_gateway_team_budget/team_budget.json", {
        "schema": "lightwork.llm-gateway-team-budget.v1",
        "rows": {"team": {"window_started": 1.0, "requests": 1,
                            "prompt_tokens": 2, "completion_tokens": 3}},
    })
    mcp_budget = _write(stage, "mcp_sidecar/call_budget.json", {
        "schema": "lightwork.governed-mcp-sidecar-budget.v1",
        "rows": {"principal": {"window_started": 1.0, "count": 2}},
    })
    _write(stage, "pilot_learning_exclusions/PLE-a.json", {
        "id": "PLE-a", "revision": 1, "goal_id": 1,
    })
    marker = stage / "pilot_learning_exclusions" / "PLE-a.required"
    file_lock.atomic_create_text(marker, "local pilot learning exclusion v1\n")
    scheduler = _write(stage, "identity_governance_scheduler/IGS-a.json", {
        "id": "IGS-a", "revision": 1, "pending_changes": [{"change": "x"}],
        "callback_attempts": 1, "callback_lease": {"token_sha256": "a" * 64},
    })
    delivery = _write(stage, "identity_governance_change_coupling/IGCC-a.json", {
        "id": "IGCC-a", "revision": 1, "status": "pending", "health": "healthy",
        "deliveries": {
            "alert": {"status": "pending", "attempts": 0},
            "dynamic_risk": {"status": "delivering", "attempts": 1},
        },
    })
    purview = _write(stage, "identity_governance_purview_writeback/IGPW-a.json", {
        "id": "IGPW-a", "revision": 1, "status": "applying", "attempts": 1,
        "compensation_attempts": 0, "operation_claim": {"operation": "apply"},
    })
    registry = _write(stage, "identity_governance_authority_registry/IGAR-a.json", {
        "id": "IGAR-a", "revision": 1, "status": "active", "kind": "agent_authority",
        "tenant_sha256": "a" * 64, "payload": {"tenant_sha256": "a" * 64},
        "payload_sha256": "b" * 64,
    })
    request = _write(stage, "identity_governance_alert_requests/IGRQ-a.json", {
        "id": "IGRQ-a", "revision": 1,
        "status": "pending_human_or_service_assessment",
        "provider_write_performed": False,
    })
    schedule = _write(stage, "red_team_schedules/RTS-a.json", {
        "id": "RTS-a", "revision": 1, "status": "active",
        "pending_run": {"lease_expires_at": 2.0},
    })
    campaign = _write(stage, "red_team_campaigns/RTC-a.json", {
        "id": "RTC-a", "revision": 1, "status": "running",
        "case_leases": {"case": {"completed_at": None}},
    })
    _write(stage, "red_team_results/RTR-a.json", {
        "id": "RTR-a", "revision": 1, "status": "passed",
    })

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert {"flows/published/flow.json", "agent_trust.json",
            "identity_governance_scheduler/IGS-a.json"}.issubset(removed)
    assert not publication.exists() and not trust.exists() and not scheduler.exists()
    run = json.loads((stage / "flows/runs/run.json").read_text())
    assert run["status"] == "indeterminate" and run["human"] == {}
    enrolled = json.loads(agents.read_text())["agent-a"]
    assert enrolled["contained"] is True
    assert enrolled["spent_dollars"] == 11.0
    assert enrolled["executions"]["pending"]["status"] == "denied"
    assert enrolled["executions"]["executing"]["status"] == "failed"
    assert json.loads(outbox.read_text())["items"] == []
    assert json.loads(team_budget.read_text())["rows"]["team"]["requests"] == 2**63 - 1
    assert json.loads(mcp_budget.read_text())["rows"]["principal"]["count"] == 2**63 - 1
    changed_delivery = json.loads(delivery.read_text())
    assert changed_delivery["deliveries"]["alert"]["status"] == "bootstrap_reauthorization_required"
    assert changed_delivery["deliveries"]["dynamic_risk"]["status"] == "bootstrap_reconciliation_required"
    assert json.loads(purview.read_text())["status"] == "bootstrap_reconciliation_required"
    assert json.loads(registry.read_text())["status"] == "purged"
    assert json.loads(request.read_text())["status"] == "bootstrap_reauthorization_required"
    assert json.loads(schedule.read_text())["status"] == "cancelled"
    changed_campaign = json.loads(campaign.read_text())
    assert changed_campaign["status"] == "cancelled"
    assert changed_campaign["case_leases"]["case"]["cancelled_at"] > 0
    assert report["protected_authority"]["classification_complete"] is True
    assert not any(
        item["safe_state"] == "global_start_blocked" for item in report["items"]
    )
    assert all("safe_source" in item for item in report["items"])


def test_rollback_sensitive_replay_and_consent_authorities_block_startup(
    tmp_path: Path,
) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    paths = {
        "federation/channel_replay.json": {"claims": {"message": 1}},
        "federation/channel_rate.json": {"windows": {"peer": 1}},
        "handoff_nonces.json": {"used": ["nonce"]},
        "consent.ledger": {"grants": [{"state": "active"}]},
        "consent.ledger.key": {"key": "fixture"},
    }
    for relative, value in paths.items():
        _write(stage, relative, value)

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == set()
    blockers = {
        item["source"]: item
        for item in report["items"]
        if item["safe_state"] == "global_start_blocked"
    }
    assert set(paths) <= set(blockers)
    assert all(blockers[path]["requires_external_readback"] for path in paths)
    assert all((stage / path).exists() for path in paths)
    assert report["protected_authority"]["classification_complete"] is True


def test_every_unreconciled_authority_blocks_global_start_until_disposed(
    tmp_path: Path,
) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    for relative in GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES:
        if relative.endswith(".sqlite3"):
            path = stage / relative
            file_lock.ensure_private_directory(path.parent)
            file_lock.atomic_create_bytes(path, b"")
            connection = sqlite3.connect(path)
            try:
                connection.execute("CREATE TABLE restored(id TEXT)")
                connection.commit()
            finally:
                connection.close()
        else:
            _write(stage, relative, {"restored": True})

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == set()
    blockers = {
        item["source"]: item
        for item in report["items"]
        if item["safe_state"] == "global_start_blocked"
    }
    assert set(blockers) == set(GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES)
    for relative, expected_policy in GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES.items():
        item = blockers[relative]
        namespace = relative.split("/", 1)[0]
        expected_prior = (f"unreadable_{namespace}" if namespace in CHANNEL_NAMESPACES
                          else f"unclassified:{expected_policy}")
        assert item["prior_state"] == expected_prior
        assert item["requires_external_readback"] is True
        assert item["state"] == "unresolved"
        assert (stage / relative).exists()
    assert report["protected_authority"] == {
        "file_count": len(GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES),
        "classified_count": len(GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES),
        "classification_complete": True,
        "state_sha256": report["protected_authority"]["state_sha256"],
        "disposition": "current_authority_and_external_readback_required",
    }


def test_restored_collection_and_organization_receipts_remain_held_and_unchanged(
    tmp_path: Path,
) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    expected = {}
    for prefix in ("", "tenants/tenant-a/"):
        collection = prefix + "billing/stripe-collections/period.json"
        holds = prefix + "usage/provider_holds.json"
        _write(stage, collection, {"schema": 1, "items": {"item-a": {"state": "unknown"}}})
        _write(stage, holds, {"version": 1, "calls": {"call-a": {"state": "unknown"}}})
        expected[collection] = "stripe_collection_authority"
        expected[holds] = "organization_provider_holds"
        for stem in ("provider_holds", "provider_history"):
            marker = prefix + f"usage/{stem}.required"
            file_lock.atomic_create_text(stage / marker, "organization provider authority v1\n")
            expected[marker] = f"organization_{stem}_required"
        history = prefix + "usage/provider_history.sqlite3"
        database = stage / history
        file_lock.atomic_create_bytes(database, b"")
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE calls(id TEXT PRIMARY KEY, data TEXT)")
            connection.execute("INSERT INTO calls VALUES(?, ?)",
                               ("call-a", '{"released":true,"state":"settled"}'))
            connection.commit()
        finally:
            connection.close()
        expected[history] = "organization_provider_history"
    original = {relative: (stage / relative).read_bytes() for relative in expected}

    removed, report = recovery._reconcile_bootstrap_stage(stage)

    assert removed == set()
    assert {item["source"] for item in report["items"]} == set(expected)
    for item in report["items"]:
        relative = item["source"]
        assert item["prior_state"] == f"unclassified:{expected[relative]}"
        assert item["safe_state"] == "global_start_blocked"
        assert item["state"] == "unresolved"
        assert item["requires_external_readback"] is True
        assert (stage / relative).read_bytes() == original[relative]
        assert authority_policy(relative.swapcase(), is_sqlite=relative.endswith(".sqlite3")) == expected[relative]
        assert authority_policy(relative + ".lock", is_sqlite=False) is None
    assert report["protected_authority"]["classification_complete"] is True


def test_world_approvals_are_invalidated_but_attempt_receipts_remain(tmp_path: Path) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    database = stage / "world.db"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE approvals(
                id INTEGER PRIMARY KEY, action TEXT, risk TEXT, status TEXT,
                requested_at REAL, decided_at REAL, claimed_by TEXT,
                claimed_at REAL, decided_by TEXT
            );
            CREATE TABLE approval_signoffs(approval_id INTEGER, approver TEXT);
            CREATE TABLE provider_operation_attempts(
                scope_sha256 TEXT, operation_id TEXT, attempt_no INTEGER,
                PRIMARY KEY(scope_sha256,operation_id,attempt_no)
            );
            CREATE TABLE goals(
                id INTEGER PRIMARY KEY, title TEXT, status TEXT,
                updated_at REAL, result TEXT, execution_principal TEXT
            );
            INSERT INTO approvals VALUES(1,'send','high','pending',1,NULL,NULL,NULL,NULL);
            INSERT INTO approvals VALUES(2,'write','high','approved',1,2,'worker',2,'admin');
            INSERT INTO provider_operation_attempts VALUES('scope','operation',1);
            INSERT INTO goals VALUES(1,'not started','pending',1,NULL,'agent:a');
            INSERT INTO goals VALUES(2,'may have run','active',2,NULL,'agent:b');
        """)
    _, report = recovery._reconcile_bootstrap_stage(stage)
    with sqlite3.connect(database) as connection:
        assert dict(connection.execute("SELECT id,status FROM approvals")) == {
            1: "denied", 2: "denied",
        }
        assert connection.execute(
            "SELECT COUNT(*) FROM provider_operation_attempts"
        ).fetchone()[0] == 1
        assert dict(connection.execute("SELECT id,status FROM goals")) == {
            1: "blocked", 2: "blocked",
        }
    approvals = [
        item for item in report["items"] if item["category"] == "approval_authority"
    ]
    assert len(approvals) == 2
    assert next(item for item in approvals if item["record_id"] == "1")["state"] == "resolved"
    assert next(item for item in approvals if item["record_id"] == "2")["requires_external_readback"] is True
    goals = [
        item for item in report["items"] if item["category"] == "goal_execution"
    ]
    assert len(goals) == 2
    assert next(item for item in goals if item["record_id"] == "1")["state"] == "resolved"
    assert next(item for item in goals if item["record_id"] == "2")["requires_external_readback"] is True


def test_privacy_queue_and_callback_leases_are_held(tmp_path: Path) -> None:
    stage = file_lock.ensure_private_directory(tmp_path / "stage")
    automation = file_lock.ensure_private_directory(stage / "privacy_automation")
    discovery = automation / "privacy-data-discovery.sqlite3"
    with sqlite3.connect(discovery) as connection:
        connection.executescript("""
            CREATE TABLE schedules(tenant_id TEXT,schedule_id TEXT,active INTEGER,
                payload_json TEXT,integrity_sha256 TEXT);
            CREATE TABLE jobs(tenant_id TEXT,job_id TEXT,state TEXT,next_attempt_at REAL,
                lease_until REAL,payload_json TEXT,integrity_sha256 TEXT);
            CREATE TABLE operations(id TEXT);
        """)
        schedule = {"active": True, "revision": 1, "updated_at": 1.0}
        raw, digest = _canonical(schedule)
        connection.execute("INSERT INTO schedules VALUES(?,?,?,?,?)",
                           ("tenant", "schedule", 1, raw, digest))
        for state in ("queued", "leased"):
            payload = {
                "job_id": state, "state": state, "next_attempt_at": 1.0,
                "lease_owner": "worker" if state == "leased" else None,
                "lease_until": 99.0 if state == "leased" else None,
                "revision": 1, "last_error_code": None,
            }
            raw, digest = _canonical(payload)
            connection.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?)",
                               ("tenant", state, state, 1.0,
                                payload["lease_until"], raw, digest))

    remediation = automation / "privacy-discovery-remediation.sqlite3"
    with sqlite3.connect(remediation) as connection:
        connection.executescript("""
            CREATE TABLE remediation_work(tenant_sha256 TEXT,work_id TEXT,state TEXT,
                next_attempt_at REAL,lease_until REAL,revision INTEGER,
                payload_json TEXT,integrity_sha256 TEXT);
            CREATE TABLE remediation_history(tenant_sha256 TEXT,work_id TEXT,
                revision INTEGER,state TEXT,payload_json TEXT,integrity_sha256 TEXT,
                PRIMARY KEY(tenant_sha256,work_id,revision));
            CREATE TABLE remediation_operations(id TEXT);
        """)
        for state in ("queued", "leased"):
            payload = {
                "state": state, "next_attempt_at": 1.0,
                "lease_until": 99.0 if state == "leased" else None,
                "lease_owner_sha256": "a" * 64 if state == "leased" else None,
                "lease_token_sha256": "b" * 64 if state == "leased" else None,
                "revision": 1, "updated_at": 1.0,
                "last_error_code": None, "ambiguous_at": None,
                "previous_integrity_sha256": "0" * 64,
            }
            raw, digest = _canonical(payload)
            connection.execute("INSERT INTO remediation_work VALUES(?,?,?,?,?,?,?,?)",
                               ("tenant", state, state, 1.0,
                                payload["lease_until"], 1, raw, digest))

    _, report = recovery._reconcile_bootstrap_stage(stage)
    with sqlite3.connect(discovery) as connection:
        assert dict(connection.execute("SELECT job_id,state FROM jobs")) == {
            "queued": "dead_letter", "leased": "dead_letter",
        }
        assert connection.execute("SELECT active FROM schedules").fetchone()[0] == 0
    with sqlite3.connect(remediation) as connection:
        assert dict(connection.execute(
            "SELECT work_id,state FROM remediation_work"
        )) == {"queued": "cancelled", "leased": "ambiguous"}
        assert connection.execute(
            "SELECT COUNT(*) FROM remediation_history"
        ).fetchone()[0] == 2
    unresolved = {
        (item["category"], item["record_id"])
        for item in report["items"] if item["state"] == "unresolved"
    }
    assert ("privacy_discovery_job", "leased") in unresolved
    assert ("privacy_remediation", "leased") in unresolved
    assert ("privacy_discovery_job", "queued") not in unresolved
    assert ("privacy_remediation", "queued") not in unresolved


def test_installation_passphrases_and_link_signing_key_are_protected_authority() -> None:
    """Colleague sign-in passphrases, their reset links and the mute-link signing key are retained
    restore blockers, never ordinary data, replayed state or discarded bytes."""
    expected = {
        "dashboard-passphrases.json": "dashboard_local_passphrases",
        "dashboard-passphrase-resets.json": "dashboard_passphrase_resets",
        "notification-links/signing.key": "notification_link_signing_key",
        "privacy_automation/discovery-data-use-key.sealed": "privacy_discovery_data_use_key",
    }
    for relative, policy in expected.items():
        assert authority_policy(relative, is_sqlite=False) == policy
        assert authority_policy(relative.upper(), is_sqlite=False) == policy
        assert GLOBAL_START_BLOCKED_AUTHORITY_SAMPLES[relative] == policy
        assert relative not in DISCARD_BEFORE_PUBLICATION_AUTHORITY_SAMPLES
    assert authority_policy("notification-links/signing.key.lock", is_sqlite=False) is None
    assert authority_policy("other/signing.key", is_sqlite=False) is None
