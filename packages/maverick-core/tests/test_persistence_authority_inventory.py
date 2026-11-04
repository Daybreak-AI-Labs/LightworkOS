"""Keep the reviewed persistence map closed without treating every write as authority."""
from __future__ import annotations

import ast
import json
from pathlib import Path

from maverick.recovery_authorities import NON_AUTHORIZING_GOVERNED_NAMESPACES, authority_policy

ROOT = Path(__file__).parents[3]
INVENTORY = ROOT / "docs/operations/persistence-authorities.json"
PERSISTENCE_SEAMS = frozenset({
    "data_dir", "maverick_home", "GovernedRecordStore", "_RecordStore", "connect", "commit",
    "executemany", "cross_process_lock", "atomic_write_text", "atomic_write_bytes",
    "atomic_create_text", "atomic_create_bytes", "atomic_create_bytes_chunks", "atomic_write_text_chunks",
    "atomic_write_bytes_chunks", "open_private_append", "write_text", "write_bytes",
})


def _inventory():
    return json.loads(INVENTORY.read_text(encoding="utf-8"))


def test_inventory_is_closed_and_preserves_single_owner_deployment_boundary():
    data = _inventory()
    assert data["schema"] == "lightwork.persistence-authority-inventory.v1"
    assert data["singleton_required"] is True
    assert data["high_availability_qualified"] is False
    entries = data["entries"]
    assert len({entry["path"] for entry in entries}) == len(entries)
    for entry in entries:
        assert (ROOT / entry["path"]).is_file()
        contract = data["contracts"][entry["contract"]]
        assert all(contract[key] for key in ("owner", "transactions", "migration", "recovery", "limits"))
        assert entry["owner"] and entry["purpose"] and entry["review"]
        assert all(site["line"] > 0 and site["function"] for site in entry["source_sites"])


def test_contract_counts_match_the_entries():
    data = _inventory()
    tally: dict[str, int] = {}
    for entry in data["entries"]:
        tally[entry["contract"]] = tally.get(entry["contract"], 0) + 1
    assert data["counts"] == tally


def test_all_governed_store_declarations_have_semantic_owner_and_recovery_disposition():
    data = _inventory()
    entries = {entry["path"]: entry for entry in data["entries"]}
    seen_preferences = False
    roots = [ROOT / "packages" / package / module for package, module in (
        ("maverick-core", "maverick"), ("maverick-dashboard", "maverick_dashboard"),
        ("maverick-channels", "maverick_channels"), ("maverick-evolve", "maverick_evolve"),
        ("maverick-knowledge", "maverick_knowledge"), ("maverick-mcp", "maverick_mcp"),
        ("maverick-shield", "maverick_shield"),
    )] + [ROOT / "apps/installer-cli/maverick_installer", ROOT / "apps/installer-msi"]
    for source_root in roots:
        for source in source_root.rglob("*.py"):
            if source.name.startswith("test_") or "fixtures" in source.parts or "tests" in source.parts:
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"))
            constants = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
                         for target in node.targets if isinstance(target, ast.Name) and target.id.isupper()
                         and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
                relative = source.relative_to(ROOT).as_posix()
                if name in PERSISTENCE_SEAMS:
                    assert relative in entries, f"Classify new persistence seam (which may be data/cache/output): {relative}"
                if name not in {"GovernedRecordStore", "_RecordStore"} or not node.args:
                    continue
                assert relative in entries, f"Classify the new store owner: {relative}"
                namespace = node.args[0]
                if isinstance(namespace, ast.Name) and namespace.id in constants:
                    namespace = constants[namespace.id]
                if not isinstance(namespace, ast.Constant) or not isinstance(namespace.value, str):
                    continue  # Narrow dynamic factories remain covered by the closed recovery registry test.
                namespace = namespace.value
                declared = {item["namespace"]: item for item in entries[relative]["governed_namespaces"]}
                assert namespace in declared, f"Classify the new namespace: {relative}: {namespace}"
                policy = authority_policy(namespace + "/record.json", is_sqlite=False)
                if namespace == "action_center_preferences":
                    assert relative == "packages/maverick-dashboard/maverick_dashboard/action_center.py"
                    assert entries[relative]["contract"] == "preferences"
                    assert policy is None  # Read/snooze UI preferences cannot authorize the source work.
                    seen_preferences = True
                elif namespace in NON_AUTHORIZING_GOVERNED_NAMESPACES:
                    assert policy is None
                    assert entries[relative]["contract"] in {"preferences", "mixed_api", "derived_analytics"}
                else:
                    assert policy is not None, f"Missing restore disposition: {namespace}"
                assert declared[namespace]["recovery_policy"] == policy
    assert seen_preferences


def test_knowledge_rights_archive_has_an_explicit_retained_owner_and_policy():
    entries = {entry["path"]: entry for entry in _inventory()["entries"]}
    knowledge = entries["packages/maverick-core/maverick/knowledge_access.py"]
    archived = [item for item in knowledge["governed_namespaces"]
                if item["namespace"] == "knowledge-rights-archive"]
    assert len(archived) == 1
    assert archived[0]["recovery_policy"] == "knowledge_access_authority"
    assert authority_policy("knowledge-rights-archive/recovered.json", is_sqlite=False) == (
        "knowledge_access_authority"
    )


def test_high_risk_authorities_and_non_authority_counterexamples_stay_distinct():
    entries = {entry["path"]: entry for entry in _inventory()["entries"]}
    core = "packages/maverick-core/maverick/"
    expected = {
        "world_model.py": "world", "a2a_store.py": "a2a", "a2a_migration.py": "a2a",
        "cli/_a2a_groups.py": "a2a", "governed_record_batch.py": "storage_primitive",
        "postgres_io.py": "storage_primitive", "learning_store_pg_schema.py": "storage_primitive",
        "form_store.py": "execution", "oauth_vault.py": "configuration", "self_improvement.py": "learning",
        "audit/signing.py": "audit", "ai_evidence_ledger.py": "audit", "flow/store.py": "execution",
        "flow/run_index.py": "derived", "governed_record_lookup.py": "derived", "semantic_recall.py": "derived",
        "consent_preferences.py": "sqlite_domain", "consent_scanner.py": "external",
        "tools/database_tool.py": "external", "tools/sql_query.py": "external",
        "duckdb_analytics.py": "external", "tools/document_processing.py": "transient",
        "support_bundle.py": "artifact", "crypto_at_rest.py": "key_custody",
        "channel_recovery.py": "recovery", "stripe_collection.py": "execution",
        "tenant/provider_admission.py": "execution", "tenant/_provider_archive.py": "sqlite_domain",
    }
    assert {path: entries[core + path]["contract"] for path in expected} == expected
    assert entries["packages/maverick-channels/maverick_channels/slack.py"]["contract"] == "governed"
    assert entries["packages/maverick-channels/maverick_channels/rich_render.py"]["contract"] == "artifact"


def test_reconciliation_and_provider_receipt_owners_have_explicit_path_dispositions():
    entries = {entry["path"]: entry for entry in _inventory()["entries"]}
    for owner in ("channel_recovery.py", "stripe_collection.py", "tenant/provider_admission.py",
                  "tenant/_provider_archive.py"):
        authorities = entries["packages/maverick-core/maverick/" + owner]["persisted_authorities"]
        assert authorities
        for authority in authorities:
            path = authority["sample_path"]
            assert authority_policy(path, is_sqlite=path.endswith(".sqlite3")) == authority["recovery_policy"]
            assert authority["disposition"]
