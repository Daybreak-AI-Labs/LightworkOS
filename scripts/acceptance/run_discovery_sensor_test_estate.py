"""Run the fixed, local consenting-estate discovery-sensor acceptance scope.

The runner uses the production reference normalizers, durable normalized-event
spool, detached Ed25519 client, reload-on-sign key file, and the in-process
consenting test estate.  Its evidence is deliberately digest-only: it contains
no raw source event, hostname, tenant identifier, agent identifier, consent
reference, public key, private key, or signature.

Passing this runner is local synthetic acceptance.  It is not evidence of an
external/customer deployment, enterprise completeness, production signing-key
custody, or privacy approval for any real estate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from maverick.ai_discovery_sensor_agents import (
    AGENT_CONFIG_SCHEMA,
    DiscoverySensorAgent,
    SensorAgentConfig,
    SensorAgentTransportError,
)
from maverick.ai_discovery_sensor_clients import (
    SensorBinding,
    SignedDiscoverySensorClient,
)
from maverick.ai_discovery_sensor_test_estate import ConsentingDiscoveryTestEstate
from maverick.file_lock import atomic_write_bytes, atomic_write_text

SCHEMA = "lightwork.discovery-sensor-test-estate-acceptance.v1"
SCALE_OBSERVATIONS = 1_000
CONCURRENT_WORKERS = 8
FIXED_TIME = 1_700_000_000.0
CONSENT_REFERENCE = "local-synthetic-consenting-discovery-estate-2026-08-28"
COVERAGE_LIMITATIONS = (
    "supplied_events_only",
    "reviewed_allowlist_only",
    "test_tenant_only",
    "no_enterprise_completeness_claim",
)
SOURCE_KINDS = ("network_egress", "browser_extension", "oauth_grant")
_TENANT_REF = "local-synthetic-tenant"
_SECOND_TENANT_REF = "local-synthetic-tenant-two"
_SENSOR_ID = "DSN-" + "a" * 32


class _Clock:
    def __init__(self, value: float = FIXED_TIME) -> None:
        self._value = value
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._value += seconds


class _AcceptThenLoseResponse:
    """Inject one ambiguous success without altering the estate contract."""

    def __init__(self, estate: ConsentingDiscoveryTestEstate) -> None:
        self._estate = estate
        self._armed = True

    def send(self, request):
        response = self._estate.send(request)
        if self._armed and 200 <= response.status_code < 300:
            self._armed = False
            raise SensorAgentTransportError("synthetic response loss after acceptance")
        return response


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _private_pem(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _config(work_directory: Path, source_kind: str) -> SensorAgentConfig:
    deployment_type = "hosted_api" if source_kind == "network_egress" else "saas"
    return SensorAgentConfig.from_mapping(
        {
            "schema": AGENT_CONFIG_SCHEMA,
            "enable": True,
            "consent_acknowledged": True,
            "consent_reference": CONSENT_REFERENCE,
            "source_kind": source_kind,
            "source_scope_code": f"local_synthetic_{source_kind}",
            "coverage_limitations": list(COVERAGE_LIMITATIONS),
            "endpoint_url": "http://127.0.0.1:8899",
            "allow_loopback_http": True,
            "key_file": str(work_directory / f"{source_kind}.pem"),
            "spool_file": str(work_directory / f"{source_kind}.sqlite"),
            "binding": {
                "tenant_ref": _TENANT_REF,
                "agent_id": f"local-{source_kind.replace('_', '-')}-sensor",
                "sensor_id": _SENSOR_ID,
                "sensor_revision": 1,
                "config_sha256": _digest(f"config:{source_kind}"),
            },
            "environment_code": "consenting_test",
            "deployment_type": deployment_type,
            "context_codes": ["managed_device"],
            "batch_size": 100,
            "max_pending": 2_000,
            "request_timeout_seconds": 5.0,
            "lease_seconds": 30.0,
            "base_backoff_seconds": 0.01,
        }
    )


def _event(source_kind: str, label: str) -> dict[str, Any]:
    common: dict[str, Any] = {
        "source_event_sha256": _digest(f"event:{source_kind}:{label}"),
        "observed_at": FIXED_TIME,
        "context_codes": ["approved_source"],
    }
    if source_kind == "network_egress":
        return {"hostname": "api.openai.com", **common}
    if source_kind == "browser_extension":
        return {
            **common,
            "provider_code": "microsoft",
            "ai_product_code": "copilot",
        }
    return {
        **common,
        "provider_code": "openai",
        "ai_product_code": "chatgpt",
    }


def _register(
    estate: ConsentingDiscoveryTestEstate,
    config: SensorAgentConfig,
    key: Ed25519PrivateKey,
) -> None:
    estate.register_sensor(
        agent_id=config.binding.agent_id,
        sensor_id=config.binding.sensor_id,
        tenant_ref=config.binding.tenant_ref,
        sensor_revision=config.binding.sensor_revision,
        config_sha256=config.binding.config_sha256,
        domain_category=config.source_kind,
        public_key=key.public_key(),
    )


def _source_result(config: SensorAgentConfig, report: object) -> dict[str, Any]:
    return {
        "initial_delivery_passed": report.delivered_events == 1,
        "initial_delivered_events": report.delivered_events,
        "consent_reference_sha256": report.consent_reference_sha256,
        "source_scope_sha256": _digest(config.source_scope_code),
        "coverage_complete": report.coverage_complete,
        "coverage_limitations": list(report.coverage_limitations),
        "raw_source_persisted": report.raw_source_persisted,
    }


def _drain(agent: DiscoverySensorAgent) -> int:
    delivered = 0
    while True:
        count = agent.deliver_once()["delivered"]
        delivered += count
        if count == 0:
            return delivered


def _run_fixed_scope(work_directory: Path) -> tuple[dict[str, Any], tuple[str, ...]]:
    clock = _Clock()
    estate = ConsentingDiscoveryTestEstate(
        consent_acknowledged=True,
        consent_reference=CONSENT_REFERENCE,
        coverage_limitations=COVERAGE_LIMITATIONS,
        clock=clock,
    )
    configs = {source: _config(work_directory, source) for source in SOURCE_KINDS}
    keys = {source: Ed25519PrivateKey.generate() for source in SOURCE_KINDS}
    for source in SOURCE_KINDS:
        atomic_write_bytes(configs[source].key_file, _private_pem(keys[source]), mode=0o600)
        _register(estate, configs[source], keys[source])

    agents = {
        source: DiscoverySensorAgent(
            configs[source],
            transport=estate,
            clock=clock,
            worker_id=f"initial-{source}",
        )
        for source in SOURCE_KINDS
    }
    initial = {
        source: agents[source].run_once([_event(source, "initial")])
        for source in SOURCE_KINDS
    }

    # Hot rotation is exercised by replacing the key file while the original
    # agent object remains alive.  Its signer reopens the file for every request.
    network_config = configs["network_egress"]
    network_agent = agents["network_egress"]
    old_network_key = keys["network_egress"]
    new_network_key = Ed25519PrivateKey.generate()
    estate.rotate_key(network_config.binding.agent_id, new_network_key.public_key())
    atomic_write_bytes(network_config.key_file, _private_pem(new_network_key), mode=0o600)
    rotated = network_agent.run_once([_event("network_egress", "after-rotation")])
    old_request = SignedDiscoverySensorClient(
        network_config.binding,
        signer=old_network_key.sign,
        clock=clock,
        nonce_factory=lambda: "old-key-after-rotation",
    ).build(network_agent.normalize(_event("network_egress", "old-key-rejected")))
    old_key_status = estate.send(old_request).status_code

    # Revocation preserves the normalized observation for an explicit operator
    # restore/unblock action; it is then delivered without raw-source recovery.
    browser_config = configs["browser_extension"]
    browser_agent = agents["browser_extension"]
    estate.revoke_sensor(browser_config.binding.agent_id)
    revoked = browser_agent.run_once([_event("browser_extension", "revoked")])
    estate.restore_sensor(browser_config.binding.agent_id)
    unblocked = browser_agent.spool.unblock_auth()
    recovered_after_restore = browser_agent.deliver_once()["delivered"]

    # An injected 503 leaves a normalized event queued.  Inspect privacy while
    # the payload is retained, then retry against the same estate.
    oauth_agent = agents["oauth_grant"]
    estate.simulate_outage(1)
    outage = oauth_agent.run_once([_event("oauth_grant", "outage")])
    pending_privacy = oauth_agent.spool.privacy_posture()
    raw_hostname_absent = b"api.openai.com" not in network_config.spool_file.read_bytes()
    outage_recovered = oauth_agent.deliver_once()["delivered"]

    # The estate accepts once and the transport loses the response.  The retry
    # uses a fresh nonce and is accepted idempotently by event digest.
    before_loss = estate.acceptance_report()
    loss_agent = DiscoverySensorAgent(
        configs["oauth_grant"],
        signer=keys["oauth_grant"].sign,
        transport=_AcceptThenLoseResponse(estate),
        clock=clock,
        worker_id="response-loss-worker",
    )
    response_loss = loss_agent.run_once([_event("oauth_grant", "response-loss")])
    after_ambiguous_acceptance = estate.acceptance_report()
    clock.advance(0.02)
    response_loss_recovered = loss_agent.deliver_once()["delivered"]
    after_loss_retry = estate.acceptance_report()

    # The source-event digest namespace is not globally unique.  Reuse the
    # first tenant's sensor id and event digest under a second authenticated
    # tenant, then replay it inside that second tenant with a fresh nonce.
    second_tenant_key = Ed25519PrivateKey.generate()
    second_tenant_config = replace(
        network_config,
        key_file=work_directory / "second-tenant-network.pem",
        spool_file=work_directory / "second-tenant-network.sqlite",
        binding=SensorBinding(
            tenant_ref=_SECOND_TENANT_REF,
            agent_id="local-network-egress-sensor-second-tenant",
            sensor_id=network_config.binding.sensor_id,
            sensor_revision=network_config.binding.sensor_revision,
            config_sha256=network_config.binding.config_sha256,
        ),
    )
    _register(estate, second_tenant_config, second_tenant_key)
    cross_tenant_before = estate.acceptance_report()
    second_tenant_agent = DiscoverySensorAgent(
        second_tenant_config,
        signer=second_tenant_key.sign,
        transport=estate,
        clock=clock,
        worker_id="second-tenant-worker",
    )
    cross_tenant_delivery = second_tenant_agent.run_once(
        [_event("network_egress", "initial")]
    )
    cross_tenant_after = estate.acceptance_report()
    same_scope_duplicate = SignedDiscoverySensorClient(
        second_tenant_config.binding,
        signer=second_tenant_key.sign,
        clock=clock,
        nonce_factory=lambda: "second-tenant-same-sensor-fresh-nonce",
    ).build(
        second_tenant_agent.normalize(_event("network_egress", "initial"))
    )
    same_scope_duplicate_status = estate.send(same_scope_duplicate).status_code
    after_same_scope_duplicate = estate.acceptance_report()

    # Bounded shared-spool concurrency: eight agents ingest disjoint chunks and
    # race lease acquisition.  SQLite leases and estate digest idempotency must
    # yield exactly 1,000 new accepted observations and no pending residue.
    scale_before = estate.acceptance_report()["unique_observations"]
    scale_agents = [
        DiscoverySensorAgent(
            network_config,
            signer=new_network_key.sign,
            transport=estate,
            clock=clock,
            worker_id=f"scale-worker-{index}",
        )
        for index in range(CONCURRENT_WORKERS)
    ]
    scale_events = [
        _event("network_egress", f"scale-{index}")
        for index in range(SCALE_OBSERVATIONS)
    ]
    chunks = [scale_events[index::CONCURRENT_WORKERS] for index in range(CONCURRENT_WORKERS)]
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        ingested = list(
            executor.map(
                lambda pair: pair[0].ingest(pair[1]),
                zip(scale_agents, chunks, strict=True),
            )
        )
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        scale_delivered = sum(executor.map(_drain, scale_agents))
    final_estate = estate.acceptance_report()
    scale_unique = final_estate["unique_observations"] - scale_before

    ceremony_records = estate.ceremony_records()
    source_results = {
        source: _source_result(configs[source], initial[source])
        for source in SOURCE_KINDS
    }
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "passed_local_synthetic",
        "execution_scope": {
            "mode": "in_process_consenting_test_estate",
            "local_synthetic": True,
            "consent_acknowledged": True,
            "network_io_used": False,
            "external_or_customer_estate_run": False,
            "external_credentials_used": False,
            "coverage_complete": False,
        },
        "consent": {
            "consent_reference_sha256": _digest(CONSENT_REFERENCE),
            "raw_consent_reference_in_evidence": False,
        },
        "sources": source_results,
        "key_lifecycle": {
            "hot_rotation_without_agent_restart": rotated.delivered_events == 1,
            "old_key_rejected_after_rotation": old_key_status == 401,
            "old_key_status_code": old_key_status,
            "ceremony_record_count": len(ceremony_records),
            "ceremony_records_sha256": _sha256(ceremony_records),
            "public_or_private_key_material_in_evidence": False,
        },
        "revocation_and_recovery": {
            "revoked_request_auth_blocked": revoked.auth_blocked_events == 1,
            "normalized_observation_preserved": revoked.blocked_events == 1,
            "operator_unblocked_events": unblocked,
            "delivered_after_restore": recovered_after_restore,
            "passed": (
                revoked.auth_blocked_events == 1
                and revoked.blocked_events == 1
                and unblocked == 1
                and recovered_after_restore == 1
            ),
        },
        "outage_and_retry": {
            "simulated_503_retry_scheduled": outage.retry_scheduled_events == 1,
            "pending_after_outage": outage.pending_events,
            "delivered_after_retry": outage_recovered,
            "passed": outage.retry_scheduled_events == 1 and outage_recovered == 1,
        },
        "response_loss_idempotency": {
            "retry_scheduled_after_ambiguous_success": (
                response_loss.retry_scheduled_events == 1
            ),
            "accepted_before_response_loss": (
                after_ambiguous_acceptance["unique_observations"]
                == before_loss["unique_observations"] + 1
            ),
            "delivered_after_retry": response_loss_recovered,
            "retry_request_count": (
                after_loss_retry["requests_received"]
                - before_loss["requests_received"]
            ),
            "unique_observation_delta": (
                after_loss_retry["unique_observations"]
                - before_loss["unique_observations"]
            ),
            "passed": (
                response_loss.retry_scheduled_events == 1
                and response_loss_recovered == 1
                and after_loss_retry["requests_received"]
                - before_loss["requests_received"]
                == 2
                and after_loss_retry["unique_observations"]
                - before_loss["unique_observations"]
                == 1
            ),
        },
        "tenant_scoped_idempotency": {
            "scope": "authenticated_tenant_sensor_event_digest",
            "same_digest_second_tenant_delivered": (
                cross_tenant_delivery.delivered_events == 1
            ),
            "cross_tenant_unique_observation_delta": (
                cross_tenant_after["unique_observations"]
                - cross_tenant_before["unique_observations"]
            ),
            "same_tenant_sensor_duplicate_status_code": (
                same_scope_duplicate_status
            ),
            "same_tenant_sensor_duplicate_unique_delta": (
                after_same_scope_duplicate["unique_observations"]
                - cross_tenant_after["unique_observations"]
            ),
            "passed": (
                cross_tenant_delivery.delivered_events == 1
                and cross_tenant_after["unique_observations"]
                - cross_tenant_before["unique_observations"]
                == 1
                and same_scope_duplicate_status == 201
                and after_same_scope_duplicate["unique_observations"]
                - cross_tenant_after["unique_observations"]
                == 0
            ),
        },
        "bounded_concurrent_scale": {
            "target_observations": SCALE_OBSERVATIONS,
            "worker_count": CONCURRENT_WORKERS,
            "normalized_observations": sum(row["normalized"] for row in ingested),
            "delivered_observations": scale_delivered,
            "unique_observation_delta": scale_unique,
            "pending_after_drain": scale_agents[0].spool.counts()["pending"],
            "passed": (
                sum(row["normalized"] for row in ingested) == SCALE_OBSERVATIONS
                and scale_delivered == SCALE_OBSERVATIONS
                and scale_unique == SCALE_OBSERVATIONS
                and scale_agents[0].spool.counts()["pending"] == 0
            ),
        },
        "privacy": {
            "raw_source_persisted": final_estate["raw_source_persisted"],
            "prohibited_fields_found": list(final_estate["prohibited_fields_found"]),
            "estate_privacy_check_passed": final_estate["privacy_check_passed"],
            "queued_payload_privacy_check_passed": pending_privacy[
                "privacy_check_passed"
            ],
            "queued_payload_schema_sha256": _sha256(
                pending_privacy["retained_fields"]
            ),
            "network_raw_hostname_absent_from_spool": raw_hostname_absent,
            "raw_source_values_in_evidence": False,
            "private_key_material_in_evidence": False,
        },
        "estate_summary": {
            "requests_received": final_estate["requests_received"],
            "unique_observations": final_estate["unique_observations"],
            "key_ceremony_events": final_estate["key_ceremony_events"],
            "coverage_complete": final_estate["coverage_complete"],
            "coverage_limitations": list(final_estate["coverage_limitations"]),
        },
        "limitations": [
            "All source events, consent, bindings, identities, keys and outages are local synthetic fixtures.",
            "Coverage is limited to supplied events and a reviewed allowlist; enterprise completeness is false.",
            "No external or customer estate, live adapter, external credential, privacy approval or production key custody was accepted.",
        ],
    }
    checks = (
        all(row["initial_delivery_passed"] for row in source_results.values()),
        all(row["coverage_complete"] is False for row in source_results.values()),
        result["key_lifecycle"]["hot_rotation_without_agent_restart"],
        result["key_lifecycle"]["old_key_rejected_after_rotation"],
        result["revocation_and_recovery"]["passed"],
        result["outage_and_retry"]["passed"],
        result["response_loss_idempotency"]["passed"],
        result["tenant_scoped_idempotency"]["passed"],
        result["bounded_concurrent_scale"]["passed"],
        result["privacy"]["estate_privacy_check_passed"],
        result["privacy"]["queued_payload_privacy_check_passed"],
        result["privacy"]["network_raw_hostname_absent_from_spool"],
        final_estate["coverage_complete"] is False,
        tuple(final_estate["coverage_limitations"]) == COVERAGE_LIMITATIONS,
    )
    if not all(checks):
        raise RuntimeError("fixed discovery-sensor acceptance did not pass")
    private_markers = tuple(key.private_bytes_raw().hex() for key in keys.values()) + (
        old_network_key.private_bytes_raw().hex(),
        new_network_key.private_bytes_raw().hex(),
        second_tenant_key.private_bytes_raw().hex(),
        CONSENT_REFERENCE,
        _TENANT_REF,
        _SECOND_TENANT_REF,
    )
    return result, private_markers


def run_acceptance(*, synthetic_consent_confirmed: bool) -> dict[str, Any]:
    if synthetic_consent_confirmed is not True:
        raise ValueError("the local synthetic consenting-estate boundary must be acknowledged")
    with tempfile.TemporaryDirectory(prefix="lightwork-discovery-sensor-acceptance-") as raw:
        result, forbidden_markers = _run_fixed_scope(Path(raw))
    serialized = _canonical(result).decode("ascii")
    if any(marker and marker in serialized for marker in forbidden_markers):
        raise RuntimeError("private or raw fixture material entered acceptance evidence")
    result["evidence_sha256"] = _sha256(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--synthetic-consent-confirmed", action="store_true")
    args = parser.parse_args(argv)
    report = run_acceptance(
        synthetic_consent_confirmed=args.synthetic_consent_confirmed,
    )
    atomic_write_text(
        args.output,
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        mode=0o600,
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
