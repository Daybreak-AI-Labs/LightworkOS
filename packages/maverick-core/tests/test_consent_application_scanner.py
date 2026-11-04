"""Governed mobile and OTT/CTV manifest-analysis coverage."""

from __future__ import annotations

import json
import plistlib
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import consent_application_scanner as scanner
from maverick.paths import tenant_scope


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[consent_preferences]\nenable = true\n",
        encoding="utf-8",
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _android_files(*, package: str = "com.example.mobile") -> list[scanner.ManifestFile]:
    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="{package}">
  <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
  <uses-permission android:name="com.google.android.gms.permission.AD_ID" />
  <application>
    <activity android:name="com.google.android.gms.ads.AdActivity" />
  </application>
</manifest>""".encode()
    dependencies = json.dumps(
        {
            "dependencies": [
                {
                    "name": "com.appsflyer.sdk",
                    "version": "6.15.0",
                    "source": "build_inventory",
                },
                {"name": "com.example.internal", "version": "1.0.0", "source": "manifest"},
            ]
        }
    ).encode()
    return [
        scanner.ManifestFile("AndroidManifest.xml", manifest, "application/xml"),
        scanner.ManifestFile("dependencies.json", dependencies, "application/json"),
    ]


def _apple_files(*, bundle: str = "com.example.ios") -> list[scanner.ManifestFile]:
    info = plistlib.dumps(
        {
            "CFBundleIdentifier": bundle,
            "CFBundleShortVersionString": "2.3.1",
            "NSCameraUsageDescription": "Capture a receipt for customer support.",
            "NSUserTrackingUsageDescription": "Measure campaign attribution.",
            "SKAdNetworkItems": [{"SKAdNetworkIdentifier": "example.skadnetwork"}],
        }
    )
    privacy = plistlib.dumps(
        {
            "NSPrivacyTracking": True,
            "NSPrivacyTrackingDomains": ["metrics.example.test"],
            "NSPrivacyCollectedDataTypes": [
                {
                    "NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeEmailAddress",
                    "NSPrivacyCollectedDataTypeLinked": True,
                    "NSPrivacyCollectedDataTypeTracking": False,
                    "NSPrivacyCollectedDataTypePurposes": [
                        "NSPrivacyCollectedDataTypePurposeAppFunctionality"
                    ],
                }
            ],
            "NSPrivacyAccessedAPITypes": [
                {
                    "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryUserDefaults",
                    "NSPrivacyAccessedAPITypeReasons": ["CA92.1"],
                }
            ],
        }
    )
    return [
        scanner.ManifestFile("Payload/App.app/Info.plist", info, "application/x-plist"),
        scanner.ManifestFile(
            "Payload/App.app/PrivacyInfo.xcprivacy",
            privacy,
            "application/x-plist",
        ),
    ]


def test_android_manifest_analysis_is_cited_bounded_and_not_a_tracker_verdict():
    result = scanner.scan_manifest_bundle(
        "android",
        _android_files(),
        expected_bundle_id="com.example.mobile",
    )

    assert result["schema"] == scanner.RESULT_SCHEMA
    assert result["completeness"]["complete"] is True
    assert result["identities"] == {
        "bundle_id": "com.example.mobile",
        "minimum_platform_version": "26",
        "target_platform_version": "35",
    }
    assert {item["category"] for item in result["permissions"]} == {
        "advertising_identifier",
        "precise_location",
    }
    assert result["signals"]["advertising_identifier_declared"] is True
    assert {item["vendor_hint"] for item in result["sdk_candidates"]} >= {
        "AppsFlyer",
        "Google Mobile Ads",
    }
    assert {item["classification"] for item in result["sdk_candidates"]} == {
        "unreviewed_sdk_candidate"
    }
    assert all(
        item["citation"]["file_sha256"]
        in {entry["file_sha256"] for entry in result["file_manifest"]}
        for item in result["permissions"] + result["sdk_candidates"]
    )
    assert result["completeness"]["dynamic_runtime_observed"] is False
    assert result["completeness"]["compiled_binary_inspected"] is False


def test_apple_privacy_manifest_analysis_hashes_free_form_source_values():
    result = scanner.scan_manifest_bundle(
        "ios",
        _apple_files(),
        expected_bundle_id="com.example.ios",
    )

    assert result["completeness"]["complete"] is True
    assert result["signals"]["tracking_declared"] is True
    assert len(result["signals"]["tracking_domain_sha256"]) == 1
    assert result["signals"]["tracking_domain_sha256"][0] != "metrics.example.test"
    assert result["signals"]["tracking_authorization_description_declared"] is True
    assert result["privacy_data_types"][0] == {
        "data_type": "NSPrivacyCollectedDataTypeEmailAddress",
        "linked_to_identity": True,
        "used_for_tracking": False,
        "purposes": ["NSPrivacyCollectedDataTypePurposeAppFunctionality"],
        "citation": result["privacy_data_types"][0]["citation"],
    }
    assert result["required_reason_apis"][0]["reason_codes"] == ["CA92.1"]
    serialized = json.dumps(result)
    assert "Capture a receipt" not in serialized
    assert "Measure campaign attribution" not in serialized
    assert "metrics.example.test" not in serialized


@pytest.mark.parametrize(
    ("platform", "bundle", "file"),
    [
        (
            "tizen",
            "https://example.test/tizen/app",
            scanner.ManifestFile(
                "config.xml",
                b"""<widget xmlns:tizen="http://tizen.org/ns/widgets"
                    id="https://example.test/tizen/app">
                    <tizen:privilege name="http://tizen.org/privilege/internet" />
                </widget>""",
                "application/xml",
            ),
        ),
        (
            "webos",
            "com.example.webos",
            scanner.ManifestFile(
                "appinfo.json",
                json.dumps(
                    {
                        "id": "com.example.webos",
                        "version": "1.2.0",
                        "requiredPermissions": ["networking.internal"],
                    }
                ).encode(),
                "application/json",
            ),
        ),
        (
            "roku",
            "com.example.roku",
            scanner.ManifestFile(
                "manifest",
                b"channel_id=com.example.roku\nmajor_version=1\nminor_version=4\nbuild_version=7\n",
                "text/plain",
            ),
        ),
    ],
)
def test_ott_manifest_formats_produce_complete_explicit_observations(platform, bundle, file):
    result = scanner.scan_manifest_bundle(platform, [file], expected_bundle_id=bundle)
    assert result["identities"]["bundle_id"] == bundle
    assert result["completeness"]["complete"] is True
    assert result["completeness"]["dynamic_runtime_observed"] is False


@pytest.mark.parametrize(
    "files, error",
    [
        (
            [scanner.ManifestFile("../AndroidManifest.xml", b"<manifest package='x.y' />")],
            "unsafe",
        ),
        (
            [scanner.ManifestFile("AndroidManifest.xml", b"\x03\x00\x08\x00binary-axml")],
            "binary application manifests are unsupported",
        ),
        (
            [
                scanner.ManifestFile(
                    "AndroidManifest.xml",
                    b"<!DOCTYPE manifest [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><manifest package='x.y' />",
                )
            ],
            "forbidden DTD/entity",
        ),
    ],
)
def test_unsafe_or_unbounded_manifest_inputs_fail_closed(files, error):
    with pytest.raises(scanner.ConsentApplicationScanValidationError, match=error):
        scanner.scan_manifest_bundle("android", files, expected_bundle_id="x.y")


def test_xml_declaration_cannot_hide_beyond_the_prefix_bound():
    hidden_dtd = (b" " * 70_000) + b"<!DOCTYPE manifest><manifest package='com.example.mobile' />"
    with pytest.raises(scanner.ConsentApplicationScanValidationError, match="forbidden DTD"):
        scanner.scan_manifest_bundle(
            "android",
            [scanner.ManifestFile("AndroidManifest.xml", hidden_dtd)],
            expected_bundle_id="com.example.mobile",
        )


def test_structured_manifests_reject_duplicate_keys_and_namespace_spoofing():
    duplicate_json = b'{"id":"com.example.webos","id":"com.attacker.other","version":"1.0"}'
    with pytest.raises(scanner.ConsentApplicationScanValidationError, match="duplicate keys"):
        scanner.scan_manifest_bundle(
            "webos",
            [scanner.ManifestFile("appinfo.json", duplicate_json)],
            expected_bundle_id="com.example.webos",
        )

    duplicate_plist = b"""<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.ios</string>
<key>CFBundleIdentifier</key><string>com.attacker.other</string>
</dict></plist>"""
    with pytest.raises(scanner.ConsentApplicationScanValidationError, match="duplicate keys"):
        scanner.scan_manifest_bundle(
            "ios",
            [scanner.ManifestFile("Info.plist", duplicate_plist)],
            expected_bundle_id="com.example.ios",
        )

    namespaced_spoof = b"""<widget xmlns:evil="https://attacker.invalid/tizen"
        id="https://example.test/tizen/app">
        <evil:privilege name="http://tizen.org/privilege/location" />
    </widget>"""
    result = scanner.scan_manifest_bundle(
        "tizen",
        [scanner.ManifestFile("config.xml", namespaced_spoof)],
        expected_bundle_id="https://example.test/tizen/app",
    )
    assert result["permissions"] == []


def test_missing_required_manifest_is_explicit_not_a_completeness_claim():
    result = scanner.scan_manifest_bundle(
        "ios",
        [_apple_files()[0]],
        expected_bundle_id="com.example.ios",
    )
    assert result["completeness"]["complete"] is False
    assert result["completeness"]["missing_basenames"] == ["privacyinfo.xcprivacy"]


def test_service_lifecycle_is_tenant_private_idempotent_and_four_eyes():
    service = scanner.ConsentApplicationScanService()
    with tenant_scope(tenant="alpha"):
        application = service.register_application(
            platform="android",
            bundle_id="com.example.mobile",
            display_name="Example Mobile",
            actor="registrar",
            idempotency_key="register-001",
        )
        replayed_application = service.register_application(
            platform="android",
            bundle_id="com.example.mobile",
            display_name="Example Mobile",
            actor="registrar",
            idempotency_key="register-001",
        )
        assert replayed_application == application

        scan = service.scan(
            application["id"],
            _android_files(),
            actor="scanner-worker",
            idempotency_key="scan-001",
            expected_application_revision=application["revision"],
        )
        replayed_scan = service.scan(
            application["id"],
            _android_files(),
            actor="scanner-worker",
            idempotency_key="scan-001",
            expected_application_revision=application["revision"],
        )
        assert replayed_scan == scan
        assert scan["status"] == "pending_review"
        assert "AndroidManifest.xml" in {entry["path"] for entry in scan["result"]["file_manifest"]}
        listed_scan = service.list_scans(limit=1)[0]
        assert listed_scan["id"] == scan["id"]
        assert listed_scan["permission_count"] == 2
        assert "result" not in listed_scan

        with pytest.raises(scanner.ConsentApplicationScanConflict, match="cannot review"):
            service.review(
                scan["id"],
                decision="accepted",
                reviewer="scanner-worker",
                expected_revision=scan["revision"],
                review_note_code="looks_good",
            )

        reviewed = service.review(
            scan["id"],
            decision="accepted",
            reviewer="privacy-reviewer",
            expected_revision=scan["revision"],
            review_note_code="manifest_reviewed",
        )
        assert reviewed["status"] == "accepted"
        assert reviewed["review"]["result_sha256"] == scan["result_sha256"]
        assert service.verify_integrity()["ok"] is True

    with tenant_scope(tenant="beta"):
        with pytest.raises(scanner.ConsentApplicationScanNotFound):
            service.get_application(application["id"])
        assert service.list_scans() == []


def test_application_revocation_invalidates_pending_review():
    service = scanner.ConsentApplicationScanService()
    with tenant_scope(tenant="alpha"):
        application = service.register_application(
            platform="ios",
            bundle_id="com.example.ios",
            display_name="Example iOS",
            actor="registrar",
            idempotency_key="register-ios",
        )
        scan = service.scan(
            application["id"],
            _apple_files(),
            actor="scanner-worker",
            idempotency_key="scan-ios",
            expected_application_revision=application["revision"],
        )
        service.revoke_application(
            application["id"],
            actor="application-admin",
            reason_code="retired",
            expected_revision=application["revision"],
        )
        with pytest.raises(scanner.ConsentApplicationScanConflict, match="revoked"):
            service.review(
                scan["id"],
                decision="accepted",
                reviewer="privacy-reviewer",
                expected_revision=scan["revision"],
                review_note_code="manifest_reviewed",
            )


def test_revocation_and_scan_acceptance_are_cross_record_linearized(monkeypatch):
    service = scanner.ConsentApplicationScanService()
    with tenant_scope(tenant="alpha"):
        application = service.register_application(
            platform="android",
            bundle_id="com.example.mobile",
            display_name="Example Mobile",
            actor="registrar",
            idempotency_key="register-race",
        )
        scan = service.scan(
            application["id"],
            _android_files(),
            actor="scanner-worker",
            idempotency_key="scan-race",
            expected_application_revision=application["revision"],
        )

    revocation_entered = threading.Event()
    allow_revocation = threading.Event()
    review_update_entered = threading.Event()
    original_application_update = service._applications.update
    original_scan_update = service._scans.update

    def delayed_application_update(*args, **kwargs):
        if kwargs.get("action") == "revoke_application":
            revocation_entered.set()
            assert allow_revocation.wait(5)
        return original_application_update(*args, **kwargs)

    def observed_scan_update(*args, **kwargs):
        review_update_entered.set()
        return original_scan_update(*args, **kwargs)

    monkeypatch.setattr(service._applications, "update", delayed_application_update)
    monkeypatch.setattr(service._scans, "update", observed_scan_update)

    def revoke():
        with tenant_scope(tenant="alpha"):
            return service.revoke_application(
                application["id"],
                actor="application-admin",
                reason_code="retired",
                expected_revision=application["revision"],
            )

    def review():
        with tenant_scope(tenant="alpha"):
            return service.review(
                scan["id"],
                decision="accepted",
                reviewer="privacy-reviewer",
                expected_revision=scan["revision"],
                review_note_code="manifest_reviewed",
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        revocation = executor.submit(revoke)
        assert revocation_entered.wait(5)
        acceptance = executor.submit(review)
        assert review_update_entered.wait(0.2) is False
        allow_revocation.set()
        assert revocation.result(timeout=5)["status"] == "revoked"
        with pytest.raises(scanner.ConsentApplicationScanConflict, match="not active"):
            acceptance.result(timeout=5)


def test_revocation_replay_is_exact_not_blanket_success():
    service = scanner.ConsentApplicationScanService()
    with tenant_scope(tenant="alpha"):
        application = service.register_application(
            platform="android",
            bundle_id="com.example.mobile",
            display_name="Example Mobile",
            actor="registrar",
            idempotency_key="register-revoke-replay",
        )
        revoked = service.revoke_application(
            application["id"],
            actor="application-admin",
            reason_code="retired",
            expected_revision=application["revision"],
        )
        replay = service.revoke_application(
            application["id"],
            actor="application-admin",
            reason_code="retired",
            expected_revision=application["revision"],
        )
        assert replay == revoked
        with pytest.raises(scanner.ConsentApplicationScanConflict, match="different operation"):
            service.revoke_application(
                application["id"],
                actor="different-admin",
                reason_code="other_reason",
                expected_revision=application["revision"],
            )


def test_shared_backend_fence_rejects_a_revoked_application_pin():
    service = scanner.ConsentApplicationScanService()
    with tenant_scope(tenant="alpha"):
        application = service.register_application(
            platform="android",
            bundle_id="com.example.mobile",
            display_name="Example Mobile",
            actor="registrar",
            idempotency_key="register-fence",
        )
        fence = service._application_fence(application)
        assert fence.namespace == "consent_applications"
        assert fence.record_id == application["id"]
        fence.validate(application, 1_700_000_000.0)
        revoked = service.revoke_application(
            application["id"],
            actor="application-admin",
            reason_code="retired",
            expected_revision=application["revision"],
        )
        with pytest.raises(scanner.ConsentApplicationScanConflict, match="revoked"):
            fence.validate(revoked, 1_700_000_001.0)


def test_integrity_never_reports_a_truncated_window_as_complete():
    service = scanner.ConsentApplicationScanService()
    with tenant_scope(tenant="alpha"):
        for suffix in ("one", "two"):
            service.register_application(
                platform="android",
                bundle_id=f"com.example.{suffix}",
                display_name=f"Example {suffix}",
                actor="registrar",
                idempotency_key=f"register-{suffix}",
            )
        report = service.verify_integrity(limit=1)
        assert report["sample_ok"] is True
        assert report["complete"] is False
        assert report["ok"] is False
        assert report["applications_complete"] is False


def test_integrity_cross_checks_scan_platform_and_application_authority():
    service = scanner.ConsentApplicationScanService()
    with tenant_scope(tenant="alpha"):
        application = service.register_application(
            platform="android",
            bundle_id="com.example.mobile",
            display_name="Example Mobile",
            actor="registrar",
            idempotency_key="register-authority-check",
        )
        scan = service.scan(
            application["id"],
            _android_files(),
            actor="scanner-worker",
            idempotency_key="scan-authority-check",
            expected_application_revision=application["revision"],
        )

        def tamper(current):
            current["result"]["platform"] = "webos"
            current["result"]["result_sha256"] = scanner._sha256(
                {key: value for key, value in current["result"].items() if key != "result_sha256"}
            )
            current["result_sha256"] = current["result"]["result_sha256"]
            current["integrity_sha256"] = scanner._record_digest(
                current,
                exclude=scanner._STORE_FIELDS | frozenset({"integrity_sha256"}),
            )

        service._scans.update(
            scan["id"],
            tamper,
            expected_revision=scan["revision"],
            action="test_authority_mismatch",
            actor="test",
        )
        report = service.verify_integrity()
        assert report["sample_ok"] is False
        assert report["ok"] is False
        assert report["authority_mismatch_scan_ids"] == [scan["id"]]


def test_retention_replaces_findings_with_a_minimized_tombstone():
    now = [1_700_000_000.0]
    service = scanner.ConsentApplicationScanService(
        clock=lambda: now[0],
        retention_seconds=86_400,
    )
    with tenant_scope(tenant="alpha"):
        application = service.register_application(
            platform="android",
            bundle_id="com.example.mobile",
            display_name="Example Mobile",
            actor="registrar",
            idempotency_key="register-retention",
        )
        scan = service.scan(
            application["id"],
            _android_files(),
            actor="scanner-worker",
            idempotency_key="scan-retention",
            expected_application_revision=application["revision"],
        )
        now[0] += 86_401
        outcome = service.purge_expired(actor="retention-worker", now=now[0])
        assert outcome == {"inspected": 1, "purged": 1, "deleted": 0}
        tombstone = service.get_scan(scan["id"])
        assert tombstone["schema"] == scanner.TOMBSTONE_SCHEMA
        assert tombstone["status"] == "purged"
        assert "result" not in tombstone
        assert tombstone["result_sha256"] == scan["result_sha256"]
        assert tombstone["delete_after"] > tombstone["purged_at"]

        now[0] += 86_401
        deletion = service.purge_expired(actor="retention-worker", now=now[0])
        assert deletion == {"inspected": 1, "purged": 0, "deleted": 1}
        with pytest.raises(scanner.ConsentApplicationScanNotFound):
            service.get_scan(scan["id"])


def test_retention_never_discards_an_undelivered_audit_outbox(monkeypatch):
    from maverick import audit

    now = [1_700_000_000.0]
    service = scanner.ConsentApplicationScanService(
        clock=lambda: now[0],
        retention_seconds=86_400,
    )
    with tenant_scope(tenant="alpha"):
        application = service.register_application(
            platform="android",
            bundle_id="com.example.mobile",
            display_name="Example Mobile",
            actor="registrar",
            idempotency_key="register-pending-audit",
        )
        monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
        scan = service.scan(
            application["id"],
            _android_files(),
            actor="scanner-worker",
            idempotency_key="scan-pending-audit",
            expected_application_revision=application["revision"],
        )
        assert scan.get("_audit_pending")
        now[0] += 86_401
        assert service.purge_expired(actor="retention-worker", now=now[0]) == {
            "inspected": 1,
            "purged": 0,
            "deleted": 0,
        }
        assert service.get_scan(scan["id"])["schema"] == scanner.SCAN_SCHEMA

        monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
        assert service.purge_expired(actor="retention-worker", now=now[0]) == {
            "inspected": 1,
            "purged": 1,
            "deleted": 0,
        }
        assert service.get_scan(scan["id"])["schema"] == scanner.TOMBSTONE_SCHEMA
