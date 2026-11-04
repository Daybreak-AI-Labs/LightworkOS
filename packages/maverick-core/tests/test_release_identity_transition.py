"""Distinct ephemeral signing identities; no Windows trust or MSI execution."""
import base64
import copy
import hashlib
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from maverick import release_identity_transition as transition


def signer():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    identifier = hashlib.sha256(public).digest()[:8]
    encoded = base64.b64encode(b"untrusted comment: ephemeral synthetic fixture\n" + base64.b64encode(b"Ed" + identifier + public) + b"\n").decode()
    def sign(payload):
        signature = key.sign(hashlib.blake2b(payload, digest_size=64).digest())
        comment = b"synthetic identity-transition fixture"
        envelope = b"\n".join([b"untrusted comment: synthetic signature", base64.b64encode(b"ED" + identifier + signature),
                                  b"trusted comment: " + comment, base64.b64encode(key.sign(signature + comment))])
        return base64.b64encode(envelope).decode()
    return encoded, sign


def test_actual_tauri_cli_distinct_signing_fixture_remains_interoperable(monkeypatch, tmp_path):
    from maverick.windows_installer_verification import verify_minisign
    fixture = json.loads((Path(__file__).parent / "fixtures/tauri_identity_bridge.json").read_text(encoding="utf-8"))
    envelope = fixture["envelope"]
    policy = envelope["policy"]
    monkeypatch.setattr(transition.time, "time", lambda: policy["issued_at"] + 1)
    assert policy["from"]["public_key"] != policy["to"]["public_key"]
    assert transition.verify(envelope, installed=policy["from"]) == envelope
    artifact = tmp_path / "synthetic-bridge.msi"
    artifact.write_bytes(base64.b64decode(fixture["payload_base64"]))
    assert verify_minisign(artifact, policy["from"]["public_key"], fixture["artifact_signature"]) == policy["new_installer_sha256"]
    with pytest.raises(transition.IdentityTransitionError, match="signatures"):
        transition.verify({**envelope, "to_signature": fixture["unrelated_signature"]}, installed=policy["from"])


@pytest.fixture
def bridge():
    old, old_sign = signer()
    new, new_sign = signer()
    policy = {"schema": 1, "id": "a" * 32, "issued_at": int(time.time()) - 30, "expires_at": int(time.time()) + 600,
              "from": {"version": "1.0.0", "runtime_sha256": "1" * 64, "native_sha256": "2" * 64,
                       "publisher_thumbprint": "A" * 40, "public_key": old},
              "to": {"version": "1.0.1", "runtime_sha256": "3" * 64, "native_sha256": "4" * 64,
                     "publisher_thumbprint": "B" * 40, "public_key": new},
              "new_installer_sha256": "5" * 64, "rollback": "exact-retained-pair-only"}
    payload = transition.canonical(policy).encode()
    return {"policy": policy, "from_signature": old_sign(payload), "to_signature": new_sign(payload)}


def test_distinct_identity_bridge_requires_real_old_and_new_key_signatures(bridge):
    assert transition.verify(bridge, installed=bridge["policy"]["from"]) == bridge
    for field in ("from_signature", "to_signature"):
        unrelated, sign = signer()
        wrong = copy.deepcopy(bridge)
        wrong[field] = sign(transition.canonical(wrong["policy"]).encode())
        assert unrelated not in (bridge["policy"]["from"]["public_key"], bridge["policy"]["to"]["public_key"])
        with pytest.raises(transition.IdentityTransitionError, match="signatures"):
            transition.verify(wrong, installed=bridge["policy"]["from"])


@pytest.mark.parametrize("field", ["runtime_sha256", "native_sha256", "version", "public_key"])
def test_stale_source_or_unrelated_installed_key_refuses(bridge, field):
    installed = dict(bridge["policy"]["from"], **{field: "unrelated"})
    with pytest.raises(transition.IdentityTransitionError, match="installed"):
        transition.verify(bridge, installed=installed)


def test_tampered_target_or_expired_admission_does_not_gain_trust(bridge, monkeypatch):
    changed = copy.deepcopy(bridge)
    changed["policy"]["to"]["publisher_thumbprint"] = "C" * 40
    with pytest.raises(transition.IdentityTransitionError, match="signatures"):
        transition.verify(changed, installed=bridge["policy"]["from"])
    monkeypatch.setattr(transition.time, "time", lambda: bridge["policy"]["expires_at"])
    with pytest.raises(transition.IdentityTransitionError, match="admission"):
        transition.verify(bridge, installed=bridge["policy"]["from"])
    # No public caller can use this to admit a new pair. The maintenance caller
    # uses it only for its private, authenticated already-prepared exact record.
    assert transition.verify(bridge, installed=bridge["policy"]["from"], admit=False) == bridge


def test_exact_publisher_runtime_version_and_msi_bytes_remain_required(bridge):
    policy = bridge["policy"]
    old = {**policy["from"], "sha256": "0" * 64}
    new = {**policy["to"], "sha256": policy["new_installer_sha256"]}
    transition.verify_installers(bridge, old=old, new=new)
    for field, value in (("publisher_thumbprint", "C" * 40), ("runtime_sha256", "9" * 64),
                         ("version", "1.0.2"), ("sha256", "9" * 64)):
        with pytest.raises(transition.IdentityTransitionError):
            transition.verify_installers(bridge, old=old, new={**new, field: value})


@pytest.mark.parametrize("malformed", ["{}", '{"policy":{},"policy":{}}', "[" * 1000, "x" * 65537,
                                      {"schema": float("nan")}], ids=["empty", "duplicate", "deep", "oversized", "nan"])
def test_malformed_or_oversized_bridge_is_refused(malformed):
    with pytest.raises(transition.IdentityTransitionError):
        transition.parse(malformed)


@pytest.fixture
def transition_installation(tmp_path, monkeypatch):
    from maverick import config, control_plane_lease
    from maverick import installation_recovery as maintenance
    home, installed = tmp_path / "home", tmp_path / "installed"
    home.mkdir()
    installed.mkdir()
    (home / "config.toml").write_text("[features]\nsigning_identity_transition = true\n", encoding="utf-8")
    (home / "document.txt").write_text("before upgrade", encoding="utf-8")
    runtime = installed / "maverick.exe"
    runtime.write_bytes(b"old-runtime")
    native = installed / "maverick-desktop.exe"
    native.write_bytes(b"old-native")
    old_key, old_sign = signer()
    new_key, new_sign = signer()
    sides = {label: {"version": version, "runtime_sha256": hashlib.sha256((label + "-runtime").encode()).hexdigest(),
                    "native_sha256": hashlib.sha256((label + "-native").encode()).hexdigest(),
                    "publisher_thumbprint": publisher * 40, "public_key": key}
             for label, version, publisher, key in (("old", "1.0.0", "A", old_key), ("new", "1.0.1", "B", new_key))}
    policy = {"schema": 1, "id": "b" * 32, "issued_at": int(time.time()) - 30, "expires_at": int(time.time()) + 600,
              "from": sides["old"], "to": sides["new"], "new_installer_sha256": hashlib.sha256(b"new-msi").hexdigest(),
              "rollback": "exact-retained-pair-only"}
    payload = transition.canonical(policy).encode()
    envelope = {"policy": policy, "from_signature": old_sign(payload), "to_signature": new_sign(payload)}
    active = [runtime]
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(home / "config.toml"))
    monkeypatch.delenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", raising=False)
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.setattr(maintenance, "blockers", list)
    monkeypatch.setattr(maintenance.workspace_recovery, "version", lambda: "1.0.0")
    monkeypatch.setattr(maintenance, "_runtime", lambda: active[0])
    def native_identity(path, **kwargs):
        del kwargs
        data = (path.parent / "maverick-desktop.exe").read_bytes()
        return {"native_sha256": hashlib.sha256(data).hexdigest(),
                "public_key": new_key if data == b"new-native" else old_key}
    monkeypatch.setattr(maintenance, "_native_channel", native_identity)
    def windows_inspection(path, *, version, scratch):
        del scratch
        label = path.stem
        assert version == sides[label]["version"]
        return {"ProductCode": label, "PublisherThumbprint": sides[label]["publisher_thumbprint"]}
    monkeypatch.setattr(maintenance, "inspect_signed_msi", windows_inspection)
    events = []
    def msi(directory, action, label):
        del directory
        events.append((action, label))
        if action == "/i":
            runtime.write_bytes((label + "-runtime").encode())
            native.write_bytes((label + "-native").encode())
        else:
            runtime.unlink()
    monkeypatch.setattr(maintenance, "_msiexec", msi)
    control_plane_lease.release()
    yield {"home": home, "runtime": runtime, "native": native, "active": active, "events": events,
           "envelope": envelope, "sides": sides, "old_sign": old_sign, "maintenance": maintenance}
    control_plane_lease.release()


def native_review(fixture):
    from maverick.installation_handoff import save_review
    return save_review({"version": fixture["sides"]["new"]["version"],
                        "runtime_sha256": fixture["sides"]["new"]["runtime_sha256"],
                        "installer_sha256": hashlib.sha256(b"new-msi").hexdigest(),
                        "signature": fixture["old_sign"](b"new-msi")})["id"]


def stage_bridge(fixture, *, authorized=True):
    maintenance = fixture["maintenance"]
    options = {"identity_transition": fixture["envelope"], "transition_sha256": transition.digest(fixture["envelope"]),
               "confirm_identity_transition": True} if authorized else {}
    grant = maintenance.authorize(actor="named-global-admin", isolated=True, confirm_all_workspaces=True, review_id=native_review(fixture), **options)
    directory = maintenance._directory(grant["id"])
    metadata = {"public_key": fixture["sides"]["old"]["public_key"], "identity_transition": fixture["envelope"]}
    for label in ("old", "new"):
        payload = (label + "-msi").encode()
        (directory / (label + ".msi")).write_bytes(payload)
        metadata[label] = {"version": fixture["sides"][label]["version"],
                           "runtime_sha256": fixture["sides"][label]["runtime_sha256"],
                           "signature": fixture["old_sign"](payload)}
    (directory / "downloads.json").write_text(json.dumps(metadata), encoding="utf-8")
    return grant, directory


def test_explicit_dual_signed_bridge_upgrade_and_exact_rollback_use_real_signature_checks(transition_installation):
    fixture = transition_installation
    maintenance = fixture["maintenance"]
    grant, directory = stage_bridge(fixture)
    maintenance.prepare(grant["authorization"])
    fixture["active"][0] = directory / "maverick.exe"
    assert maintenance.execute(grant["authorization"])["status"] == "upgraded"
    fixture["active"][0] = fixture["runtime"]
    rollback = maintenance.authorize(actor="named-global-admin", isolated=True, confirm_all_workspaces=True, rollback_id=grant["id"])
    maintenance.prepare(rollback["authorization"])
    fixture["active"][0] = directory / "maverick.exe"
    assert maintenance.execute(rollback["authorization"])["status"] == "rolled_back"
    assert fixture["runtime"].read_bytes() == b"old-runtime"
    assert fixture["native"].read_bytes() == b"old-native"
    assert fixture["events"] == [("/i", "new"), ("/x", "new"), ("/i", "old")]


@pytest.mark.parametrize("reason", ["unreviewed", "changed-envelope", "expired", "disabled"])
def test_bridge_refusal_before_admission_preserves_normal_start(transition_installation, monkeypatch, reason):
    from maverick import config
    fixture = transition_installation
    maintenance = fixture["maintenance"]
    grant, directory = stage_bridge(fixture, authorized=reason != "unreviewed")
    if reason == "changed-envelope":
        metadata = json.loads((directory / "downloads.json").read_text(encoding="utf-8"))
        metadata["identity_transition"]["policy"]["id"] = "c" * 32
        (directory / "downloads.json").write_text(json.dumps(metadata), encoding="utf-8")
    if reason == "expired":
        monkeypatch.setattr(transition.time, "time", lambda: fixture["envelope"]["policy"]["expires_at"] + 1)
    if reason == "disabled":
        monkeypatch.setattr(config, "signing_identity_transition_enabled", lambda: False)
    with pytest.raises(maintenance.MaintenanceError):
        maintenance.prepare(grant["authorization"])
    maintenance.assert_normal_start_allowed()
    assert fixture["events"] == []
    assert fixture["runtime"].read_bytes() == b"old-runtime"


def test_disabled_or_unconfirmed_transition_never_grants_trust(transition_installation, monkeypatch):
    from maverick import config
    fixture = transition_installation
    maintenance = fixture["maintenance"]
    options = {"actor": "named-admin", "isolated": True, "confirm_all_workspaces": True, "review_id": native_review(fixture),
               "identity_transition": fixture["envelope"], "transition_sha256": transition.digest(fixture["envelope"])}
    with pytest.raises(maintenance.MaintenanceError, match="confirm"):
        maintenance.authorize(**options)
    monkeypatch.setattr(config, "signing_identity_transition_enabled", lambda: False)
    with pytest.raises(maintenance.MaintenanceError, match="disabled"):
        maintenance.authorize(**options, confirm_identity_transition=True)
    assert maintenance.status()["recovery_points"] == []


def test_interrupted_admitted_bridge_can_resume_after_admission_expiry_and_feature_disable(transition_installation, monkeypatch):
    from maverick import config
    fixture = transition_installation
    maintenance = fixture["maintenance"]
    grant, directory = stage_bridge(fixture)
    maintenance.prepare(grant["authorization"])
    fixture["active"][0] = directory / "maverick.exe"
    installer = maintenance._msiexec
    def interrupted(*args):
        installer(*args)
        raise OSError("synthetic interruption after install")
    monkeypatch.setattr(maintenance, "_msiexec", interrupted)
    with pytest.raises(OSError):
        maintenance.execute(grant["authorization"])
    assert maintenance.status()["incomplete"] is True
    monkeypatch.setattr(transition.time, "time", lambda: fixture["envelope"]["policy"]["expires_at"] + 1)
    monkeypatch.setattr(config, "signing_identity_transition_enabled", lambda: False)
    monkeypatch.setattr(maintenance, "_msiexec", installer)
    token = maintenance.resume(grant["id"])
    assert maintenance.execute(token)["status"] == "upgrade_recovered"
    assert fixture["native"].read_bytes() == b"old-native"


@pytest.mark.parametrize("fault", ["msi-tamper", "publisher-revoked", "native-key-mismatch"])
def test_prepared_bridge_rechecks_bytes_windows_trust_and_installed_native_identity(transition_installation, monkeypatch, fault):
    from maverick.windows_installer_verification import InstallerVerificationError
    fixture = transition_installation
    maintenance = fixture["maintenance"]
    grant, directory = stage_bridge(fixture)
    maintenance.prepare(grant["authorization"])
    fixture["active"][0] = directory / "maverick.exe"
    if fault == "msi-tamper":
        (directory / "new.msi").write_bytes(b"changed installer")
    elif fault == "publisher-revoked":
        def revoked(*args, **kwargs):
            raise InstallerVerificationError("Synthetic Windows publisher trust refusal")
        monkeypatch.setattr(maintenance, "inspect_signed_msi", revoked)
    else:
        installer = maintenance._msiexec
        def wrong_native(*args):
            installer(*args)
            fixture["native"].write_bytes(b"unrelated-native")
        monkeypatch.setattr(maintenance, "_msiexec", wrong_native)
    with pytest.raises((InstallerVerificationError, maintenance.MaintenanceError)):
        maintenance.execute(grant["authorization"])
    assert maintenance.status()["incomplete"] is True
    if fault != "native-key-mismatch":
        assert fixture["events"] == []


def test_transition_configuration_is_default_off_and_cannot_be_enabled_by_a_tenant(monkeypatch, tmp_path):
    from maverick import config
    from maverick.paths import tenant_scope
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    tenant = tmp_path / "tenants" / "fixture-tenant"
    tenant.mkdir(parents=True)
    (tenant / "config.toml").write_text("[features]\nsigning_identity_transition = true\n", encoding="utf-8")
    config.reset_config_cache()
    with tenant_scope(tenant="fixture-tenant"):
        assert config.signing_identity_transition_enabled() is False
        assert config.get_features()["signing_identity_transition"] is False
        (tmp_path / "config.toml").write_text("[features]\nsigning_identity_transition = true\n", encoding="utf-8")
        config.reset_config_cache()
        assert config.signing_identity_transition_enabled() is True
        (tmp_path / "config.toml").write_text("[invalid", encoding="utf-8")
        config.reset_config_cache()
        assert config.signing_identity_transition_enabled() is False


def test_unreviewed_same_publisher_upgrade_cannot_complete_with_a_changed_embedded_key(transition_installation, monkeypatch):
    from maverick import config
    fixture = transition_installation
    maintenance = fixture["maintenance"]
    monkeypatch.setattr(config, "signing_identity_transition_enabled", lambda: False)
    monkeypatch.setattr(maintenance, "inspect_signed_msi", lambda path, **kwargs: {
        "ProductCode": path.stem, "PublisherThumbprint": "A" * 40})
    grant, directory = stage_bridge(fixture, authorized=False)
    metadata = json.loads((directory / "downloads.json").read_text(encoding="utf-8"))
    del metadata["identity_transition"]
    (directory / "downloads.json").write_text(json.dumps(metadata), encoding="utf-8")
    maintenance.prepare(grant["authorization"])
    fixture["active"][0] = directory / "maverick.exe"
    with pytest.raises(maintenance.MaintenanceError, match="signing|identity|key"):
        maintenance.execute(grant["authorization"])
    assert fixture["events"] == [("/i", "new")]
    assert maintenance.status()["incomplete"] is True
    with pytest.raises(maintenance.MaintenanceError, match="unfinished"):
        maintenance.assert_normal_start_allowed()
