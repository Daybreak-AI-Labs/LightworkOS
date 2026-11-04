"""BYOK cloud KMS backends (AWS / GCP / Vault) behind the tenant_kms.KMS
Protocol. Fakes use real AES-GCM so context binding is actually exercised."""
from __future__ import annotations

import base64
import enum
import functools
import hashlib
import json
import os
import sys
import types

import pytest

pytest.importorskip("cryptography")
from cryptography.exceptions import InvalidSignature, InvalidTag  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from maverick import kms_backends  # noqa: E402
from maverick.crypto_at_rest import EncryptionUnavailable  # noqa: E402
from maverick.tenant import kms as tenant_kms  # noqa: E402

_FIXED_KEK = b"\x11" * 32


def _enc(plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(_FIXED_KEK).encrypt(nonce, plaintext, aad)


def _dec(blob: bytes, aad: bytes) -> bytes:
    return AESGCM(_FIXED_KEK).decrypt(blob[:12], blob[12:], aad)


# ---- fake SDK clients (match each SDK's response shape) --------------------


class _FakeAws:
    def __init__(self):
        self.decrypt_key_ids = []

    def encrypt(self, KeyId, Plaintext, EncryptionContext):  # noqa: N803
        aad = json.dumps(EncryptionContext, sort_keys=True).encode()
        return {"CiphertextBlob": _enc(Plaintext, aad)}

    def decrypt(self, KeyId, CiphertextBlob, EncryptionContext):  # noqa: N803
        self.decrypt_key_ids.append(KeyId)
        aad = json.dumps(EncryptionContext, sort_keys=True).encode()
        return {"Plaintext": _dec(CiphertextBlob, aad)}


class _FakeGcp:
    def encrypt(self, request):
        aad = request["additional_authenticated_data"]
        ct = _enc(request["plaintext"], aad)
        return types.SimpleNamespace(ciphertext=ct)

    def decrypt(self, request):
        aad = request["additional_authenticated_data"]
        pt = _dec(request["ciphertext"], aad)
        return types.SimpleNamespace(plaintext=pt)


class _FakeVault:
    class _Transit:
        def encrypt_data(self, name, mount_point, plaintext, context):
            aad = context.encode()
            ct = _enc(base64.b64decode(plaintext), aad)
            return {"data": {"ciphertext": "vault:v1:" + base64.b64encode(ct).decode()}}

        def decrypt_data(self, name, mount_point, ciphertext, context):
            aad = context.encode()
            ct = base64.b64decode(ciphertext.split("vault:v1:", 1)[1])
            return {"data": {"plaintext": base64.b64encode(_dec(ct, aad)).decode()}}

    def __init__(self):
        self.secrets = types.SimpleNamespace(transit=self._Transit())


_BACKENDS = [
    lambda: kms_backends.AwsKmsKEK(key_id="k", client=_FakeAws()),
    lambda: kms_backends.GcpKmsKEK(key_id="k", client=_FakeGcp()),
    lambda: kms_backends.VaultTransitKMS(key_id="k", client=_FakeVault()),
]


@pytest.mark.parametrize("make", _BACKENDS)
def test_wrap_unwrap_round_trip(make):
    kms = make()
    dek = b"\x42" * 32
    ctx = b"tenant:acme"
    wrapped = kms.wrap(dek, context=ctx)
    assert wrapped != dek
    assert kms.unwrap(wrapped, context=ctx) == dek


@pytest.mark.parametrize("make", _BACKENDS)
def test_context_binding_enforced(make):
    kms = make()
    wrapped = kms.wrap(b"\x42" * 32, context=b"tenant:acme")
    with pytest.raises(InvalidTag):  # wrong context -> AEAD auth failure
        kms.unwrap(wrapped, context=b"tenant:evil")


def test_aws_unwrap_enforces_configured_key_id():
    client = _FakeAws()
    kms = kms_backends.AwsKmsKEK(key_id="tenant-key", client=client)

    wrapped = kms.wrap(b"\x42" * 32, context=b"tenant:acme")

    assert kms.unwrap(wrapped, context=b"tenant:acme") == b"\x42" * 32
    assert client.decrypt_key_ids == ["tenant-key"]


@pytest.mark.parametrize("make", _BACKENDS)
def test_wrong_provider_magic_rejected(make):
    kms = make()
    with pytest.raises(EncryptionUnavailable):
        kms.unwrap(b"NOT-OUR-MAGIC" + b"x" * 40, context=b"c")


# ---- Azure Key Vault / Managed HSM ----------------------------------------

_AZ_VAULT = "https://acme-kv.vault.azure.net"
_AZ_V1 = "a" * 32
_AZ_V2 = "b" * 32
_AZ_KEY = f"{_AZ_VAULT}/keys/tenant-kek"          # unversioned key identifier
_AZ_V1_ID = f"{_AZ_KEY}/{_AZ_V1}"
_AZ_V2_ID = f"{_AZ_KEY}/{_AZ_V2}"


_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
# PS256: RSASSA-PSS, SHA-256, MGF1-SHA-256, salt length = digest length (32), which is
# what the SDK's own local verify uses (rsa_signing.py: salt_length=len(digest)).
_PS256 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
_PREHASHED = utils.Prehashed(hashes.SHA256())


@functools.cache
def _vault_key():
    """The RSA key the fake Key Vault holds. Only the vault's own operations sign or
    unwrap with its private half."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@functools.cache
def _attacker_key():
    """An RSA key the attacker controls, which forged envelopes can be signed with."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _Forbidden(Exception):
    """Shaped like azure.core's HttpResponseError for a refusal: only status_code is read."""

    status_code = 403


class _Refused(Exception):
    """Shaped like azure.core's HttpResponseError for a refusal that is not a 403."""

    status_code = 400


class _FakeAzureVault:
    """The ``client_factory`` injected into AzureKeyVaultKEK: one CryptographyClient fake
    per key id, all backed by one real RSA key. ``log`` records each operation in order,
    ``digests`` each digest the vault was asked to sign. ``sign_error`` and
    ``verify_error`` make the vault refuse that operation."""

    def __init__(self, reported_id=None, *, sign_error=None, verify_error=None):
        self.log = []
        self.digests = []
        self._reported = reported_id
        self.sign_error = sign_error
        self.verify_error = verify_error

    def __call__(self, key_id):
        return _FakeAzureCrypto(key_id, self)

    def reported(self, key_id):
        return self._reported or key_id


class _FakeAzureCrypto:
    """Stands in for ``azure.keyvault.keys.crypto.CryptographyClient`` bound to one key
    identifier. Results carry the SDK's attribute names (``WrapResult.key_id`` and
    ``encrypted_key``, ``UnwrapResult.key``, ``SignResult.signature``,
    ``VerifyResult.is_valid``). RSA-OAEP-256 and PS256 are real, so anyone holding the
    public key can wrap, but only the vault can unwrap or sign."""

    def __init__(self, key_id, vault):
        self._key_id = key_id
        self._vault = vault

    def _note(self, op, algorithm):
        self._vault.log.append((op, self._key_id, algorithm))

    def wrap_key(self, algorithm, key):
        self._note("wrap", algorithm)
        encrypted = _vault_key().public_key().encrypt(key, _OAEP)
        return types.SimpleNamespace(key_id=self._vault.reported(self._key_id),
                                     encrypted_key=encrypted)

    def unwrap_key(self, algorithm, encrypted_key):
        self._note("unwrap", algorithm)
        key = _vault_key().decrypt(encrypted_key, _OAEP)
        return types.SimpleNamespace(key_id=self._vault.reported(self._key_id), key=key)

    def sign(self, algorithm, digest):
        self._note("sign", algorithm)
        self._vault.digests.append(digest)
        if self._vault.sign_error is not None:
            raise self._vault.sign_error
        signature = _vault_key().sign(digest, _PS256, _PREHASHED)
        return types.SimpleNamespace(key_id=self._vault.reported(self._key_id),
                                     signature=signature)

    def verify(self, algorithm, digest, signature):
        self._note("verify", algorithm)
        if self._vault.verify_error is not None:
            raise self._vault.verify_error
        try:
            _vault_key().public_key().verify(signature, digest, _PS256, _PREHASHED)
            valid = True
        except InvalidSignature:
            valid = False
        return types.SimpleNamespace(key_id=self._vault.reported(self._key_id), is_valid=valid)


def _azure_kek(key_id=_AZ_V1_ID, reported_id=None, **vault_faults):
    fake = _FakeAzureVault(reported_id, **vault_faults)
    return kms_backends.AzureKeyVaultKEK(key_id=key_id, client_factory=fake), fake


def _len2(field: bytes) -> bytes:
    return len(field).to_bytes(2, "big") + field


def _envelope(encrypted_key, key_id, signature, nonce, sealed):
    return (kms_backends._AZURE_MAGIC + _len2(encrypted_key) + _len2(key_id)
            + _len2(signature) + nonce + sealed)


def _split(wrapped):
    """``(encrypted_key, key_id, signature, nonce, sealed)`` of an AZR2 envelope."""
    body = wrapped[len(kms_backends._AZURE_MAGIC):]
    fields, pos = [], 0
    for _ in range(3):
        size = int.from_bytes(body[pos:pos + 2], "big")
        fields.append(body[pos + 2:pos + 2 + size])
        pos += 2 + size
    return (*fields, body[pos:pos + 12], body[pos + 12:])


def _canonical_digest(encrypted_key, key_id, nonce, sealed, context):
    """The digest the vault signs, as documented in kms_backends: the magic, wrapped key,
    versioned key id, nonce, ciphertext and context, each with an 8-byte length prefix."""
    fields = (kms_backends._AZURE_MAGIC, encrypted_key, key_id, nonce, sealed, context)
    return hashlib.sha256(b"".join(len(f).to_bytes(8, "big") + f for f in fields)).digest()


def _sign_as_attacker(encrypted_key, key_id, nonce, sealed, context):
    return _attacker_key().sign(
        _canonical_digest(encrypted_key, key_id, nonce, sealed, context), _PS256, _PREHASHED)


def _public_key_forgery(signature_for, context=b"tenant:acme"):
    """What someone holding only the vault's public key can build: a DEK of their choice,
    wrapped with RSA-OAEP-256 and sealed with AES-GCM under the same associated data a
    real envelope uses. ``signature_for`` supplies the signature field."""
    aes_key, nonce = os.urandom(32), os.urandom(12)
    key_id = _AZ_V1_ID.encode("utf-8")
    encrypted_key = _vault_key().public_key().encrypt(aes_key, _OAEP)
    sealed = AESGCM(aes_key).encrypt(nonce, b"\x66" * 32, kms_backends._AZURE_AAD + context)
    signature = signature_for(encrypted_key, key_id, nonce, sealed, context)
    return _envelope(encrypted_key, key_id, signature, nonce, sealed)


def test_azure_round_trip_wraps_under_rsa_oaep_256():
    kek, fake = _azure_kek()
    dek = b"\x42" * 32
    wrapped = kek.wrap(dek, context=b"tenant:acme")
    assert wrapped.startswith(kms_backends._AZURE_MAGIC)
    assert dek not in wrapped
    assert kek.unwrap(wrapped, context=b"tenant:acme") == dek
    assert fake.log[0] == ("wrap", _AZ_V1_ID, "RSA-OAEP-256")
    # A fresh key and nonce per wrap: the same DEK never wraps to the same bytes.
    assert kek.wrap(dek, context=b"tenant:acme") != wrapped


def test_azure_wrong_context_fails():
    kek, _ = _azure_kek()
    wrapped = kek.wrap(b"\x42" * 32, context=b"tenant:acme")
    with pytest.raises(EncryptionUnavailable):
        kek.unwrap(wrapped, context=b"tenant:evil")
    with pytest.raises(EncryptionUnavailable):
        kek.unwrap(wrapped)  # no context is a different context too


def test_azure_tampered_ciphertext_fails():
    kek, _ = _azure_kek()
    tampered = bytearray(kek.wrap(b"\x42" * 32, context=b"c"))
    tampered[-1] ^= 0x01
    with pytest.raises(EncryptionUnavailable):
        kek.unwrap(bytes(tampered), context=b"c")


def test_azure_every_truncation_and_trailing_bytes_fail():
    kek, _ = _azure_kek()
    wrapped = kek.wrap(b"\x42" * 32, context=b"c")
    for cut in range(len(kms_backends._AZURE_MAGIC), len(wrapped)):
        with pytest.raises(EncryptionUnavailable):
            kek.unwrap(wrapped[:cut], context=b"c")
    with pytest.raises(EncryptionUnavailable):
        kek.unwrap(wrapped + b"\x00", context=b"c")


def test_azure_rejects_empty_envelope_fields():
    kek, fake = _azure_kek()
    empty_key = kms_backends._AZURE_MAGIC + b"\x00\x00" + b"\x00\x05" + b"x" * 5 + b"\x00" * 28
    with pytest.raises(EncryptionUnavailable):
        kek.unwrap(empty_key, context=b"c")
    assert not any(op == "unwrap" for op, *_ in fake.log)


@pytest.mark.parametrize("other_key_id", [
    f"https://evil-kv.vault.azure.net/keys/tenant-kek/{_AZ_V1}",   # another vault
    f"{_AZ_VAULT}/keys/other-kek/{_AZ_V1}",                        # another key name
])
def test_azure_refuses_a_stored_key_from_another_vault_or_key(other_key_id):
    kek, _ = _azure_kek()
    wrapped = kek.wrap(b"\x42" * 32, context=b"c")
    other, fake = _azure_kek(key_id=other_key_id)
    with pytest.raises(EncryptionUnavailable):
        other.unwrap(wrapped, context=b"c")
    assert not any(op == "unwrap" for op, *_ in fake.log)


def test_azure_accepts_another_version_of_the_same_key():
    kek_v1, _ = _azure_kek(key_id=_AZ_V1_ID)
    wrapped = kek_v1.wrap(b"\x42" * 32, context=b"c")
    for configured in (_AZ_V2_ID, _AZ_KEY):   # rotated to v2, or unversioned
        rotated, fake = _azure_kek(key_id=configured)
        assert rotated.unwrap(wrapped, context=b"c") == b"\x42" * 32
        # The DEK is opened with the version that wrapped it, not the configured one.
        assert ("unwrap", _AZ_V1_ID, "RSA-OAEP-256") in fake.log


@pytest.mark.parametrize("configured, reported", [
    (_AZ_KEY, _AZ_KEY),                                            # no version
    (_AZ_V1_ID, f"https://evil-kv.vault.azure.net/keys/tenant-kek/{_AZ_V1}"),
])
def test_azure_wrap_refuses_a_result_that_is_not_a_pinned_version_of_the_key(configured, reported):
    kek, _ = _azure_kek(key_id=configured, reported_id=reported)
    with pytest.raises(EncryptionUnavailable):
        kek.wrap(b"\x42" * 32, context=b"c")


def test_azure_unversioned_key_error_says_how_to_fix_it():
    # Without keys/get the SDK cannot read the current version, so the operator must
    # either pin one or grant keys/get; the error has to say so.
    kek, _ = _azure_kek(key_id=_AZ_KEY, reported_id=_AZ_KEY)
    with pytest.raises(EncryptionUnavailable, match="pin a version") as err:
        kek.wrap(b"\x42" * 32, context=b"c")
    assert "keys/get" in str(err.value)


def test_azure_foreign_key_error_does_not_send_the_operator_to_pin_a_version():
    kek, _ = _azure_kek(
        key_id=_AZ_V1_ID,
        reported_id=f"https://evil-kv.vault.azure.net/keys/tenant-kek/{_AZ_V1}")
    with pytest.raises(EncryptionUnavailable, match="different key") as err:
        kek.wrap(b"\x42" * 32, context=b"c")
    assert "pin a version" not in str(err.value)


@pytest.mark.parametrize("bad", [
    "http://acme-kv.vault.azure.net/keys/tenant-kek",              # not https
    "https://acme-kv.vault.azure.net/secrets/tenant-kek",          # a secret, not a key
    "https://acme-kv.vault.azure.net/keys/",                       # no key name
    f"{_AZ_KEY}/{_AZ_V1}/extra",                                   # too many segments
    "tenant-kek",                                                  # a bare name
    "https://user@acme-kv.vault.azure.net/keys/tenant-kek",        # userinfo
    "https://acme-kv.vault.azure.net:8443/keys/tenant-kek",        # explicit port
    "https://acme-kv.vault.azure.net/keys/tenant-kek?api-version=7.4",
    "https://acme-kv.vault.azure.net/keys/tenant/kek",             # slash in the name
])
def test_azure_rejects_a_malformed_key_id(bad):
    with pytest.raises(EncryptionUnavailable):
        kms_backends.AzureKeyVaultKEK(key_id=bad, client_factory=_FakeAzureVault())


@pytest.mark.parametrize("good", [
    _AZ_KEY,
    _AZ_V1_ID,
    "https://acme-hsm.managedhsm.azure.net/keys/tenant-kek/" + _AZ_V1,
])
def test_azure_accepts_vault_and_managed_hsm_key_ids(good):
    kek = kms_backends.AzureKeyVaultKEK(key_id=good, client_factory=_FakeAzureVault())
    assert kek.key_id == good


def test_azure_rejects_other_providers_envelopes():
    vault_wrapped = kms_backends.VaultTransitKMS(
        key_id="k", client=_FakeVault()).wrap(b"\x42" * 32, context=b"c")
    kek, _ = _azure_kek()
    with pytest.raises(EncryptionUnavailable):
        kek.unwrap(vault_wrapped, context=b"c")


# ---- Azure envelopes are signed by the vault before anything is unwrapped ---


class _SdkSignatureAlgorithm(str, enum.Enum):
    """The shape of azure.keyvault.keys.crypto.SignatureAlgorithm: a str enum whose
    ps256 member is "PS256"."""

    ps256 = "PS256"


def test_azure_sig_alg_is_the_sdk_enum_when_the_sdk_is_importable(monkeypatch):
    # The SDK's local verify reads algorithm.value, which a bare "PS256" string lacks, so
    # with the SDK present the client must be given the enum member, not the string.
    stub = types.ModuleType("azure.keyvault.keys.crypto")
    stub.SignatureAlgorithm = _SdkSignatureAlgorithm
    monkeypatch.setitem(sys.modules, "azure.keyvault.keys.crypto", stub)
    alg = kms_backends._azure_sig_alg()
    assert alg is _SdkSignatureAlgorithm.ps256
    assert alg.value == "PS256"


def test_azure_sig_alg_is_the_plain_name_without_the_sdk(monkeypatch):
    monkeypatch.setitem(sys.modules, "azure.keyvault.keys.crypto", None)
    assert kms_backends._azure_sig_alg() == "PS256"


def test_azure_sig_alg_is_the_installed_sdk_enum():
    crypto = pytest.importorskip("azure.keyvault.keys.crypto")
    assert kms_backends._azure_sig_alg() is crypto.SignatureAlgorithm.ps256


def test_azure_round_trip_is_signed_by_the_vault_under_ps256_before_unwrap():
    kek, fake = _azure_kek()
    dek = b"\x42" * 32
    wrapped = kek.wrap(dek, context=b"tenant:acme")
    assert wrapped.startswith(b"MVKKMS-AZR2\n")
    assert kek.unwrap(wrapped, context=b"tenant:acme") == dek
    assert [op for op, *_ in fake.log] == ["wrap", "sign", "verify", "unwrap"]
    assert ("sign", _AZ_V1_ID, "PS256") in fake.log
    assert ("verify", _AZ_V1_ID, "PS256") in fake.log


def test_azure_vault_signs_the_documented_canonical_digest():
    kek, fake = _azure_kek()
    wrapped = kek.wrap(b"\x42" * 32, context=b"tenant:acme")
    encrypted_key, key_id, signature, nonce, sealed = _split(wrapped)
    assert key_id == _AZ_V1_ID.encode("utf-8")
    assert fake.digests == [_canonical_digest(encrypted_key, key_id, nonce, sealed, b"tenant:acme")]
    _vault_key().public_key().verify(signature, fake.digests[0], _PS256, _PREHASHED)


def test_azure_signs_with_the_version_the_vault_wrapped_under():
    # Configured without a version; the vault reports the version it wrapped under.
    kek, fake = _azure_kek(key_id=_AZ_KEY, reported_id=_AZ_V1_ID)
    kek.wrap(b"\x42" * 32, context=b"c")
    assert ("sign", _AZ_V1_ID, "PS256") in fake.log


def test_azure_public_key_forgery_is_refused_before_unwrap():
    kek, fake = _azure_kek()
    legit_signature = _split(kek.wrap(b"\x42" * 32, context=b"tenant:acme"))[2]
    forgeries = [
        _public_key_forgery(lambda *_: b"\x00" * 256),           # unsigned: junk bytes
        _public_key_forgery(_sign_as_attacker),                  # signed by another key
        _public_key_forgery(lambda *_: legit_signature),         # another envelope's signature
    ]
    for forged in forgeries:
        with pytest.raises(EncryptionUnavailable, match="signature"):
            kek.unwrap(forged, context=b"tenant:acme")
    assert not any(op == "unwrap" for op, *_ in fake.log)


def test_azure_any_changed_byte_is_refused_before_unwrap():
    kek, fake = _azure_kek()
    wrapped = kek.wrap(b"\x42" * 32, context=b"c")
    for i in range(len(wrapped)):
        tampered = bytearray(wrapped)
        tampered[i] ^= 0x01
        with pytest.raises(EncryptionUnavailable):
            kek.unwrap(bytes(tampered), context=b"c")
    assert not any(op == "unwrap" for op, *_ in fake.log)


def test_azure_wrong_context_is_refused_before_unwrap():
    kek, fake = _azure_kek()
    wrapped = kek.wrap(b"\x42" * 32, context=b"tenant:acme")
    with pytest.raises(EncryptionUnavailable, match="signature"):
        kek.unwrap(wrapped, context=b"tenant:evil")
    assert not any(op == "unwrap" for op, *_ in fake.log)


def test_azure_unsigned_az1_envelopes_are_refused():
    # The pre-signature AZR1 layout: the same fields, with no signature field.
    kek, fake = _azure_kek()
    aes_key, nonce = os.urandom(32), os.urandom(12)
    encrypted_key = _vault_key().public_key().encrypt(aes_key, _OAEP)
    sealed = AESGCM(aes_key).encrypt(nonce, b"\x42" * 32, kms_backends._AZURE_AAD + b"c")
    az1 = b"MVKKMS-AZR1\n" + _len2(encrypted_key) + _len2(_AZ_V1_ID.encode()) + nonce + sealed
    with pytest.raises(EncryptionUnavailable):
        kek.unwrap(az1, context=b"c")
    assert not any(op == "unwrap" for op, *_ in fake.log)


def test_azure_sign_refused_by_the_vault_names_the_missing_permission():
    marker = "principal-7f3a-marker"
    kek, _ = _azure_kek(sign_error=_Forbidden(f"403 for {marker}: not authorized"))
    with pytest.raises(EncryptionUnavailable, match="keys/sign") as err:
        kek.wrap(b"\x42" * 32, context=b"c")
    assert marker not in str(err.value)
    # The service error must not ride along as __context__ either (raised outside except).
    assert err.value.__context__ is None


@pytest.mark.parametrize("error", [
    _Refused("400 for principal-7f3a-marker: bad request"),
    RuntimeError("connection reset for principal-7f3a-marker"),
])
def test_azure_sign_failure_without_a_403_names_the_key_and_the_permission(error):
    kek, _ = _azure_kek(sign_error=error)
    with pytest.raises(EncryptionUnavailable, match="allow sign") as err:
        kek.wrap(b"\x42" * 32, context=b"c")
    assert "keys/sign" in str(err.value)
    assert "principal-7f3a-marker" not in str(err.value)
    assert err.value.__context__ is None


@pytest.mark.parametrize("error", [
    _Refused("400 for principal-7f3a-marker: bad request"),
    RuntimeError("connection reset for principal-7f3a-marker"),
])
def test_azure_verify_failure_without_a_403_names_the_key_and_the_permission(error):
    kek, fake = _azure_kek(verify_error=error)
    wrapped = kek.wrap(b"\x42" * 32, context=b"c")
    with pytest.raises(EncryptionUnavailable, match="allow verify") as err:
        kek.unwrap(wrapped, context=b"c")
    assert "keys/verify" in str(err.value)
    assert "principal-7f3a-marker" not in str(err.value)
    assert not any(op == "unwrap" for op, *_ in fake.log)


@pytest.mark.parametrize("error, expected", [
    (_Forbidden("403"), "keys/verify"),
    (RuntimeError("connection reset"), "verify operation failed"),
])
def test_azure_verify_refused_by_the_vault_refuses_the_envelope(error, expected):
    kek, fake = _azure_kek(verify_error=error)
    wrapped = kek.wrap(b"\x42" * 32, context=b"c")
    with pytest.raises(EncryptionUnavailable, match=expected) as err:
        kek.unwrap(wrapped, context=b"c")
    assert err.value.__context__ is None
    assert not any(op == "unwrap" for op, *_ in fake.log)


def test_azure_missing_sdk_gives_the_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "azure.keyvault.keys.crypto", None)
    kek = kms_backends.AzureKeyVaultKEK(key_id=_AZ_V1_ID)  # no fake: the real SDK path
    with pytest.raises(EncryptionUnavailable, match=r"maverick-core\[azure-kms\]"):
        kek.wrap(b"\x42" * 32, context=b"c")


def test_build_cloud_kms_azure_dispatch(monkeypatch):
    monkeypatch.delenv("MAVERICK_KMS_KEY_ID", raising=False)
    kek = kms_backends.build_cloud_kms("azure", {"key_id": _AZ_V1_ID})
    assert isinstance(kek, kms_backends.AzureKeyVaultKEK)
    assert kek.key_id == _AZ_V1_ID
    tenant = kms_backends.build_cloud_kms("azure", {"key_id": _AZ_V1_ID}, key_id=_AZ_V2_ID)
    assert tenant.key_id == _AZ_V2_ID  # a pinned tenant key outranks the config key
    with pytest.raises(EncryptionUnavailable):
        kms_backends.build_cloud_kms("azure", {"key_id": "operator-global"})


def test_azure_key_id_is_required(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", lambda: {"kms": {}})
    monkeypatch.delenv("MAVERICK_KMS_KEY_ID", raising=False)
    with pytest.raises(EncryptionUnavailable):
        kms_backends.AzureKeyVaultKEK()


# ---- factory + get_kms dispatch -------------------------------------------


def test_build_cloud_kms_dispatch(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"kms": {"provider": "aws", "key_id": "k"}})
    assert isinstance(kms_backends.build_cloud_kms("aws"), kms_backends.AwsKmsKEK)
    assert isinstance(kms_backends.build_cloud_kms("gcp"), kms_backends.GcpKmsKEK)
    assert isinstance(kms_backends.build_cloud_kms("vault"),
                      kms_backends.VaultTransitKMS)


@pytest.mark.parametrize("provider", ["aws", "gcp", "vault"])
def test_explicit_key_id_beats_the_server_wide_env_key(monkeypatch, provider):
    monkeypatch.setenv("MAVERICK_KMS_KEY_ID", "operator-global")
    kms = kms_backends.build_cloud_kms(
        provider, {"key_id": "cfg-key"}, key_id="tenant-byok")
    assert kms.key_id == "tenant-byok"


@pytest.mark.parametrize("provider", ["aws", "gcp", "vault"])
def test_env_key_is_used_when_no_explicit_key_id(monkeypatch, provider):
    monkeypatch.setenv("MAVERICK_KMS_KEY_ID", "operator-global")
    kms = kms_backends.build_cloud_kms(provider, {"key_id": "cfg-key"})
    assert kms.key_id == "operator-global"


def test_build_cloud_kms_unknown_fails():
    with pytest.raises(EncryptionUnavailable):
        kms_backends.build_cloud_kms("oracle")


def test_missing_key_id_fails(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", lambda: {"kms": {}})
    monkeypatch.delenv("MAVERICK_KMS_KEY_ID", raising=False)
    with pytest.raises(EncryptionUnavailable):
        kms_backends.AwsKmsKEK()


def test_get_kms_routes_to_cloud(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"kms": {"provider": "vault", "key_id": "k"}})
    assert isinstance(tenant_kms.get_kms(), kms_backends.VaultTransitKMS)


def test_get_kms_routes_to_azure(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config",
                        lambda: {"kms": {"provider": "azure", "key_id": _AZ_V1_ID}})
    assert isinstance(tenant_kms.get_kms(), kms_backends.AzureKeyVaultKEK)


def test_get_kms_local_default(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", lambda: {"kms": {"provider": "local"}})
    assert isinstance(tenant_kms.get_kms(), tenant_kms.LocalKMS)


def test_get_kms_unknown_provider_fails(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", lambda: {"kms": {"provider": "oracle"}})
    with pytest.raises(EncryptionUnavailable):
        tenant_kms.get_kms()


# ---- integration: tenant seal/unseal through a cloud KEK ------------------


def test_tenant_seal_through_cloud_kms(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    tenant_kms._clear_cache()
    kms = kms_backends.AwsKmsKEK(key_id="k", client=_FakeAws())
    blob = tenant_kms.seal_for_tenant("acme", b"phi-data", kms=kms)
    assert b"phi-data" not in blob
    assert tenant_kms.unseal_for_tenant("acme", blob, kms=kms) == b"phi-data"
    tenant_kms._clear_cache()
