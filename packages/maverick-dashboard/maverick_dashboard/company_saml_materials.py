"""Uploaded SAML documents in encrypted deployment custody, never public files."""
from __future__ import annotations

import base64
import json
import re
import tempfile
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from fastapi import HTTPException
from maverick import crypto_at_rest, file_lock
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore

from .company_signin_migration import deployment

PREFIX = "managed-saml:"
MAX_BYTES = 256 * 1024
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"


def store():
    return GovernedRecordStore("company-saml-materials", "SMD", "company_saml_material",
                               authority_scope="deployment_global")


def _certificate(raw):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa

    certificate = x509.load_pem_x509_certificate(raw)
    key = certificate.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise ValueError("Use a current RSA certificate of at least 2048 bits.")
    if not certificate.not_valid_before_utc.timestamp() <= time.time() < certificate.not_valid_after_utc.timestamp():
        raise ValueError("The certificate is not currently valid.")
    return certificate


def validate(metadata, certificate=b"", key=b"", password=b""):
    """Closed, finite metadata; signatures remain PySAML2's responsibility."""
    from xml.etree.ElementTree import ParseError

    from cryptography.hazmat.primitives import serialization
    from defusedxml.common import DefusedXmlException
    from defusedxml.ElementTree import fromstring

    try:
        if not metadata or sum(map(len, (metadata, certificate, key))) > MAX_BYTES:
            raise ValueError("Choose files totalling no more than 256 KB.")
        root = fromstring(metadata, forbid_dtd=True)
        entities = [root] if root.tag == MD + "EntityDescriptor" else list(root)
        if root.tag not in {MD + "EntityDescriptor", MD + "EntitiesDescriptor"} or len(entities) != 1:
            raise ValueError("Choose metadata for one sign-in provider.")
        entity = entities[0]
        provider = entity.find(MD + "IDPSSODescriptor")
        if entity.tag != MD + "EntityDescriptor" or provider is None:
            raise ValueError("Choose your identity provider's metadata document.")
        identity = entity.attrib.get("entityID", "")
        if not identity or len(identity) > 300:
            raise ValueError("The provider name in this document is unavailable.")
        from urllib.parse import urlparse
        addresses = [node.attrib.get("Location", "") for node in provider.findall(MD + "SingleSignOnService")]
        if not addresses or any(urlparse(address).scheme != "https" or not urlparse(address).hostname
                                or urlparse(address).username or urlparse(address).password for address in addresses):
            raise ValueError("The provider must publish an HTTPS sign-in address.")
        certificates = [node.text or "" for node in provider.findall(".//" + DS + "X509Certificate")]
        if not certificates or len(certificates) > 10:
            raise ValueError("The provider must publish a bounded set of signing certificates.")
        signing = []
        for text in certificates:
            encoded = base64.b64decode("".join(text.split()), validate=True)
            pem = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(encoded) + b"-----END CERTIFICATE-----\n"
            cert = _certificate(pem)
            from cryptography.hazmat.primitives import hashes
            signing.append({"Certificate name": cert.subject.rfc4514_string(),
                            "Issued by": cert.issuer.rfc4514_string(),
                            "Valid until": cert.not_valid_after_utc.isoformat(),
                            "Public certificate fingerprint": cert.fingerprint(hashes.SHA256()).hex()})
        expires = root.attrib.get("validUntil") or entity.attrib.get("validUntil")
        if expires:
            from .saml import _iso_to_epoch
            if not time.time() < _iso_to_epoch(expires):
                raise ValueError("The provider metadata has expired.")
        if bool(certificate) != bool(key):
            raise ValueError("Choose both Lightwork's certificate and its matching private key, or neither.")
        if key:
            cert = _certificate(certificate)
            private = serialization.load_pem_private_key(key, password=password or None)
            public = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            if public != cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                raise ValueError("The private key does not match Lightwork's certificate.")
            key = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return {"metadata": metadata.decode("utf-8-sig"), "certificate": certificate.decode("ascii"),
                "key": key.decode("ascii")}, {"Provider": identity, "Sign-in addresses": addresses,
                                              "Provider signing certificates": signing,
                                              "Lightwork's certificate and private key": "Supplied" if key else "Not supplied"}
    except (ValueError, TypeError, UnicodeError, ParseError, DefusedXmlException) as exc:
        raise HTTPException(422, "These single sign-on files could not be validated. Check the provider metadata, current RSA certificates and matching private key.") from exc


def retain(record_id, material, summary, *, actor, owner, guard):
    with deployment():
        sealed = crypto_at_rest.seal_to_str(json.dumps(material, separators=(",", ":")))
        if not crypto_at_rest.is_sealed_str(sealed):
            raise HTTPException(503, "Protected sign-in files could not be retained. Nothing was enabled.")
        row = store().create({"id": record_id, "actor": actor, "owner": owner, "material": sealed,
                              "summary": summary, "digest": digest(material)}, actor=actor,
                             action="company_saml_files_retained", max_records=1000, effect_guard=guard)
    return row


def resolve(reference):
    if not isinstance(reference, str) or not re.fullmatch(r"managed-saml:SMD-[a-f0-9]{32}", reference):
        raise HTTPException(409, "The saved protected sign-in files cannot be identified.")
    with deployment():
        row = store().get(reference.removeprefix(PREFIX))
        if not row or row.get("_audit_pending") or not crypto_at_rest.is_sealed_str(row.get("material", "")):
            raise HTTPException(503, "The protected sign-in files are unavailable or not confirmed. Nothing was enabled.")
        material = json.loads(crypto_at_rest.unseal_from_str(row["material"]))
    if not isinstance(material, dict) or set(material) != {"metadata", "certificate", "key"} or digest(material) != row["digest"]:
        raise HTTPException(503, "The protected sign-in files could not be verified.")
    # Expiry and certificate validity remain current, rather than upload-only.
    checked, _summary = validate(*(material[name].encode() for name in ("metadata", "certificate", "key")))
    if checked != material:
        raise HTTPException(503, "The retained sign-in files differ from their validated form.")
    return row, material


@contextmanager
def materialized(cfg):
    if not cfg.idp_metadata_file.startswith(PREFIX):
        yield cfg
        return
    _row, material = resolve(cfg.idp_metadata_file)
    # These temporary files exist only throughout the native parser/signing call.
    with tempfile.TemporaryDirectory(prefix="lightwork-saml-") as folder:
        file_lock.prepare_private_directory(folder)
        paths = {}
        for name, value in material.items():
            if value:
                path = Path(folder) / name
                file_lock.atomic_write_text(path, value, mode=0o600)
                paths[name] = str(path)
        yield replace(cfg, idp_metadata_url="", idp_metadata_file=paths["metadata"],
                      sp_cert_file=paths.get("certificate", ""), sp_key_file=paths.get("key", ""))


def display(reference):
    row, _material = resolve(reference)
    return "Protected uploaded files for " + row["summary"]["Provider"]
