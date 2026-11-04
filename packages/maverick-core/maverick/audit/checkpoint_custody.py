"""Independently retained, signed checkpoint prefixes in AWS S3 Compliance storage.

No ambient credentials, local staging, provider retry or caller-supplied trust
pin. A complete bounded remote version inventory supplies the verification pin.
The existing checkpoint signatures and local prefix verifier remain authoritative.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import re
import time

from .. import connections
from ..authority_effects import authority_effect_fence
from . import checkpoints, signing, worm

SCHEMA = "lightwork.audit.independent-checkpoint.v1"
MAX_CHECKPOINTS = 2000
MAX_BYTES = 4 * 1024 * 1024
MAX_VERSIONS = 10_000
PAGE_SIZE = 128
MAX_INVENTORY_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 60


class CustodyRefused(ValueError):
    """A complete current verification or safe dispatch cannot be established."""


class CustodyUnconfirmed(RuntimeError):
    """A physical upload was attempted. It must never be automatically repeated."""


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def trusted(keys=None):
    return checkpoints._trusted_key_map(pubkey_hex=None, trusted_pubkeys=keys)


def capture(directory, *, keys=None):
    """Capture exact signed bytes, not a reconstructed checkpoint."""
    files = checkpoints._checkpoint_files(directory)
    if not files or len(files) > MAX_CHECKPOINTS:
        raise CustodyRefused("Publish checkpoints first. One retained prefix can contain at most 2,000 checkpoints.")
    chain = checkpoints._load_checkpoint_chain(directory, trusted(keys))
    rows = [item.raw.decode("utf-8") for item in chain]
    if len(encoded(rows)) > MAX_BYTES // 2:
        raise CustodyRefused("This checkpoint prefix is too large for one independent copy. Nothing was copied.")
    return {"records": rows, "sequence": len(rows), "checkpoint_sha256": chain[-1].digest,
            "day": chain[-1].record["day"], "row_count": chain[-1].record["row_count"]}


def bundle(source, *, workspace, actor, reviewer, destination, retain_until):
    body = {"schema": SCHEMA, "workspace": workspace, "requested_by": actor,
            "reviewed_by": reviewer, "destination": destination, "retain_until": retain_until,
            "checkpoint_sequence": source["sequence"], "checkpoint_sha256": source["checkpoint_sha256"],
            "records": source["records"]}
    proof = signing.sign_detached_digest(sha(encoded(body)))
    return encoded({"manifest": body, "signature": proof})


def _validated(raw, *, workspace, destination, keys):
    try:
        value = json.loads(raw)
        if set(value) != {"manifest", "signature"}:
            raise ValueError
        body, proof = value["manifest"], value["signature"]
        if (set(body) != {"schema", "workspace", "requested_by", "reviewed_by", "destination", "retain_until",
                         "checkpoint_sequence", "checkpoint_sha256", "records"}
                or body["schema"] != SCHEMA or body["workspace"] != workspace
                or body["destination"] != destination
                or not isinstance(body["requested_by"], str) or not isinstance(body["reviewed_by"], str)
                or not body["requested_by"] or not body["reviewed_by"]
                or body["requested_by"] == body["reviewed_by"]
                or set(proof) != {"algorithm", "digest", "key_id", "message_version", "signature"}
                or proof.get("algorithm") != "Ed25519-SHA256"
                or proof.get("message_version") != signing.DETACHED_DIGEST_MESSAGE_VERSION
                or proof.get("digest") != sha(encoded(body))
                or not signing.verify_detached_digest(keys.get(proof.get("key_id"), ""), proof["digest"], proof["signature"])):
            raise ValueError
        rows = body["records"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_CHECKPOINTS or body["checkpoint_sequence"] != len(rows):
            raise ValueError
        hashes, previous, days, retired = [], "", {}, set()
        for sequence, text in enumerate(rows, 1):
            if not isinstance(text, str) or len(text.encode()) > checkpoints._MAX_CHECKPOINT_BYTES:
                raise ValueError
            signed = checkpoints._verify_signed_text(text, keys, label="retained checkpoint")
            if len(signed) != 1:
                raise ValueError
            row = signed[0]
            checkpoints._validate_record_shape(row, expected_sequence=sequence)
            if row["previous_checkpoint_sha256"] != previous or row["prev_hash"] != "":
                raise ValueError
            day, kind = row["day"], row["record_type"]
            prior = days.get(day)
            if kind == "checkpoint":
                if day in retired or (prior and (row["row_count"] < prior[0]["row_count"] or
                        (row["row_count"] == prior[0]["row_count"] and row["tip_hash"] != prior[0]["tip_hash"]))):
                    raise ValueError
            elif (not prior or row["supersedes_checkpoint_sha256"] != prior[1] or day in retired):
                raise ValueError
            elif kind == "retirement":
                if row["row_count"] != prior[0]["row_count"] or row["tip_hash"] != prior[0]["tip_hash"]:
                    raise ValueError
                retired.add(day)
            previous = sha(text.encode())
            hashes.append(previous)
            days[day] = (row, previous)
        if body["checkpoint_sha256"] != previous or worm._parse_utc(body["retain_until"]) is None:
            raise ValueError
        return body, hashes, row["day"]
    except (KeyError, TypeError, ValueError, checkpoints.AuditCheckpointError) as exc:
        raise CustodyRefused("A retained checkpoint's identity, signature or complete history could not be verified.") from exc


def _client(credential, region):
    """Closed stock SDK transport, explicitly pinned credentials and no retries."""
    import boto3
    from botocore.config import Config
    try:
        token = json.loads(credential["token"])
        if (not isinstance(token, dict) or set(token) - {"access_key_id", "secret_access_key", "session_token", "region"}
                or token.get("region") != region
                or not re.fullmatch(r"[A-Z0-9]{16,128}", token.get("access_key_id", ""))
                or not isinstance(token.get("secret_access_key"), str)
                or not 16 <= len(token["secret_access_key"]) <= 256
                or any(c in token["secret_access_key"] for c in "\r\n")):
            raise ValueError
        session = token.get("session_token")
        if session is not None and (not isinstance(session, str) or not 8 <= len(session) <= 16384 or "\n" in session or "\r" in session):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise CustodyRefused("The selected saved Amazon account does not match this storage region. Update it in Connections.") from exc
    return boto3.client("s3", region_name=region, endpoint_url="https://s3." + region + ".amazonaws.com",
        aws_access_key_id=token["access_key_id"],
        aws_secret_access_key=token["secret_access_key"], aws_session_token=session,
        config=Config(connect_timeout=5, read_timeout=5, retries={"total_max_attempts": 1},
                      s3={"addressing_style": "virtual"}))


class RetainedCheckpoints:
    def __init__(self, destination, account, *, workspace, actor, guard, keys=None):
        self.destination, self.account = destination, account
        self.workspace, self.actor, self.guard = workspace, actor, guard
        self.keys = trusted(keys)
        self.deadline = time.monotonic() + MAX_SECONDS
        self.prefix = destination["prefix"].rstrip("/") + "/checkpoints/" + sha(encoded(workspace)) + "/"
        self.prefix = self.prefix.lstrip("/")
        self.origin = "https://" + destination["bucket"] + ".s3." + destination["region"] + ".amazonaws.com"

    def call(self, method, **arguments):
        # Do not hold authority across a multi-call scan. Each bounded physical
        # call (including its response body) independently rechecks the pin.
        with authority_effect_fence():
            if time.monotonic() >= self.deadline:
                raise CustodyRefused("Independent storage did not complete within 60 seconds. No partial verification was accepted.")
            self.guard()
            with connections.bind_principal(self.actor):
                credential = connections.resolve_named(self.account["name"], expected_revision=self.account["revision"],
                    connector="aws_s3", origin=self.origin)
            if credential.get("owner") != self.actor:
                raise CustodyRefused("Choose an Amazon account owned by your signed-in account.")
            client = _client(credential, self.destination["region"])
            self.guard()
            try:
                value = getattr(client, method)(Bucket=self.destination["bucket"], **arguments)
                if method == "get_object":
                    body = value.get("Body")
                    try:
                        raw = body.read(MAX_BYTES + 1)
                    finally:
                        if hasattr(body, "close"):
                            body.close()
                    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
                        raise CustodyRefused("A retained checkpoint exceeded the complete read limit.")
                    value["Body"] = io.BytesIO(raw)
                self.guard()
                if time.monotonic() >= self.deadline:
                    raise CustodyRefused("Independent storage did not complete within 60 seconds. No partial verification was accepted.")
                return value
            finally:
                if hasattr(client, "close"):
                    client.close()

    def _sink(self, prefix):
        sink = worm.S3WormSink(bucket=self.destination["bucket"], prefix=prefix,
                               mode="COMPLIANCE", region=self.destination["region"])
        transport = self

        class ExactClient:
            def put_object(self, **kwargs):
                kwargs.pop("Bucket")
                return transport.call("put_object", IfNoneMatch="*", **kwargs)

            def get_object(self, **kwargs):
                kwargs.pop("Bucket")
                return transport.call("get_object", **kwargs)

            def get_object_retention(self, **kwargs):
                kwargs.pop("Bucket")
                return transport.call("get_object_retention", **kwargs)

        sink._client = ExactClient()
        return sink

    def inventory(self):
        """Discover all retained versions without any dependency on local receipts."""
        versions, markers, seen, cursor = [], [], set(), {}
        while True:
            listing = self.call("list_object_versions", Prefix=self.prefix, MaxKeys=PAGE_SIZE, **cursor)
            found, deleted = listing.get("Versions", []), listing.get("DeleteMarkers", [])
            if not isinstance(found, list) or not isinstance(deleted, list) or not isinstance(listing.get("IsTruncated"), bool):
                raise CustodyRefused("Independent version inventory is incomplete. No partial verification was accepted.")
            versions.extend(found)
            markers.extend(deleted)
            if len(versions) + len(markers) > MAX_VERSIONS:
                raise CustodyRefused("Independent history exceeds 10,000 versions. No partial verification was accepted.")
            if not listing["IsTruncated"]:
                break
            key, version = listing.get("NextKeyMarker"), listing.get("NextVersionIdMarker")
            if not isinstance(key, str) or not key.startswith(self.prefix) or not isinstance(version, str) or not version or (key, version) in seen:
                raise CustodyRefused("Independent version pagination did not establish complete coverage.")
            seen.add((key, version))
            cursor = {"KeyMarker": key, "VersionIdMarker": version}
        pattern = re.compile(re.escape(self.prefix) + r"([0-9]{20})/([a-f0-9]{64})/(\d{4}-\d{2}-\d{2}\.ndjson)\Z")
        observed, commitments, expired, total_bytes = [], {}, 0, 0
        for item in markers:
            if not pattern.fullmatch(str(item.get("Key", ""))):
                raise CustodyRefused("The independent checkpoint folder contains an unexpected object.")
        for item in versions:
            key, version = item.get("Key", ""), item.get("VersionId")
            match = pattern.fullmatch(str(key))
            if not match or not isinstance(version, str) or not version or version == "null":
                raise CustodyRefused("An independent checkpoint has no verifiable object version.")
            obj = self.call("get_object", Key=key, VersionId=version)
            if obj.get("VersionId") != version:
                raise CustodyRefused("The storage provider returned a different checkpoint version.")
            raw = obj["Body"].read()
            total_bytes += len(raw)
            if total_bytes > MAX_INVENTORY_BYTES:
                raise CustodyRefused("Independent checkpoint contents exceed the complete 64 MB read limit. No partial verification was accepted.")
            body, hashes, day = _validated(raw, workspace=self.workspace, destination=self.destination, keys=self.keys)
            if int(match[1]) != len(hashes) or match[2] != sha(raw) or match[3] != day + ".ndjson":
                raise CustodyRefused("An independent checkpoint does not match its retained address.")
            until = worm._parse_utc(body["retain_until"])
            if until <= dt.datetime.now(dt.timezone.utc):
                expired += 1
                continue
            sink = self._sink(key.removesuffix(match[3]))
            locator = {"target": "s3", "bucket": self.destination["bucket"], "key": key, "mode": "COMPLIANCE",
                       "version_id": version, "authority_id": sink._authority_id(), "retain_until": body["retain_until"]}
            if not sink.verify(locator, sha(raw)):
                raise CustodyRefused("The exact independent checkpoint bytes or Compliance retention could not be confirmed.")
            for sequence, digest in enumerate(hashes, 1):
                if sequence in commitments and commitments[sequence] != digest:
                    raise CustodyRefused("Independent storage contains conflicting checkpoint histories. A signed fork was found; verification was refused.")
                commitments[sequence] = digest
            observed.append({"sequence": len(hashes), "checkpoint_sha256": hashes[-1], "payload_sha256": sha(raw),
                             "locator": locator, "retain_until": body["retain_until"]})
        self.guard()
        return {"versions": observed, "expired": expired, "complete": True}

    def upload(self, raw, source, retain_until):
        if len(raw) > MAX_BYTES:
            raise CustodyRefused("This complete checkpoint copy is too large. Nothing was uploaded.")
        settings = self.call("get_object_lock_configuration")
        versioning = self.call("get_bucket_versioning")
        if settings.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled" or versioning.get("Status") != "Enabled":
            raise CustodyRefused("Enable Object Lock and versioning on the selected Amazon bucket before copying checkpoints.")
        sink = self._sink(self.prefix + f'{source["sequence"]:020d}/' + sha(raw) + "/")
        # Once PUT is entered, even a lost reply or a withdrawn permission
        # leaves an unknown outcome. Original can read; it cannot replay PUT.
        try:
            locator = sink.put(source["day"] + ".ndjson", raw, retain_until=retain_until)
            if not sink.verify(locator, sha(raw)):
                raise CustodyUnconfirmed
            self.guard()
            return locator
        except Exception as exc:  # failure-policy: fail_closed -- any error after PUT is an unknown outcome, never success or retry
            raise CustodyUnconfirmed("The upload may have happened. Read the original retained result; do not repeat this request.") from exc


def verify_current(transport, audit_dir, checkpoint_dir, *, keys=None):
    remote = transport.inventory()
    if not remote["versions"]:
        return {"verified": False, "reason": "No currently locked independent checkpoint was found.",
                "expired_versions": remote["expired"], "complete_inventory": True}
    pin = max(remote["versions"], key=lambda row: row["sequence"])
    breaks = checkpoints.verify_checkpoints(audit_dir, checkpoint_dir, trusted_pubkeys=keys,
        minimum_sequence=pin["sequence"], minimum_digest=pin["checkpoint_sha256"])
    transport.guard()
    if time.monotonic() >= transport.deadline:
        raise CustodyRefused("Independent history verification did not complete within 60 seconds. No partial result was accepted.")
    return {"verified": not breaks, "remote_sequence": pin["sequence"], "checkpoint_sha256": pin["checkpoint_sha256"],
            "retained_until": pin["retain_until"], "complete_inventory": True,
            "expired_versions": remote["expired"], "problems": sorted({item.reason for item in breaks}),
            "scope": "Signed checkpoint prefixes and their lifecycle evidence were checked against independently read, currently locked Amazon versions. Later audit entries, administrator independence, future availability and expired locks are outside this result."}
