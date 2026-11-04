"""Map device-signed native consent operations onto existing authorities.

The protocol and durable replay boundary live in
``maverick.consent_native_sdk``.  This adapter does not create another consent
store: it resolves the already-enrolled public service client by digest and
uses the existing publishing, preference, public-profile, identity-pairing and
consumer-rights authorities.  Every call re-resolves current client/profile
revocation state and current publication/policy state before mutation.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable, Mapping
from typing import Any

from maverick.consent_native_sdk import (
    NativeApplicationAuthority,
    NativeConsentConflict,
    NativeConsentDenied,
    NativeConsentIntegrityError,
    NativeDeviceAuthority,
)
from maverick.consent_preferences import ConsentContext, PreferenceChoice

from .consent_identity_federation_api import resolve_consent_pairing_context
from .consent_public_api import PublicConsentDependencies, PublicProfileBinding


class LightworkNativeConsentBackend:
    """Closed operation handler for :class:`NativeConsentGateway`.

    ``profile_linker`` must independently resolve and consume an identity
    pairing authorization. ``rights_requester`` must build the existing
    verified consumer-rights intake authority. Those two security boundaries
    deliberately have no permissive default.
    """

    def __init__(
        self,
        public: PublicConsentDependencies,
        *,
        profile_linker: Callable[..., Mapping[str, Any]] | None = None,
        rights_requester: Callable[..., Mapping[str, Any]] | None = None,
        standards_wire_verifier: Callable[..., Mapping[str, Any]] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.public = public
        self.profile_linker = profile_linker
        self.rights_requester = rights_requester
        self.standards_wire_verifier = standards_wire_verifier
        self.clock = clock

    @staticmethod
    def _same(left: object, right: object) -> bool:
        return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)

    @staticmethod
    def _idempotency(
        namespace: str,
        authority: NativeApplicationAuthority,
        device: NativeDeviceAuthority,
        profile: PublicProfileBinding | None,
        presented: str,
    ) -> str:
        material = (
            f"{namespace}\0{authority.tenant_id}\0{authority.application_ref}\0"
            f"{device.device_id}\0{profile.profile_id if profile else '-'}\0{presented}"
        )
        return f"native-{namespace}-" + hashlib.sha256(material.encode()).hexdigest()

    @staticmethod
    def _actor(
        authority: NativeApplicationAuthority,
        device: NativeDeviceAuthority,
    ) -> str:
        return hashlib.sha256(
            (
                f"native-consent\0{authority.tenant_id}\0{authority.application_ref}\0"
                f"{device.device_id}\0{device.install_subject_sha256}"
            ).encode()
        ).hexdigest()

    def _client(self, authority: NativeApplicationAuthority):
        client = self.public.credential_store.resolve_client_authority(
            authority.public_client_credential_sha256
        )
        expected = {
            "tenant_id": authority.tenant_id,
            "property_id": authority.property_id,
            "client_kind": "service",
            "service_client_id": authority.application_ref,
            "target_bundle_id": authority.application_id,
            "target_platform": authority.platform,
            "revision": authority.public_client_revision,
            "record_sha256": authority.public_client_record_sha256,
            "property_revision": authority.property_revision,
            "property_sha256": authority.property_sha256,
            "publication_sha256": authority.publication_sha256,
            "bundle_sha256": authority.publication_bundle_sha256,
            "policy_id": authority.policy_id,
            "policy_version": authority.policy_version,
            "policy_sha256": authority.policy_sha256,
        }
        if any(getattr(client, name, None) != value for name, value in expected.items()):
            raise NativeConsentConflict("public service-client authority changed")
        return client

    def _profile(self, client: object, payload: Mapping[str, Any]) -> PublicProfileBinding:
        digest = payload.get("profile_credential_sha256")
        if not isinstance(digest, str):
            raise NativeConsentDenied("profile capability authority is unavailable")
        profile = self.public.credential_store.resolve_profile_authority(digest, client)
        if not isinstance(profile, PublicProfileBinding):
            raise NativeConsentDenied("profile capability authority is unavailable")
        return profile

    def _configuration(
        self,
        authority: NativeApplicationAuthority,
        client: object,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        publishing = self.public.publishing_store_for(authority.tenant_id)
        configuration = publishing.resolve_public_configuration(
            authority.tenant_id,
            authority.property_id,
            server_origin=getattr(client, "target_origin", None),
            server_bundle_id=authority.application_id,
            server_platform=authority.platform,
            jurisdiction=getattr(client, "jurisdiction", ""),
            country_code=getattr(client, "country_code", ""),
            region_code=getattr(client, "region_code", ""),
            requested_locale=getattr(client, "default_locale", authority.default_locale),
            evaluated_at=self.clock(),
        )
        publication = configuration.get("publication") if isinstance(configuration, Mapping) else None
        property_binding = configuration.get("property") if isinstance(configuration, Mapping) else None
        if (
            not isinstance(configuration, Mapping)
            or configuration.get("allowed") is not True
            or not isinstance(publication, Mapping)
            or not isinstance(property_binding, Mapping)
            or property_binding.get("property_id") != authority.property_id
            or property_binding.get("revision") != authority.property_revision
            or (
                property_binding.get("record_sha256") is not None
                and not self._same(
                    property_binding.get("record_sha256"),
                    authority.property_sha256,
                )
            )
            or not self._same(publication.get("publication_sha256"), authority.publication_sha256)
            or not self._same(publication.get("bundle_sha256"), authority.publication_bundle_sha256)
            or not self._same(configuration.get("configuration_sha256"), authority.configuration_sha256)
        ):
            raise NativeConsentConflict("published native consent configuration changed")
        preferences = self.public.preference_store_for(authority.tenant_id)
        policy = preferences.get_active_policy(
            authority.tenant_id, authority.policy_id, at=self.clock(),
        )
        if (
            not isinstance(policy, Mapping)
            or policy.get("version") != authority.policy_version
            or not self._same(policy.get("policy_sha256"), authority.policy_sha256)
        ):
            raise NativeConsentConflict("native policy authority changed")
        content = configuration.get("configuration")
        purposes = content.get("purposes") if isinstance(content, Mapping) else None
        notice = content.get("notice") if isinstance(content, Mapping) else None
        if not isinstance(purposes, list) or not isinstance(notice, Mapping):
            raise NativeConsentConflict("published native consent content is unavailable")
        published: dict[str, str] = {}
        for item in purposes:
            if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
                raise NativeConsentConflict("published native consent content is unavailable")
            if item["id"] in published:
                raise NativeConsentConflict("published native consent purposes repeat")
            published[item["id"]] = str(item.get("lawful_basis", ""))
        if published != policy.get("purposes") or not self._same(
            notice.get("document_sha256"), policy.get("notice_sha256")
        ):
            raise NativeConsentConflict("published native consent policy changed")
        return dict(configuration), dict(policy)

    def _context(self, authority: NativeApplicationAuthority, client: object) -> ConsentContext:
        return ConsentContext(
            jurisdiction=str(getattr(client, "jurisdiction", "")),
            country_code=str(getattr(client, "country_code", "")),
            region_code=str(getattr(client, "region_code", "")),
            collection_point=authority.platform,
            asserted_source="client",
        )

    def __call__(
        self,
        authority: NativeApplicationAuthority,
        device: NativeDeviceAuthority,
        operation: str,
        payload: Mapping[str, Any],
        request_id: str,
    ) -> Mapping[str, Any]:
        client = self._client(authority)
        configuration, policy = self._configuration(authority, client)
        preferences = self.public.preference_store_for(authority.tenant_id)
        if operation == "configuration":
            return configuration
        if operation == "bootstrap_profile":
            result = self.public.credential_store.bootstrap_profile(
                client,
                subject_sha256=str(payload["subject_sha256"]),
                profile_credential_sha256=str(payload["profile_credential_sha256"]),
                idempotency_key=self._idempotency(
                    "bootstrap",
                    authority,
                    device,
                    None,
                    str(payload["idempotency_key"]),
                ),
                create_profile=lambda profile_id, subject_binding_sha256, idempotency_key: (
                    preferences.create_profile(
                        authority.tenant_id,
                        profile_id,
                        "anonymous",
                        subject_binding_sha256,
                        idempotency_key,
                    )
                ),
            )
            return dict(result)

        profile = self._profile(client, payload)
        # This resolver double-checks profile/publication/policy/link CAS pins.
        pairing_context = resolve_consent_pairing_context(self.public, client, profile)
        if not self._same(pairing_context.configuration_sha256, authority.configuration_sha256):
            raise NativeConsentConflict("native profile configuration changed")

        if operation == "current_preferences":
            purpose_rows = configuration["configuration"]["purposes"]
            decisions = [
                preferences.decide(
                    authority.tenant_id,
                    profile.profile_id,
                    str(item["id"]),
                    policy_id=authority.policy_id,
                    policy_version=authority.policy_version,
                    at=self.clock(),
                ).as_dict()
                for item in purpose_rows
            ]
            revisions = {
                item.get("profile_revision")
                for item in decisions
                if item.get("profile_revision") is not None
            }
            if len(revisions) != 1:
                raise NativeConsentIntegrityError("profile preference revision is incomplete")
            return {
                "profile_revision": revisions.pop(),
                "preferences": [
                    {
                        "purpose_id": source["id"],
                        "granted": bool(decision["allowed"]),
                        "reason": decision["reason"],
                        "receipt_sha256": decision["receipt_sha256"],
                    }
                    for source, decision in zip(purpose_rows, decisions, strict=True)
                ],
                "configuration_sha256": authority.configuration_sha256,
                "policy_sha256": authority.policy_sha256,
            }

        actor = self._actor(authority, device)
        if operation == "record_preferences":
            choices = [
                PreferenceChoice(
                    purpose_id=str(item["purpose_id"]),
                    action=str(item["action"]),
                    channel=str(item["channel"]),
                    vendor_id=str(item["vendor_id"]),
                    expires_at=item["expires_at"],
                )
                for item in payload["choices"]
            ]
            return preferences.record_preferences(
                authority.tenant_id,
                profile.profile_id,
                authority.policy_id,
                authority.policy_version,
                self._context(authority, client),
                choices,
                expected_revision=int(payload["expected_revision"]),
                idempotency_key=self._idempotency(
                    "preferences",
                    authority,
                    device,
                    profile,
                    str(payload["idempotency_key"]),
                ),
                actor_sha256=actor,
            )

        if operation == "privacy_signals":
            signals = payload["signals"]
            if not self._same(
                signals.get("standards_contract_sha256"),
                authority.standards_contract_sha256,
            ):
                raise NativeConsentConflict("consent standards contract changed")
            standards_evidence: dict[str, Any] = {
                "verifier_authority": None,
                "verification_sha256": None,
            }
            if signals.get("tcf_string") is not None or signals.get("gpp_string") is not None:
                if not callable(self.standards_wire_verifier):
                    raise NativeConsentDenied("certified consent-string authority is unavailable")
                try:
                    verified = self.standards_wire_verifier(
                        tenant_id=authority.tenant_id,
                        application_ref=authority.application_ref,
                        standards_contract_sha256=authority.standards_contract_sha256,
                        tcf_string=signals.get("tcf_string"),
                        tcf_string_sha256=signals.get("tcf_string_sha256"),
                        gpp_string=signals.get("gpp_string"),
                        gpp_string_sha256=signals.get("gpp_string_sha256"),
                    )
                except Exception as exc:
                    raise NativeConsentDenied(
                        "certified consent-string verification failed"
                    ) from exc
                expected = {
                    "standards_contract_sha256": authority.standards_contract_sha256,
                    "tcf_string_sha256": signals.get("tcf_string_sha256"),
                    "gpp_string_sha256": signals.get("gpp_string_sha256"),
                }
                if (
                    not isinstance(verified, Mapping)
                    or verified.get("allowed") is not True
                    or any(
                        (verified.get(name) is not None if value is None else not self._same(verified.get(name), value))
                        for name, value in expected.items()
                    )
                    or not isinstance(verified.get("verifier_authority"), str)
                    or not 1 <= len(str(verified["verifier_authority"])) <= 128
                    or not isinstance(verified.get("verification_sha256"), str)
                    or len(str(verified["verification_sha256"])) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in str(verified["verification_sha256"])
                    )
                ):
                    raise NativeConsentDenied("certified consent-string verification failed")
                standards_evidence = {
                    "verifier_authority": str(verified["verifier_authority"]),
                    "verification_sha256": str(verified["verification_sha256"]),
                }
            choices = [PreferenceChoice(purpose_id=str(item), action="deny") for item in signals["purposes"]]
            result = preferences.record_preferences(
                authority.tenant_id,
                profile.profile_id,
                authority.policy_id,
                authority.policy_version,
                self._context(authority, client),
                choices,
                expected_revision=int(payload["expected_revision"]),
                idempotency_key=self._idempotency(
                    "signals",
                    authority,
                    device,
                    profile,
                    str(payload["idempotency_key"]),
                ),
                actor_sha256=actor,
                signal="gpc" if signals["gpc"] is True else None,
            )
            return {
                **result,
                "signal_evidence": {
                    "gpc": signals["gpc"],
                    "do_not_sell_or_share": signals["do_not_sell_or_share"],
                    "tcf_string_sha256": signals.get("tcf_string_sha256"),
                    "gpp_string_sha256": signals.get("gpp_string_sha256"),
                    "standards_contract_sha256": signals["standards_contract_sha256"],
                    "wire_interpreted": False,
                    **standards_evidence,
                },
            }

        if operation == "revoke_profile":
            return self.public.credential_store.revoke_profile(
                authority.tenant_id,
                authority.property_id,
                profile.profile_id,
                actor_sha256=actor,
                evidence_sha256=str(payload["evidence_sha256"]),
            )

        if operation == "link_profile":
            if not callable(self.profile_linker):
                raise NativeConsentDenied("profile synchronization authority is unavailable")
            target = self.public.credential_store.resolve_profile_authority(
                str(payload["target_profile_credential_sha256"]),
                client,
            )
            target_context = resolve_consent_pairing_context(self.public, client, target)
            result = self.profile_linker(
                source=pairing_context,
                target=target_context,
                pairing_authorization_sha256=str(payload["pairing_authorization_sha256"]),
                scope=str(payload["scope"]),
                idempotency_key=self._idempotency(
                    "profile-link",
                    authority,
                    device,
                    profile,
                    str(payload["idempotency_key"]),
                ),
            )
            if not isinstance(result, Mapping):
                raise NativeConsentIntegrityError("profile synchronization returned invalid data")
            return dict(result)

        if operation == "rights_request":
            if not callable(self.rights_requester):
                raise NativeConsentDenied("consumer-rights handoff authority is unavailable")
            result = self.rights_requester(
                client=client,
                profile=profile,
                active_public_configuration=configuration,
                active_policy=policy,
                rights=tuple(payload["rights"]),
                expected_revision=0,
                idempotency_key=self._idempotency(
                    "rights",
                    authority,
                    device,
                    profile,
                    str(payload["idempotency_key"]),
                ),
                request_id=request_id,
            )
            if not isinstance(result, Mapping):
                raise NativeConsentIntegrityError("consumer-rights handoff returned invalid data")
            return dict(result)

        raise NativeConsentDenied("native operation is unavailable")


__all__ = ["LightworkNativeConsentBackend"]
