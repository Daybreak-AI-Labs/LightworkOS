' Reference Roku adapter. The channel must inject a device/OEM attestation
' enrollment, a canonical-JSON Ed25519 signer, exact-origin HTTPS transport,
' and a bounded encrypted outbox. Roku devices without an accepted signing
' authority are deliberately unsupported; the adapter does not fall back to
' an embedded tenant-wide secret.

function LightworkConsentClient(authority as Object, signer as Object, transport as Object, outbox as Object, receiptVerifier as Object, authorityRefresher as Object) as Object
    if not LightworkConsentValidateAuthority(authority) then
        throw "invalid Lightwork native consent authority"
    end if
    if signer = invalid or signer.signCanonicalEd25519 = invalid or signer.normalizeOperationPayload = invalid or not LightworkConsentDigest(signer.publicKeyHex) then
        throw "closed canonical Ed25519 signing authority is unavailable"
    end if
    if transport = invalid or transport.postBounded = invalid then
        throw "bounded consent transport is unavailable"
    end if
    if outbox = invalid or outbox.append = invalid or outbox.due = invalid or outbox.acknowledge = invalid or outbox.retry = invalid or outbox.removeAll = invalid or outbox.reserveCounter = invalid or outbox.replace = invalid then
        throw "bounded durable consent outbox is unavailable"
    end if
    if receiptVerifier = invalid or receiptVerifier.verifySignedReceipt = invalid then throw "receipt verification authority is unavailable"
    if authorityRefresher = invalid or authorityRefresher.refreshAuthority = invalid then throw "attested authority refresh is unavailable"

    client = {
        authority: authority
        signer: signer
        transport: transport
        outbox: outbox
        receiptVerifier: receiptVerifier
        authorityRefresher: authorityRefresher
        queueConfiguration: LightworkConsentQueueConfiguration
        queueBootstrapProfile: LightworkConsentQueueBootstrapProfile
        queueCurrentPreferences: LightworkConsentQueueCurrentPreferences
        queuePreferences: LightworkConsentQueuePreferences
        queuePrivacySignals: LightworkConsentQueuePrivacySignals
        queueRightsRequest: LightworkConsentQueueRightsRequest
        queueProfileLink: LightworkConsentQueueProfileLink
        queueRevokeProfile: LightworkConsentQueueRevokeProfile
        drain: LightworkConsentDrain
        revokeLocalDevice: LightworkConsentRevokeLocalDevice
        replaceAuthority: LightworkConsentReplaceAuthority
        refreshAuthority: LightworkConsentRefreshAuthority
    }
    return client
end function

function LightworkConsentValidateAuthority(authority as Dynamic) as Boolean
    if type(authority) <> "roAssociativeArray" then return false
    if authority.platform <> "roku" then return false
    if not LightworkConsentReference(authority.application_ref) then return false
    if not LightworkConsentReference(authority.tenant_id) then return false
    if not LightworkConsentReference(authority.device_id) then return false
    if not LightworkConsentReference(authority.policy_id) then return false
    if not LightworkConsentIdentifier(authority.application_id, 3, 255) then return false
    for each name in ["device_revision", "key_revision", "sdk_version", "public_client_revision", "policy_version"]
        value = authority[name]
        if type(value) <> "Integer" and type(value) <> "roInt" and type(value) <> "LongInteger" and type(value) <> "roLongInteger" then return false
        if value < 1 or value > 2147483647 then return false
    end for
    if authority.sdk_version > 1000000 then return false
    for each name in ["application_authority_sha256", "public_client_record_sha256", "publication_sha256", "publication_bundle_sha256", "configuration_sha256", "policy_sha256", "standards_contract_sha256"]
        if not LightworkConsentDigest(authority[name]) then return false
    end for
    return true
end function

function LightworkConsentQueueConfiguration() as String
    return LightworkConsentQueue(m, "configuration", {}, invalid)
end function

function LightworkConsentQueueBootstrapProfile(subjectDigest as String, profileDigest as String, idempotencyKey as String) as String
    if not LightworkConsentDigest(subjectDigest) or not LightworkConsentDigest(profileDigest) then throw "profile bootstrap digests are invalid"
    payload = {
        subject_sha256: subjectDigest
        profile_credential_sha256: profileDigest
        idempotency_key: idempotencyKey
    }
    return LightworkConsentQueue(m, "bootstrap_profile", payload, idempotencyKey)
end function

function LightworkConsentQueueCurrentPreferences(profileDigest as String) as String
    if not LightworkConsentDigest(profileDigest) then throw "profile capability digest is invalid"
    return LightworkConsentQueue(m, "current_preferences", { profile_credential_sha256: profileDigest }, invalid)
end function

function LightworkConsentQueuePreferences(profileDigest as String, expectedRevision as Integer, choices as Object, idempotencyKey as String) as String
    if not LightworkConsentDigest(profileDigest) then throw "profile capability digest is invalid"
    if expectedRevision < 0 then throw "profile revision is invalid"
    if type(choices) <> "roArray" or choices.Count() < 1 or choices.Count() > 128 then throw "preference choices are invalid"
    payload = {
        profile_credential_sha256: profileDigest
        expected_revision: expectedRevision
        idempotency_key: idempotencyKey
        choices: choices
    }
    return LightworkConsentQueue(m, "record_preferences", payload, idempotencyKey)
end function

function LightworkConsentQueuePrivacySignals(profileDigest as String, expectedRevision as Integer, signals as Object, idempotencyKey as String) as String
    if not LightworkConsentDigest(profileDigest) then throw "profile capability digest is invalid"
    if expectedRevision < 0 then throw "profile revision is invalid"
    if type(signals) <> "roAssociativeArray" then throw "privacy signals are invalid"
    if signals.gpc <> true and signals.do_not_sell_or_share <> true and signals.tcf_string = invalid and signals.gpp_string = invalid then
        throw "at least one privacy signal is required"
    end if
    if not LightworkConsentDigest(signals.standards_contract_sha256) then throw "standards contract is invalid"
    payload = {
        profile_credential_sha256: profileDigest
        expected_revision: expectedRevision
        idempotency_key: idempotencyKey
        signals: signals
    }
    return LightworkConsentQueue(m, "privacy_signals", payload, idempotencyKey)
end function

function LightworkConsentQueueRightsRequest(profileDigest as String, rights as Object, idempotencyKey as String) as String
    if not LightworkConsentDigest(profileDigest) then throw "profile capability digest is invalid"
    if type(rights) <> "roArray" or rights.Count() < 1 or rights.Count() > 7 then throw "rights are invalid"
    payload = {
        profile_credential_sha256: profileDigest
        rights: rights
        expected_revision: 0
        idempotency_key: idempotencyKey
    }
    return LightworkConsentQueue(m, "rights_request", payload, idempotencyKey)
end function

function LightworkConsentQueueProfileLink(profileDigest as String, targetDigest as String, pairingDigest as String, scope as String, idempotencyKey as String) as String
    if not LightworkConsentDigest(profileDigest) or not LightworkConsentDigest(targetDigest) or not LightworkConsentDigest(pairingDigest) then throw "profile pairing digests are invalid"
    if profileDigest = targetDigest then throw "profile link target must be distinct"
    if scope <> "device" and scope <> "household" then throw "profile link scope is invalid"
    payload = {
        profile_credential_sha256: profileDigest
        target_profile_credential_sha256: targetDigest
        pairing_authorization_sha256: pairingDigest
        scope: scope
        idempotency_key: idempotencyKey
    }
    return LightworkConsentQueue(m, "link_profile", payload, idempotencyKey)
end function

function LightworkConsentQueueRevokeProfile(profileDigest as String, evidenceDigest as String, idempotencyKey as String) as String
    if not LightworkConsentDigest(profileDigest) or not LightworkConsentDigest(evidenceDigest) then throw "profile revocation digests are invalid"
    payload = {
        profile_credential_sha256: profileDigest
        evidence_sha256: evidenceDigest
        idempotency_key: idempotencyKey
    }
    return LightworkConsentQueue(m, "revoke_profile", payload, idempotencyKey)
end function

function LightworkConsentQueue(client as Object, operation as String, payload as Object, idempotencyKey as Dynamic) as String
    if not LightworkConsentReference(idempotencyKey) and idempotencyKey <> invalid then throw "idempotency key is invalid"
    requestId = "native-" + LCase(CreateObject("roDeviceInfo").GetRandomUUID())
    message = LightworkConsentMaterialize(client, requestId, operation, payload, idempotencyKey, CreateObject("roDateTime").AsSeconds())
    if not client.outbox.append(message, 524288) then throw "consent outbox rejected the message"
    return requestId
end function

sub LightworkConsentDrain(limit = 32 as Integer)
    if limit < 1 then limit = 1
    if limit > 128 then limit = 128
    messages = m.outbox.due(limit)
    for each original in messages
        message = original
        try
            now = CreateObject("roDateTime").AsSeconds()
            if message.expiresAt < now or message.deviceRevision <> m.authority.device_revision or message.applicationAuthoritySha256 <> m.authority.application_authority_sha256 then
                replacementId = "native-" + LCase(CreateObject("roDeviceInfo").GetRandomUUID())
                replacement = LightworkConsentMaterialize(m, replacementId, message.operation, message.payload, message.downstreamIdempotencyKey, message.createdAt)
                if not m.outbox.replace(message.requestId, message.requestSha256, replacement) then throw "consent renewal raced"
                message = replacement
            end if
            receipt = m.transport.postBounded("/api/v1/public/consent/native/dispatch", message.signedEnvelope, 524288, false)
            if not m.receiptVerifier.verifySignedReceipt(receipt, message, m.authority, 524288) then throw "consent receipt did not verify"
            m.outbox.acknowledge(message.requestId, message.requestSha256)
        catch error
            ' Error bodies may contain sensitive upstream data. Persist only a
            ' platform-generated digest of the failure class/code.
            m.outbox.retry(message.requestId, m.signer.sha256("transport-error"))
        end try
    end for
end sub

function LightworkConsentMaterialize(client as Object, requestId as String, operation as String, payload as Object, idempotencyKey as Dynamic, createdAt as Integer) as Object
    normalized = client.signer.normalizeOperationPayload(operation, payload, 131072)
    if normalized = invalid then throw "consent payload is outside the closed protocol"
    counter = client.outbox.reserveCounter(client.authority.device_id)
    if counter = invalid or counter < 1 then throw "durable consent counter is unavailable"
    now = CreateObject("roDateTime").AsSeconds()
    body = client.authority.Clone()
    body.schema = "lightwork.native-consent-envelope.v1"
    body.request_id = requestId
    body.counter = counter
    body.issued_at = now
    body.expires_at = now + 120
    body.operation = operation
    body.payload = normalized
    signed = client.signer.signCanonicalEd25519(body, 131072)
    if signed = invalid or signed.signature_hex = invalid or Len(signed.signature_hex) <> 128 or not LightworkConsentDigest(signed.request_sha256) then throw "consent signing failed"
    envelope = body.Clone()
    envelope.signature_hex = signed.signature_hex
    return {
        requestId: requestId
        operation: operation
        payload: normalized
        downstreamIdempotencyKey: idempotencyKey
        createdAt: createdAt
        deviceId: client.authority.device_id
        deviceRevision: client.authority.device_revision
        applicationAuthoritySha256: client.authority.application_authority_sha256
        expiresAt: now + 120
        requestSha256: signed.request_sha256
        signedEnvelope: envelope
    }
end function

sub LightworkConsentRevokeLocalDevice()
    m.outbox.removeAll(m.authority.device_id)
end sub

function LightworkConsentReplaceAuthority(nextAuthority as Object, nextSigner = invalid as Dynamic) as Boolean
    if not LightworkConsentValidateAuthority(nextAuthority) then return false
    for each name in ["tenant_id", "application_ref", "application_id", "device_id", "platform"]
        if nextAuthority[name] <> m.authority[name] then return false
    end for
    if nextAuthority.device_revision < m.authority.device_revision or nextAuthority.key_revision < m.authority.key_revision then return false
    if nextAuthority.device_revision = m.authority.device_revision then
        for each name in ["application_ref", "application_authority_sha256", "tenant_id", "application_id", "platform", "device_id", "device_revision", "key_revision", "sdk_version", "public_client_revision", "public_client_record_sha256", "publication_sha256", "publication_bundle_sha256", "configuration_sha256", "policy_id", "policy_version", "policy_sha256", "standards_contract_sha256"]
            if nextAuthority[name] <> m.authority[name] then return false
        end for
    end if
    if nextAuthority.key_revision <> m.authority.key_revision and nextSigner = invalid then return false
    if nextAuthority.key_revision = m.authority.key_revision and nextSigner <> invalid then return false
    if nextSigner <> invalid then
        if nextSigner.signCanonicalEd25519 = invalid or nextSigner.normalizeOperationPayload = invalid or not LightworkConsentDigest(nextSigner.publicKeyHex) then return false
        m.signer = nextSigner
    end if
    m.authority = nextAuthority
    return true
end function

function LightworkConsentRefreshAuthority(admittedSdkVersion = invalid as Dynamic) as Object
    if admittedSdkVersion <> invalid then
        if admittedSdkVersion < 1 or admittedSdkVersion > 1000000 then throw "admitted SDK version is invalid"
    end if
    current = m.authority
    ' The host refresher obtains a fresh OEM/device attestation over the exact
    ' app/install/public key, uses a new nonce and expected revision, posts
    ' without ambient credentials, and validates the nested response schema.
    nextAuthority = m.authorityRefresher.refreshAuthority(
        "/api/v1/public/consent/native/refresh",
        current,
        m.signer.publicKeyHex,
        admittedSdkVersion,
        131072,
        524288,
        false
    )
    if not LightworkConsentValidateAuthority(nextAuthority) then throw "authority refresh response is invalid"
    if m.authority.device_revision <> current.device_revision or m.authority.application_authority_sha256 <> current.application_authority_sha256 then throw "authority refresh raced"
    if nextAuthority.device_revision <> current.device_revision + 1 or nextAuthority.key_revision <> current.key_revision then throw "authority refresh revision is invalid"
    expectedSdkVersion = current.sdk_version
    if admittedSdkVersion <> invalid then expectedSdkVersion = admittedSdkVersion
    if nextAuthority.sdk_version <> expectedSdkVersion then throw "authority refresh SDK binding is invalid"
    if not LightworkConsentReplaceAuthority(nextAuthority) then throw "authority refresh response changed identity"
    return m.authority
end function

function LightworkConsentDigest(value as Dynamic) as Boolean
    if type(value) <> "roString" and type(value) <> "String" then return false
    if Len(value) <> 64 then return false
    for index = 1 to 64
        character = Mid(value, index, 1)
        if Instr(1, "0123456789abcdef", character) = 0 then return false
    end for
    return true
end function

function LightworkConsentReference(value as Dynamic) as Boolean
    return LightworkConsentIdentifier(value, 1, 128)
end function

function LightworkConsentIdentifier(value as Dynamic, minimum as Integer, maximum as Integer) as Boolean
    if type(value) <> "roString" and type(value) <> "String" then return false
    if Len(value) < minimum or Len(value) > maximum then return false
    if Instr(1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", Left(value, 1)) = 0 then return false
    for index = 2 to Len(value)
        if Instr(1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-", Mid(value, index, 1)) = 0 then return false
    end for
    return true
end function
