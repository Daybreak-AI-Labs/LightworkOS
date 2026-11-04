import CryptoKit
import Foundation

// Reference host adapter for iOS and tvOS. The application supplies Keychain/
// Secure Enclave custody, URLSession transport, durable outbox, and platform
// attestation. No tenant-wide bearer credential is accepted here.

public enum LightworkConsentError: Error {
    case authorityChanged
    case invalidContract
    case payloadTooLarge
    case signerUnavailable
    case transportRejected
}

public protocol LightworkDeviceSigner: Sendable {
    var publicKeyHex: String { get }
    func sign(_ canonicalBody: Data) throws -> Data
}

public protocol LightworkConsentTransport: Sendable {
    func post(path: String, body: Data) async throws -> Data
}

public protocol LightworkNativeAuthorityRefresher: Sendable {
    /// Obtains fresh platform attestation over the exact app/install/device key,
    /// uses a new nonce and expected device revision, sends no ambient credentials,
    /// and validates the closed nested authority/device response before flattening it.
    func refresh(
        path: String,
        currentAuthority: NativeConsentAuthority,
        expectedDevicePublicKeyHex: String,
        admittedSDKVersion: Int?,
        maximumRequestBytes: Int,
        maximumResponseBytes: Int
    ) async throws -> NativeConsentAuthority
}

public protocol LightworkConsentOutbox: Sendable {
    func append(_ message: QueuedConsentOperation) async throws
    func due(limit: Int) async throws -> [QueuedConsentOperation]
    func acknowledge(requestID: String, requestSHA256: String) async throws
    func retry(requestID: String, errorSHA256: String) async throws
    func removeAll(deviceID: String) async throws
    func reserveCounter(deviceID: String) async throws -> UInt64
    func replace(
        requestID: String,
        expectedRequestSHA256: String,
        replacement: QueuedConsentOperation
    ) async throws
}

public protocol LightworkReceiptVerifier: Sendable {
    /// Verifies signed_payload_b64url with a versioned Ed25519 trust root and all expected bindings.
    func verify(
        response: Data,
        request: QueuedConsentOperation,
        authority: NativeConsentAuthority,
        maximumResponseBytes: Int
    ) throws
}

public struct NativeConsentAuthority: Codable, Sendable, Equatable {
    public let applicationRef: String
    public let applicationAuthoritySHA256: String
    public let tenantID: String
    public let applicationID: String
    public let platform: String
    public let deviceID: String
    public let deviceRevision: Int
    public let keyRevision: Int
    public let sdkVersion: Int
    public let publicClientRevision: Int
    public let publicClientRecordSHA256: String
    public let publicationSHA256: String
    public let publicationBundleSHA256: String
    public let configurationSHA256: String
    public let policyID: String
    public let policyVersion: Int
    public let policySHA256: String
    public let standardsContractSHA256: String

    public func validate(expectedPlatform: String) throws {
        guard platform == expectedPlatform,
              ["ios", "tvos"].contains(platform),
              applicationID.range(of: "^[A-Za-z0-9][A-Za-z0-9_.:-]{2,254}\\z", options: .regularExpression) != nil,
              [applicationRef, tenantID, deviceID, policyID].allSatisfy({
                  $0.range(of: "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\\z", options: .regularExpression) != nil
              }),
              [deviceRevision, keyRevision, publicClientRevision, policyVersion].allSatisfy({
                  (1...2_147_483_647).contains($0)
              }),
              (1...1_000_000).contains(sdkVersion) else { throw LightworkConsentError.invalidContract }
        let digests = [
            applicationAuthoritySHA256, publicClientRecordSHA256,
            publicationSHA256, publicationBundleSHA256, configurationSHA256,
            policySHA256, standardsContractSHA256,
        ]
        guard digests.allSatisfy({ $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil })
        else { throw LightworkConsentError.invalidContract }
    }
}

public struct QueuedConsentOperation: Codable, Sendable {
    public let requestID: String
    public let operation: String
    public let normalizedPayload: Data
    public let downstreamIdempotencyKey: String?
    public let createdAt: TimeInterval
    public let deviceID: String
    public let deviceRevision: Int
    public let applicationAuthoritySHA256: String
    public let expiresAt: Int
    public let requestSHA256: String
    public let signedEnvelope: Data
}

public struct PreferenceChoice: Codable, Sendable {
    public let purposeID: String
    public let action: String
    public let channel: String
    public let vendorID: String
    public let expiresAt: Int?
}

public struct NativePrivacySignals: Codable, Sendable {
    public let gpc: Bool
    public let doNotSellOrShare: Bool
    public let tcfString: String?
    public let tcfStringSHA256: String?
    public let gppString: String?
    public let gppStringSHA256: String?
    public let standardsContractSHA256: String
    public let purposes: [String]
}

public actor LightworkConsentClient {
    public static let maxPayloadBytes = 128 * 1024
    public static let maxResponseBytes = 512 * 1024
    public static let envelopeTTL: TimeInterval = 120
    private static let canonicalJSONOptions: JSONSerialization.WritingOptions = [
        .sortedKeys, .withoutEscapingSlashes,
    ]

    private var authority: NativeConsentAuthority
    private var signer: LightworkDeviceSigner
    private let transport: LightworkConsentTransport
    private let outbox: LightworkConsentOutbox
    private let receiptVerifier: LightworkReceiptVerifier
    private let authorityRefresher: LightworkNativeAuthorityRefresher

    public init(
        authority: NativeConsentAuthority,
        signer: LightworkDeviceSigner,
        transport: LightworkConsentTransport,
        outbox: LightworkConsentOutbox,
        receiptVerifier: LightworkReceiptVerifier,
        authorityRefresher: LightworkNativeAuthorityRefresher
    ) throws {
        try authority.validate(expectedPlatform: authority.platform)
        guard signer.publicKeyHex.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
        else { throw LightworkConsentError.signerUnavailable }
        self.authority = authority
        self.signer = signer
        self.transport = transport
        self.outbox = outbox
        self.receiptVerifier = receiptVerifier
        self.authorityRefresher = authorityRefresher
    }

    public func replaceAuthority(
        _ next: NativeConsentAuthority,
        nextSigner: LightworkDeviceSigner? = nil
    ) throws {
        try next.validate(expectedPlatform: authority.platform)
        guard next.tenantID == authority.tenantID,
              next.applicationRef == authority.applicationRef,
              next.applicationID == authority.applicationID,
              next.deviceID == authority.deviceID,
              next.platform == authority.platform,
              next.deviceRevision >= authority.deviceRevision,
              next.keyRevision >= authority.keyRevision,
              next.deviceRevision != authority.deviceRevision || next == authority,
              next.keyRevision == authority.keyRevision || nextSigner != nil,
              next.keyRevision != authority.keyRevision || nextSigner == nil else {
            throw LightworkConsentError.authorityChanged
        }
        if let replacement = nextSigner {
            guard replacement.publicKeyHex.range(
                of: "^[0-9a-f]{64}$",
                options: .regularExpression
            ) != nil else { throw LightworkConsentError.signerUnavailable }
            signer = replacement
        }
        authority = next
    }

    public func refreshAuthority(admittedSDKVersion: Int? = nil) async throws
        -> NativeConsentAuthority {
        if let version = admittedSDKVersion {
            guard (1...1_000_000).contains(version) else {
                throw LightworkConsentError.invalidContract
            }
        }
        let current = authority
        let next = try await authorityRefresher.refresh(
            path: "/api/v1/public/consent/native/refresh",
            currentAuthority: current,
            expectedDevicePublicKeyHex: signer.publicKeyHex,
            admittedSDKVersion: admittedSDKVersion,
            maximumRequestBytes: Self.maxPayloadBytes,
            maximumResponseBytes: Self.maxResponseBytes
        )
        // Actor methods are re-entrant across await; fail if another authority
        // transition completed while attestation was in flight.
        guard authority == current,
              next.deviceRevision == current.deviceRevision + 1,
              next.keyRevision == current.keyRevision,
              next.sdkVersion == (admittedSDKVersion ?? current.sdkVersion) else {
            throw LightworkConsentError.authorityChanged
        }
        try replaceAuthority(next)
        return authority
    }

    public func queueConfiguration() async throws -> String {
        try await queue(operation: "configuration", payload: [:], idempotencyKey: nil)
    }

    public func queueBootstrapProfile(
        subjectSHA256: String,
        profileCredentialSHA256: String,
        idempotencyKey: String
    ) async throws -> String {
        try await queue(
            operation: "bootstrap_profile",
            payload: [
                "subject_sha256": subjectSHA256,
                "profile_credential_sha256": profileCredentialSHA256,
                "idempotency_key": idempotencyKey,
            ],
            idempotencyKey: idempotencyKey
        )
    }

    public func queueCurrentPreferences(profileCredentialSHA256: String) async throws -> String {
        try await queue(
            operation: "current_preferences",
            payload: ["profile_credential_sha256": profileCredentialSHA256],
            idempotencyKey: nil
        )
    }

    public func queuePreferences(
        profileCredentialSHA256: String,
        expectedRevision: Int,
        choices: [PreferenceChoice],
        idempotencyKey: String
    ) async throws -> String {
        guard !choices.isEmpty, choices.count <= 128 else {
            throw LightworkConsentError.invalidContract
        }
        let normalizedChoices = choices.sorted {
            ($0.purposeID, $0.channel, $0.vendorID) < ($1.purposeID, $1.channel, $1.vendorID)
        }
        let payload: [String: Any] = [
            "profile_credential_sha256": try digest(profileCredentialSHA256),
            "expected_revision": expectedRevision,
            "idempotency_key": try reference(idempotencyKey),
            "choices": try object(normalizedChoices),
        ]
        return try await queue(
            operation: "record_preferences",
            payload: payload,
            idempotencyKey: idempotencyKey
        )
    }

    public func queuePrivacySignals(
        profileCredentialSHA256: String,
        expectedRevision: Int,
        signals: NativePrivacySignals,
        idempotencyKey: String
    ) async throws -> String {
        guard signals.gpc || signals.doNotSellOrShare || signals.tcfString != nil || signals.gppString != nil
        else { throw LightworkConsentError.invalidContract }
        guard !signals.purposes.isEmpty,
              signals.purposes.count <= 128,
              Set(signals.purposes).count == signals.purposes.count,
              (signals.tcfString == nil) == (signals.tcfStringSHA256 == nil),
              (signals.gppString == nil) == (signals.gppStringSHA256 == nil) else {
            throw LightworkConsentError.invalidContract
        }
        if let value = signals.tcfString {
            guard SHA256.hash(data: Data(value.utf8)).hex == signals.tcfStringSHA256 else {
                throw LightworkConsentError.invalidContract
            }
        }
        if let value = signals.gppString {
            guard SHA256.hash(data: Data(value.utf8)).hex == signals.gppStringSHA256 else {
                throw LightworkConsentError.invalidContract
            }
        }
        var normalizedSignals: [String: Any] = [
            "gpc": signals.gpc,
            "do_not_sell_or_share": signals.doNotSellOrShare,
            "standards_contract_sha256": try digest(signals.standardsContractSHA256),
            "purposes": try signals.purposes.sorted().map(reference),
        ]
        if let value = signals.tcfString, let digest = signals.tcfStringSHA256 {
            normalizedSignals["tcf_string"] = value
            normalizedSignals["tcf_string_sha256"] = digest
        }
        if let value = signals.gppString, let digest = signals.gppStringSHA256 {
            normalizedSignals["gpp_string"] = value
            normalizedSignals["gpp_string_sha256"] = digest
        }
        let payload: [String: Any] = [
            "profile_credential_sha256": try digest(profileCredentialSHA256),
            "expected_revision": expectedRevision,
            "idempotency_key": try reference(idempotencyKey),
            "signals": normalizedSignals,
        ]
        return try await queue(operation: "privacy_signals", payload: payload, idempotencyKey: idempotencyKey)
    }

    public func queueProfileLink(
        profileCredentialSHA256: String,
        targetProfileCredentialSHA256: String,
        pairingAuthorizationSHA256: String,
        scope: String,
        idempotencyKey: String
    ) async throws -> String {
        guard profileCredentialSHA256 != targetProfileCredentialSHA256,
              ["device", "household"].contains(scope) else {
            throw LightworkConsentError.invalidContract
        }
        return try await queue(
            operation: "link_profile",
            payload: [
                "profile_credential_sha256": try digest(profileCredentialSHA256),
                "target_profile_credential_sha256": try digest(targetProfileCredentialSHA256),
                "pairing_authorization_sha256": try digest(pairingAuthorizationSHA256),
                "scope": scope,
                "idempotency_key": try reference(idempotencyKey),
            ],
            idempotencyKey: idempotencyKey
        )
    }

    public func queueRightsRequest(
        profileCredentialSHA256: String,
        rights: [String],
        idempotencyKey: String
    ) async throws -> String {
        let allowed = Set(["access", "portability", "erasure", "rectification", "restriction", "objection", "opt_out"])
        guard !rights.isEmpty, Set(rights).count == rights.count, Set(rights).isSubset(of: allowed)
        else { throw LightworkConsentError.invalidContract }
        return try await queue(
            operation: "rights_request",
            payload: [
                "profile_credential_sha256": profileCredentialSHA256,
                "rights": rights.sorted(),
                "expected_revision": 0,
                "idempotency_key": idempotencyKey,
            ],
            idempotencyKey: idempotencyKey
        )
    }

    public func queueRevokeProfile(
        profileCredentialSHA256: String,
        evidenceSHA256: String,
        idempotencyKey: String
    ) async throws -> String {
        try await queue(
            operation: "revoke_profile",
            payload: [
                "profile_credential_sha256": profileCredentialSHA256,
                "evidence_sha256": evidenceSHA256,
                "idempotency_key": idempotencyKey,
            ],
            idempotencyKey: idempotencyKey
        )
    }

    public func drain(limit: Int = 32) async throws {
        for original in try await outbox.due(limit: min(max(limit, 1), 128)) {
            var message = original
            do {
                let now = Int(Date().timeIntervalSince1970.rounded(.down))
                if message.expiresAt < now ||
                    message.deviceRevision != authority.deviceRevision ||
                    message.applicationAuthoritySHA256 != authority.applicationAuthoritySHA256 {
                    let replacement = try await materialize(
                        requestID: "native-" + UUID().uuidString.lowercased(),
                        operation: message.operation,
                        normalizedPayload: message.normalizedPayload,
                        idempotencyKey: message.downstreamIdempotencyKey,
                        createdAt: message.createdAt
                    )
                    try await outbox.replace(
                        requestID: message.requestID,
                        expectedRequestSHA256: message.requestSHA256,
                        replacement: replacement
                    )
                    message = replacement
                }
                let response = try await transport.post(
                    path: "/api/v1/public/consent/native/dispatch",
                    body: message.signedEnvelope
                )
                try receiptVerifier.verify(
                    response: response,
                    request: message,
                    authority: authority,
                    maximumResponseBytes: Self.maxResponseBytes
                )
                try await outbox.acknowledge(
                    requestID: message.requestID,
                    requestSHA256: message.requestSHA256
                )
            } catch {
                let evidence = SHA256.hash(data: Data(String(describing: type(of: error)).utf8))
                try await outbox.retry(requestID: message.requestID, errorSHA256: evidence.hex)
            }
        }
    }

    public func revokeLocalDevice() async throws {
        try await outbox.removeAll(deviceID: authority.deviceID)
    }

    private func queue(
        operation: String,
        payload: [String: Any],
        idempotencyKey: String?
    ) async throws -> String {
        let encoded = try JSONSerialization.data(
            withJSONObject: payload,
            options: Self.canonicalJSONOptions
        )
        guard encoded.count <= Self.maxPayloadBytes else { throw LightworkConsentError.payloadTooLarge }
        let message = try await materialize(
            requestID: "native-" + UUID().uuidString.lowercased(),
            operation: operation,
            normalizedPayload: encoded,
            idempotencyKey: idempotencyKey,
            createdAt: Date().timeIntervalSince1970
        )
        try await outbox.append(message)
        return message.requestID
    }

    private func materialize(
        requestID: String,
        operation: String,
        normalizedPayload: Data,
        idempotencyKey: String?,
        createdAt: TimeInterval
    ) async throws -> QueuedConsentOperation {
        let counter = try await outbox.reserveCounter(deviceID: authority.deviceID)
        guard counter > 0 else { throw LightworkConsentError.invalidContract }
        let now = Int(Date().timeIntervalSince1970.rounded(.down))
        guard let payload = try JSONSerialization.jsonObject(with: normalizedPayload) as? [String: Any]
        else { throw LightworkConsentError.invalidContract }
        var body: [String: Any] = [
            "schema": "lightwork.native-consent-envelope.v1",
            "application_ref": authority.applicationRef,
            "application_authority_sha256": authority.applicationAuthoritySHA256,
            "tenant_id": authority.tenantID,
            "application_id": authority.applicationID,
            "platform": authority.platform,
            "device_id": authority.deviceID,
            "device_revision": authority.deviceRevision,
            "key_revision": authority.keyRevision,
            "sdk_version": authority.sdkVersion,
            "public_client_revision": authority.publicClientRevision,
            "public_client_record_sha256": authority.publicClientRecordSHA256,
            "publication_sha256": authority.publicationSHA256,
            "publication_bundle_sha256": authority.publicationBundleSHA256,
            "configuration_sha256": authority.configurationSHA256,
            "policy_id": authority.policyID,
            "policy_version": authority.policyVersion,
            "policy_sha256": authority.policySHA256,
            "standards_contract_sha256": authority.standardsContractSHA256,
            "request_id": requestID,
            "counter": counter,
            "issued_at": now,
            "expires_at": now + Int(Self.envelopeTTL),
            "operation": operation,
            "payload": payload,
        ]
        let canonical = try JSONSerialization.data(
            withJSONObject: body,
            options: Self.canonicalJSONOptions
        )
        let signature = try signer.sign(canonical)
        guard signature.count == 64 else { throw LightworkConsentError.signerUnavailable }
        body["signature_hex"] = signature.map { String(format: "%02x", $0) }.joined()
        let encoded = try JSONSerialization.data(
            withJSONObject: body,
            options: Self.canonicalJSONOptions
        )
        guard encoded.count <= Self.maxPayloadBytes else { throw LightworkConsentError.payloadTooLarge }
        return QueuedConsentOperation(
            requestID: requestID,
            operation: operation,
            normalizedPayload: normalizedPayload,
            downstreamIdempotencyKey: idempotencyKey,
            createdAt: createdAt,
            deviceID: authority.deviceID,
            deviceRevision: authority.deviceRevision,
            applicationAuthoritySHA256: authority.applicationAuthoritySHA256,
            expiresAt: now + Int(Self.envelopeTTL),
            requestSHA256: SHA256.hash(data: canonical).hex,
            signedEnvelope: encoded
        )
    }

    private func object<T: Encodable>(_ value: T) throws -> Any {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.keyEncodingStrategy = .convertToSnakeCase
        let data = try jsonEncoder.encode(value)
        return try JSONSerialization.jsonObject(with: data)
    }

    private func digest(_ value: String) throws -> String {
        guard value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw LightworkConsentError.invalidContract
        }
        return value
    }

    private func reference(_ value: String) throws -> String {
        guard value.range(
            of: "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
            options: .regularExpression
        ) != nil else { throw LightworkConsentError.invalidContract }
        return value
    }
}

private extension Digest {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
