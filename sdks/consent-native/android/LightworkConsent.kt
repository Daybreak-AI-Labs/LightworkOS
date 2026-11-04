package ai.lightwork.consent

import java.security.MessageDigest
import java.time.Clock
import java.util.UUID
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Reference host adapter for Android and Fire TV.
 *
 * The host supplies Android-Keystore signing, Play Integrity verification
 * enrollment, canonical JSON, bounded HTTPS transport, and a Room/SQLCipher
 * outbox. No tenant-wide bearer credential is accepted by this boundary.
 */
class LightworkConsentClient(
    @Volatile private var authority: NativeConsentAuthority,
    private var signer: DeviceSigner,
    private val canonicalJson: CanonicalJson,
    private val transport: ConsentTransport,
    private val outbox: ConsentOutbox,
    private val receiptVerifier: ReceiptVerifier,
    private val authorityRefresher: NativeAuthorityRefresher,
    private val clock: Clock = Clock.systemUTC(),
) {
    private val authorityTransition = Mutex()

    companion object {
        const val MAX_PAYLOAD_BYTES = 128 * 1024
        const val MAX_RESPONSE_BYTES = 512 * 1024
        const val ENVELOPE_TTL_SECONDS = 120L
        val SUPPORTED_PLATFORMS = setOf("android", "fireos")
        val OPERATIONS = setOf(
            "bootstrap_profile", "configuration", "current_preferences",
            "link_profile", "privacy_signals", "record_preferences",
            "revoke_profile", "rights_request",
        )
    }

    init {
        authority.validate()
        require(signer.publicKeyHex.matches(Regex("^[0-9a-f]{64}$")))
    }

    suspend fun replaceAuthority(next: NativeConsentAuthority, nextSigner: DeviceSigner? = null) =
        authorityTransition.withLock {
            replaceAuthorityLocked(next, nextSigner)
        }

    private fun replaceAuthorityLocked(
        next: NativeConsentAuthority,
        nextSigner: DeviceSigner? = null,
    ) {
        next.validate()
        check(next.tenantId == authority.tenantId)
        check(next.applicationRef == authority.applicationRef)
        check(next.applicationId == authority.applicationId)
        check(next.deviceId == authority.deviceId)
        check(next.platform == authority.platform)
        check(next.deviceRevision >= authority.deviceRevision)
        check(next.keyRevision >= authority.keyRevision)
        if (next.deviceRevision == authority.deviceRevision) check(next == authority)
        if (next.keyRevision != authority.keyRevision) check(nextSigner != null)
        if (next.keyRevision == authority.keyRevision) check(nextSigner == null)
        if (nextSigner != null) {
            require(nextSigner.publicKeyHex.matches(Regex("^[0-9a-f]{64}$")))
            signer = nextSigner
        }
        authority = next
    }

    suspend fun refreshAuthority(admittedSdkVersion: Int? = null): NativeConsentAuthority =
        authorityTransition.withLock {
            admittedSdkVersion?.let { require(it in 1..1_000_000) }
            val current = authority
            val next = authorityRefresher.refresh(
                path = "/api/v1/public/consent/native/refresh",
                currentAuthority = current,
                expectedDevicePublicKeyHex = signer.publicKeyHex,
                admittedSdkVersion = admittedSdkVersion,
                maximumRequestBytes = MAX_PAYLOAD_BYTES,
                maximumResponseBytes = MAX_RESPONSE_BYTES,
            )
            check(authority == current)
            next.validate()
            check(next.deviceRevision == current.deviceRevision + 1)
            check(next.keyRevision == current.keyRevision)
            check(next.sdkVersion == (admittedSdkVersion ?: current.sdkVersion))
            replaceAuthorityLocked(next)
            authority
        }

    suspend fun queueConfiguration(): String = queue("configuration", emptyMap(), null)

    suspend fun queueBootstrapProfile(
        subjectSha256: String,
        profileCredentialSha256: String,
        idempotencyKey: String,
    ): String = queue(
        "bootstrap_profile",
        mapOf(
            "subject_sha256" to digest(subjectSha256),
            "profile_credential_sha256" to digest(profileCredentialSha256),
            "idempotency_key" to reference(idempotencyKey),
        ),
        idempotencyKey,
    )

    suspend fun queueCurrentPreferences(profileCredentialSha256: String): String = queue(
        "current_preferences",
        mapOf("profile_credential_sha256" to digest(profileCredentialSha256)),
        null,
    )

    suspend fun queuePreferences(
        profileCredentialSha256: String,
        expectedRevision: Int,
        choices: List<PreferenceChoice>,
        idempotencyKey: String,
    ): String {
        require(choices.isNotEmpty() && choices.size <= 128)
        return queue(
            "record_preferences",
            mapOf(
                "profile_credential_sha256" to digest(profileCredentialSha256),
                "expected_revision" to expectedRevision,
                "idempotency_key" to reference(idempotencyKey),
                "choices" to choices.map { it.normalized() }.sortedWith(
                    compareBy<Map<String, Any?>>(
                        { it["purpose_id"] as String },
                        { it["channel"] as String },
                        { it["vendor_id"] as String },
                    ),
                ),
            ),
            idempotencyKey,
        )
    }

    suspend fun queuePrivacySignals(
        profileCredentialSha256: String,
        expectedRevision: Int,
        signals: NativePrivacySignals,
        idempotencyKey: String,
    ): String = queue(
        "privacy_signals",
        mapOf(
            "profile_credential_sha256" to digest(profileCredentialSha256),
            "expected_revision" to expectedRevision,
            "idempotency_key" to reference(idempotencyKey),
            "signals" to signals.normalized(),
        ),
        idempotencyKey,
    )

    suspend fun queueProfileLink(
        profileCredentialSha256: String,
        targetProfileCredentialSha256: String,
        pairingAuthorizationSha256: String,
        scope: String,
        idempotencyKey: String,
    ): String {
        require(scope == "device" || scope == "household")
        require(profileCredentialSha256 != targetProfileCredentialSha256)
        return queue(
            "link_profile",
            mapOf(
                "profile_credential_sha256" to digest(profileCredentialSha256),
                "target_profile_credential_sha256" to digest(targetProfileCredentialSha256),
                "pairing_authorization_sha256" to digest(pairingAuthorizationSha256),
                "scope" to scope,
                "idempotency_key" to reference(idempotencyKey),
            ),
            idempotencyKey,
        )
    }

    suspend fun queueRightsRequest(
        profileCredentialSha256: String,
        rights: Set<String>,
        idempotencyKey: String,
    ): String {
        val allowed = setOf(
            "access", "portability", "erasure", "rectification",
            "restriction", "objection", "opt_out",
        )
        require(rights.isNotEmpty() && allowed.containsAll(rights))
        return queue(
            "rights_request",
            mapOf(
                "profile_credential_sha256" to digest(profileCredentialSha256),
                "rights" to rights.sorted(),
                "expected_revision" to 0,
                "idempotency_key" to reference(idempotencyKey),
            ),
            idempotencyKey,
        )
    }

    suspend fun queueRevokeProfile(
        profileCredentialSha256: String,
        evidenceSha256: String,
        idempotencyKey: String,
    ): String = queue(
        "revoke_profile",
        mapOf(
            "profile_credential_sha256" to digest(profileCredentialSha256),
            "evidence_sha256" to digest(evidenceSha256),
            "idempotency_key" to reference(idempotencyKey),
        ),
        idempotencyKey,
    )

    /** WorkManager may invoke this. The outbox owns leases and backoff. */
    suspend fun drain(limit: Int = 32) {
        outbox.due(limit.coerceIn(1, 128)).forEach { message ->
            var current = message
            try {
                if (
                    current.expiresAt < clock.instant().epochSecond ||
                    current.deviceRevision != authority.deviceRevision ||
                    current.applicationAuthoritySha256 != authority.applicationAuthoritySha256
                ) {
                    val replacement = materialize(
                        "native-${UUID.randomUUID().toString().lowercase()}",
                        current.operation,
                        current.normalizedPayload,
                        current.downstreamIdempotencyKey,
                        current.createdAt,
                    )
                    outbox.replace(current.requestId, current.requestSha256, replacement)
                    current = replacement
                }
                val response = transport.post(
                    "/api/v1/public/consent/native/dispatch",
                    current.signedEnvelope,
                    MAX_RESPONSE_BYTES,
                )
                receiptVerifier.verify(response, current, authority, MAX_RESPONSE_BYTES)
                outbox.acknowledge(current.requestId, current.requestSha256)
            } catch (error: Exception) {
                // Persist only an error-class digest, never a response body or credential.
                val evidence = sha256(error.javaClass.name.toByteArray())
                outbox.retry(current.requestId, evidence)
            }
        }
    }

    suspend fun revokeLocalDevice() = outbox.removeAll(authority.deviceId)

    private suspend fun queue(
        operation: String,
        payload: Map<String, Any?>,
        downstreamIdempotencyKey: String?,
    ): String {
        require(operation in OPERATIONS)
        val normalized = canonicalJson.encode(payload)
        require(normalized.size in 1..MAX_PAYLOAD_BYTES)
        val createdAt = clock.instant().epochSecond
        val message = materialize(
            "native-${UUID.randomUUID().toString().lowercase()}",
            operation,
            normalized,
            downstreamIdempotencyKey,
            createdAt,
        )
        outbox.append(message)
        return message.requestId
    }

    private suspend fun materialize(
        requestId: String,
        operation: String,
        normalizedPayload: ByteArray,
        downstreamIdempotencyKey: String?,
        createdAt: Long,
    ): QueuedConsentOperation {
        val counter = outbox.reserveCounter(authority.deviceId)
        require(counter > 0)
        val now = clock.instant().epochSecond
        return authorityTransition.withLock {
            val currentAuthority = authority
            val currentSigner = signer
            val body = currentAuthority.envelopeFields() + mapOf(
                "schema" to "lightwork.native-consent-envelope.v1",
                "request_id" to reference(requestId),
                "counter" to counter,
                "issued_at" to now,
                "expires_at" to now + ENVELOPE_TTL_SECONDS,
                "operation" to operation,
                "payload" to canonicalJson.decodeObject(normalizedPayload),
            )
            val canonical = canonicalJson.encode(body)
            require(canonical.size in 1..MAX_PAYLOAD_BYTES)
            val signature = currentSigner.sign(canonical)
            check(signature.size == 64)
            val signedEnvelope = canonicalJson.encode(
                body + ("signature_hex" to signature.toHex())
            )
            require(signedEnvelope.size in 1..MAX_PAYLOAD_BYTES)
            QueuedConsentOperation(
                requestId,
                operation,
                normalizedPayload,
                downstreamIdempotencyKey,
                createdAt,
                currentAuthority.deviceId,
                currentAuthority.deviceRevision,
                currentAuthority.applicationAuthoritySha256,
                now + ENVELOPE_TTL_SECONDS,
                sha256(canonical),
                signedEnvelope,
            )
        }
    }

    private fun reference(value: Any?): String =
        requireNotNull(value as? String).also {
            require(it.matches(Regex("^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")))
        }

    private fun digest(value: Any?): String =
        requireNotNull(value as? String).also { require(it.matches(Regex("^[0-9a-f]{64}$"))) }
}

data class NativeConsentAuthority(
    val applicationRef: String,
    val applicationAuthoritySha256: String,
    val tenantId: String,
    val applicationId: String,
    val platform: String,
    val deviceId: String,
    val deviceRevision: Int,
    val keyRevision: Int,
    val sdkVersion: Int,
    val publicClientRevision: Int,
    val publicClientRecordSha256: String,
    val publicationSha256: String,
    val publicationBundleSha256: String,
    val configurationSha256: String,
    val policyId: String,
    val policyVersion: Int,
    val policySha256: String,
    val standardsContractSha256: String,
) {
    fun validate() {
        require(platform in LightworkConsentClient.SUPPORTED_PLATFORMS)
        require(applicationId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_.:-]{2,254}")))
        require(listOf(applicationRef, tenantId, deviceId, policyId).all {
            it.matches(Regex("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"))
        })
        require(listOf(deviceRevision, keyRevision, publicClientRevision, policyVersion).all { it > 0 })
        require(sdkVersion in 1..1_000_000)
        listOf(
            applicationAuthoritySha256, publicClientRecordSha256, publicationSha256,
            publicationBundleSha256, configurationSha256, policySha256,
            standardsContractSha256,
        ).forEach { require(it.matches(Regex("^[0-9a-f]{64}$"))) }
    }

    fun envelopeFields(): Map<String, Any> = mapOf(
        "application_ref" to applicationRef,
        "application_authority_sha256" to applicationAuthoritySha256,
        "tenant_id" to tenantId,
        "application_id" to applicationId,
        "platform" to platform,
        "device_id" to deviceId,
        "device_revision" to deviceRevision,
        "key_revision" to keyRevision,
        "sdk_version" to sdkVersion,
        "public_client_revision" to publicClientRevision,
        "public_client_record_sha256" to publicClientRecordSha256,
        "publication_sha256" to publicationSha256,
        "publication_bundle_sha256" to publicationBundleSha256,
        "configuration_sha256" to configurationSha256,
        "policy_id" to policyId,
        "policy_version" to policyVersion,
        "policy_sha256" to policySha256,
        "standards_contract_sha256" to standardsContractSha256,
    )
}

data class PreferenceChoice(
    val purposeId: String,
    val action: String,
    val channel: String = "all",
    val vendorId: String = "all",
    val expiresAt: Long? = null,
) {
    fun normalized(): Map<String, Any?> {
        require(action in setOf("grant", "deny", "revoke", "withdraw"))
        require(expiresAt == null || action in setOf("grant", "deny"))
        return mapOf(
            "purpose_id" to purposeId,
            "action" to action,
            "channel" to channel,
            "vendor_id" to vendorId,
            "expires_at" to expiresAt,
        )
    }
}

data class NativePrivacySignals(
    val gpc: Boolean,
    val doNotSellOrShare: Boolean,
    val standardsContractSha256: String,
    val purposes: Set<String>,
    val tcfString: String? = null,
    val tcfStringSha256: String? = null,
    val gppString: String? = null,
    val gppStringSha256: String? = null,
) {
    fun normalized(): Map<String, Any?> {
        require(gpc || doNotSellOrShare || tcfString != null || gppString != null)
        require(purposes.isNotEmpty() && purposes.size <= 128)
        require((tcfString == null) == (tcfStringSha256 == null))
        require((gppString == null) == (gppStringSha256 == null))
        tcfString?.let { require(sha256(it.toByteArray()) == tcfStringSha256) }
        gppString?.let { require(sha256(it.toByteArray()) == gppStringSha256) }
        return mapOf(
            "gpc" to gpc,
            "do_not_sell_or_share" to doNotSellOrShare,
            "standards_contract_sha256" to standardsContractSha256,
            "purposes" to purposes.sorted(),
            "tcf_string" to tcfString,
            "tcf_string_sha256" to tcfStringSha256,
            "gpp_string" to gppString,
            "gpp_string_sha256" to gppStringSha256,
        ).filterValues { it != null }
    }
}

data class QueuedConsentOperation(
    val requestId: String,
    val operation: String,
    val normalizedPayload: ByteArray,
    val downstreamIdempotencyKey: String?,
    val createdAt: Long,
    val deviceId: String,
    val deviceRevision: Int,
    val applicationAuthoritySha256: String,
    val expiresAt: Long,
    val requestSha256: String,
    val signedEnvelope: ByteArray,
)

interface DeviceSigner {
    val publicKeyHex: String
    fun sign(canonicalBody: ByteArray): ByteArray
}

interface CanonicalJson {
    /** Must match RFC-style UTF-8 sorted-key compact JSON used by the server. */
    fun encode(value: Any): ByteArray
    fun decodeObject(value: ByteArray): Map<String, Any?>
}

interface ConsentTransport {
    suspend fun post(path: String, body: ByteArray, maximumResponseBytes: Int): ByteArray
}

interface NativeAuthorityRefresher {
    /**
     * Obtains fresh platform attestation over the exact current app/install/device key,
     * uses a new nonce and expected device revision, POSTs without ambient credentials,
     * and validates the closed nested authority/device response before flattening it.
     */
    suspend fun refresh(
        path: String,
        currentAuthority: NativeConsentAuthority,
        expectedDevicePublicKeyHex: String,
        admittedSdkVersion: Int?,
        maximumRequestBytes: Int,
        maximumResponseBytes: Int,
    ): NativeConsentAuthority
}

interface ReceiptVerifier {
    /** Verifies signed_payload_b64url against a versioned Ed25519 trust root and every expected binding. */
    fun verify(
        response: ByteArray,
        request: QueuedConsentOperation,
        authority: NativeConsentAuthority,
        maximumResponseBytes: Int,
    )
}

interface ConsentOutbox {
    suspend fun append(operation: QueuedConsentOperation)
    suspend fun due(limit: Int): List<QueuedConsentOperation>
    suspend fun acknowledge(requestId: String, requestSha256: String)
    suspend fun retry(requestId: String, errorSha256: String)
    suspend fun removeAll(deviceId: String)
    /** Must atomically persist and increment the per-device monotonic counter. */
    suspend fun reserveCounter(deviceId: String): Long
    /** Exact CAS replacement used only for expiry or authority renewal. */
    suspend fun replace(
        requestId: String,
        expectedRequestSha256: String,
        replacement: QueuedConsentOperation,
    )
}

private fun sha256(value: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(value).toHex()

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
