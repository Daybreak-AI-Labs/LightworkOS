package ai.lightwork.consent

/** Standalone JVM contract check; this does not qualify an Android device. */
fun main() {
    val digest = "a".repeat(64)
    val authority = NativeConsentAuthority(
        applicationRef = "living-room-prod",
        applicationAuthoritySha256 = digest,
        tenantId = "tenant-one",
        applicationId = "com.example.livingroom",
        platform = "android",
        deviceId = "CP-DEV-example",
        deviceRevision = 1,
        keyRevision = 1,
        sdkVersion = 4,
        publicClientRevision = 2,
        publicClientRecordSha256 = digest,
        publicationSha256 = digest,
        publicationBundleSha256 = digest,
        configurationSha256 = digest,
        policyId = "policy-one",
        policyVersion = 3,
        policySha256 = digest,
        standardsContractSha256 = digest,
    )
    authority.validate()
    authority.copy(platform = "fireos", sdkVersion = 1_000_000).validate()
    val invalid = listOf(
        authority.copy(sdkVersion = 1_000_001),
        authority.copy(sdkVersion = 0),
        authority.copy(applicationId = "com.example/invalid"),
        authority.copy(applicationId = "ab"),
        authority.copy(applicationRef = "invalid ref"),
        authority.copy(deviceRevision = 0),
        authority.copy(platform = "webos"),
        authority.copy(policySha256 = "A".repeat(64)),
    )
    invalid.forEach { candidate ->
        check(runCatching { candidate.validate() }.exceptionOrNull() is IllegalArgumentException)
    }
    println("Android authority contract cases passed on the JVM")
}
