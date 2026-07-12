package com.notcvnt.rknhardering.model

enum class ObservationPolarity {
    POSITIVE,
    AUTHORITATIVE_NEGATIVE,
    INCONCLUSIVE,
}

enum class ObservationAuthority {
    HEURISTIC,
    PUBLIC_ANDROID_API,
    HIDDEN_ANDROID_API,
    BINDER_SERVICE,
    LIBC_OR_PRIVATE_LIBRARY,
    KERNEL_QUERY,
    ACTIVE_CANARY,
}

enum class BetaSuppressionRuleId {
    NETWORK_EPOCH_CHANGED,
    CAPTIVE_PORTAL_ACTIVE,
    NETWORK_NOT_VALIDATED,
    IMS_OR_EIMS_CONTEXT,
    WIFI_CALLING_CONTEXT,
    VCN_CONTEXT,
    NAT64_OR_CLAT_CONTEXT,
    TETHERING_CONTEXT,
    PRIVATE_DNS_EXPECTED,
    ENTERPRISE_PROXY_CONTEXT,
    LOCAL_DNS_FILTER_CONTEXT,
    HEADLESS_SYSTEM_USER_GUARD,
    INACTIVE_KERNEL_OBJECT,
    NO_CAUSAL_COUNTER_DELTA,
    BACKGROUND_TRAFFIC_NOISE,
    STOCK_ANDROID_NETD_POLICY,
    UNSCOPED_GLOBAL_STATE,
    PACKAGE_VISIBILITY_REDACTED,
    SPLIT_APK_OR_UPDATE_LAYOUT,
    ADOPTED_OR_EMULATED_STORAGE,
    ART_JIT_OR_WEBVIEW_MAPPING,
    ABI_OR_PARSER_MISMATCH,
    INSUFFICIENT_REPETITIONS,
    CORRELATED_DUPLICATE_SOURCE,
}

enum class NetworkEpochChangeReason {
    CALLBACK_MONITOR_UNAVAILABLE,
    CALLBACK_BOOTSTRAP_TIMEOUT,
    DEFAULT_NETWORK_CHANGED,
    DEFAULT_NETWORK_LOST,
    TRANSPORTS_CHANGED,
    ACTIVE_INTERFACE_CHANGED,
    VALIDATION_CHANGED,
    CAPTIVE_PORTAL_CHANGED,
    VPN_TRANSPORT_CHANGED,
    PRIVATE_DNS_CHANGED,
    NAT64_CHANGED,
    ROUTES_CHANGED,
    LINK_ADDRESSES_CHANGED,
    DNS_SERVERS_CHANGED,
    DOMAINS_CHANGED,
    HTTP_PROXY_CHANGED,
    CURRENT_USER_CHANGED,
}

data class NetworkEpoch(
    val id: String,
    val startedAtElapsedMs: Long,
    val activeNetworkHandle: Long?,
    val networkHandles: Set<Long>,
    val activeTransports: Set<Int>,
    val activeInterface: String?,
    val validated: Boolean?,
    val captivePortal: Boolean?,
    val vpnTransport: Boolean?,
    val vcnTransport: Boolean?,
    val privateDnsActive: Boolean?,
    val nat64Prefix: String?,
    val telephonyNetworkType: Int?,
    val roaming: Boolean?,
    val currentUserId: Int,
    val routes: Set<String> = emptySet(),
    val linkAddresses: Set<String> = emptySet(),
    val dnsServers: Set<String> = emptySet(),
    val domains: String? = null,
    val privateDnsServerName: String? = null,
    val httpProxy: String? = null,
)

data class BetaObservation(
    val checkId: String,
    val source: EvidenceSource,
    val availability: ProbeAvailability,
    val polarity: ObservationPolarity,
    val authority: ObservationAuthority,
    val confidence: EvidenceConfidence,
    val independenceGroup: String,
    val detectionDomain: DetectionDomain,
    val facts: Map<String, String> = emptyMap(),
    val suppressions: List<BetaSuppressionRuleId> = emptyList(),
    val observedAtElapsedMs: Long,
    val networkEpochId: String?,
    val repeatIndex: Int = 0,
)

enum class ExecutionContextKind {
    MAIN_USER,
    SECONDARY_USER,
    MANAGED_PROFILE,
    PRIVATE_PROFILE,
    CLONE_PROFILE,
    VENDOR_SECURE_PROFILE,
    VIRTUALIZED_APP,
    UNKNOWN_PROFILE,
    UNKNOWN,
}

data class ExecutionContextFacts(
    val uid: Int,
    val appId: Int,
    val uidDerivedUserId: Int,
    val contextUserId: Int? = null,
    val dataDirUserId: Int? = null,
    val deviceProtectedDataDirUserId: Int? = null,
    val externalStorageUserId: Int? = null,
    val publicIsProfile: Boolean? = null,
    val publicIsManagedProfile: Boolean? = null,
    val hiddenProfileType: String? = null,
    val profileParentUserId: Int? = null,
    val profileGroupId: Int? = null,
    val foregroundUserId: Int? = null,
    val packageUidConsistent: Boolean? = null,
    val sourceDirConsistent: Boolean? = null,
    val publicSourceDirConsistent: Boolean? = null,
    val nativeLibraryDirConsistent: Boolean? = null,
    val publicUserProfileCount: Int? = null,
    val publicCurrentUserInProfiles: Boolean? = null,
    val mountNamespaceId: String? = null,
    val selinuxContext: String? = null,
    val networkNamespaceCookie: ULong? = null,
    val vendorProfileKind: String? = null,
    val virtualizationMismatchAxes: Set<String> = emptySet(),
    val splitOrUpdateLayout: Boolean = false,
    val adoptedOrEmulatedStorage: Boolean = false,
    val kind: ExecutionContextKind,
    val confidence: EvidenceConfidence,
)

data class BetaCheckResult(
    val category: CategoryResult,
    val executionContext: ExecutionContextFacts? = null,
    val availabilitySummary: Map<ProbeAvailability, Int> = emptyMap(),
    val networkEpochChanges: Set<NetworkEpochChangeReason> = emptySet(),
    val networkEpochRetryCount: Int = 0,
) {
    companion object {
        fun disabled(): BetaCheckResult = BetaCheckResult(
            category = CategoryResult(
                name = "β Бета-проверки",
                detected = false,
                findings = emptyList(),
                maturity = EvidenceMaturity.BETA,
            ),
        )

        fun error(description: String): BetaCheckResult = BetaCheckResult(
            category = CategoryResult(
                name = "β Бета-проверки",
                detected = false,
                needsReview = false,
                findings = listOf(
                    Finding(
                        description = description,
                        isError = true,
                        maturity = EvidenceMaturity.BETA,
                        checkId = "beta.runner",
                        availability = ProbeAvailability.ERROR,
                    ),
                ),
                maturity = EvidenceMaturity.BETA,
            ),
            availabilitySummary = mapOf(ProbeAvailability.ERROR to 1),
        )
    }
}
