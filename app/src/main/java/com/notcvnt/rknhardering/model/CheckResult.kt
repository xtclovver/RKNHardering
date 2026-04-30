package com.notcvnt.rknhardering.model

import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.TunProbeDiagnostics
import com.notcvnt.rknhardering.probe.XrayApiScanResult

data class GeoIpFacts(
    val ip: String? = null,
    val countryCode: String? = null,
    val asn: String? = null,
    val outsideRu: Boolean = false,
    val hosting: Boolean = false,
    val proxyDb: Boolean = false,
    val fetchError: Boolean = false,
)

enum class EvidenceConfidence {
    LOW,
    MEDIUM,
    HIGH,
}

enum class EvidenceSource {
    GEO_IP,
    DIRECT_NETWORK_CAPABILITIES,
    INDIRECT_NETWORK_CAPABILITIES,
    ICMP_SPOOFING,
    SYSTEM_PROXY,
    INSTALLED_APP,
    VPN_SERVICE_DECLARATION,
    ACTIVE_VPN,
    LOCAL_PROXY,
    XRAY_API,
    SPLIT_TUNNEL_BYPASS,
    NETWORK_INTERFACE,
    ROUTING,
    DNS,
    PROXY_TECHNICAL_SIGNAL,
    DUMPSYS,
    LOCATION_SIGNALS,
    VPN_GATEWAY_LEAK,
    VPN_NETWORK_BINDING,
    TUN_ACTIVE_PROBE,
    TELEGRAM_CALL_TRANSPORT,
    WHATSAPP_CALL_TRANSPORT,
    STUN_PROBE,
    NATIVE_INTERFACE,
    NATIVE_ROUTE,
    NATIVE_SOCKET,
    NATIVE_HOOK_MARKERS,
    NATIVE_JVM_MISMATCH,
    NATIVE_LIBRARY_INTEGRITY,
    NATIVE_ROOT_DETECTION,
}

enum class StunScope {
    RU,
    GLOBAL,
}

data class StunProbeResult(
    val host: String,
    val port: Int,
    val scope: StunScope,
    val mappedIpv4: String? = null,
    val mappedIpv6: String? = null,
    val error: String? = null,
) {
    val hasResponse: Boolean get() = mappedIpv4 != null || mappedIpv6 != null
    val mappedIpDisplay: String?
        get() = when {
            mappedIpv4 != null && mappedIpv6 != null -> "$mappedIpv4 / $mappedIpv6"
            mappedIpv4 != null -> mappedIpv4
            mappedIpv6 != null -> mappedIpv6
            else -> null
        }
}

data class StunProbeGroupResult(
    val scope: StunScope,
    val results: List<StunProbeResult>,
) {
    val respondedCount: Int get() = results.count { it.hasResponse }
    val totalCount: Int get() = results.size
}

enum class CallTransportService {
    TELEGRAM,
    WHATSAPP,
}

enum class CallTransportProbeKind {
    DIRECT_UDP_STUN,
    PROXY_ASSISTED_TELEGRAM,
    PROXY_ASSISTED_UDP_STUN,
}

enum class CallTransportStatus {
    BASELINE,
    NO_SIGNAL,
    NEEDS_REVIEW,
    UNSUPPORTED,
    ERROR,
}

enum class CallTransportNetworkPath {
    ACTIVE,
    UNDERLYING,
    LOCAL_PROXY,
}

data class CallTransportLeakResult(
    val service: CallTransportService,
    val probeKind: CallTransportProbeKind,
    val networkPath: CallTransportNetworkPath,
    val status: CallTransportStatus,
    val targetHost: String? = null,
    val targetPort: Int? = null,
    val resolvedIps: List<String> = emptyList(),
    val mappedIp: String? = null,
    val observedPublicIp: String? = null,
    val summary: String,
    val confidence: EvidenceConfidence? = null,
    val experimental: Boolean = false,
)

enum class VpnAppKind {
    TARGETED_BYPASS,
    GENERIC_VPN,
}

data class VpnAppTechnicalMetadata(
    val versionName: String? = null,
    val serviceNames: List<String> = emptyList(),
    val appType: String? = null,
    val coreType: String? = null,
    val corePath: String? = null,
    val goVersion: String? = null,
    val systemApp: Boolean = false,
    val matchedByNameHeuristic: Boolean = false,
)

data class Finding(
    val description: String,
    val detected: Boolean = false,
    val needsReview: Boolean = false,
    val isInformational: Boolean = false,
    val isError: Boolean = false,
    val source: EvidenceSource? = null,
    val confidence: EvidenceConfidence? = null,
    val family: String? = null,
    val packageName: String? = null,
)

data class EvidenceItem(
    val source: EvidenceSource,
    val detected: Boolean,
    val confidence: EvidenceConfidence,
    val description: String,
    val family: String? = null,
    val packageName: String? = null,
    val kind: VpnAppKind? = null,
)

data class MatchedVpnApp(
    val packageName: String,
    val appName: String,
    val family: String?,
    val kind: VpnAppKind,
    val source: EvidenceSource,
    val active: Boolean,
    val confidence: EvidenceConfidence,
    val technicalMetadata: VpnAppTechnicalMetadata? = null,
)

data class ActiveVpnApp(
    val packageName: String?,
    val serviceName: String?,
    val family: String?,
    val kind: VpnAppKind?,
    val source: EvidenceSource,
    val confidence: EvidenceConfidence,
    val technicalMetadata: VpnAppTechnicalMetadata? = null,
)

data class LocalProxyOwner(
    val uid: Int,
    val packageNames: List<String>,
    val appLabels: List<String>,
    val confidence: EvidenceConfidence,
)

enum class LocalProxyOwnerStatus {
    RESOLVED,
    UNRESOLVED,
    AMBIGUOUS,
}

enum class LocalProxyCheckStatus {
    CONFIRMED_BYPASS,
    SAME_IP,
    PROXY_IP_UNAVAILABLE,
    DIRECT_IP_UNAVAILABLE,
}

enum class LocalProxySummaryReason {
    CONFIRMED_BYPASS,
    FIRST_WITH_PROXY_IP,
    FIRST_DISCOVERED,
}

data class LocalProxyCheckResult(
    val endpoint: ProxyEndpoint,
    val owner: LocalProxyOwner? = null,
    val ownerStatus: LocalProxyOwnerStatus = LocalProxyOwnerStatus.UNRESOLVED,
    val proxyIp: String? = null,
    val status: LocalProxyCheckStatus,
    val mtProtoReachable: Boolean? = null,
    val mtProtoTarget: String? = null,
    val summaryReason: LocalProxySummaryReason? = null,
)

data class CategoryResult(
    val name: String,
    val detected: Boolean,
    val findings: List<Finding>,
    val needsReview: Boolean = false,
    val evidence: List<EvidenceItem> = emptyList(),
    val matchedApps: List<MatchedVpnApp> = emptyList(),
    val activeApps: List<ActiveVpnApp> = emptyList(),
    val callTransportLeaks: List<CallTransportLeakResult> = emptyList(),
    val stunProbeGroups: List<StunProbeGroupResult> = emptyList(),
    val geoFacts: GeoIpFacts? = null,
) {
    val hasError: Boolean
        get() = findings.any { it.isError }
}

enum class Verdict {
    NOT_DETECTED,
    NEEDS_REVIEW,
    DETECTED,
}

data class BypassResult(
    val proxyEndpoint: ProxyEndpoint?,
    val proxyOwner: LocalProxyOwner? = null,
    val directIp: String?,
    val proxyIp: String?,
    val vpnNetworkIp: String? = null,
    val underlyingIp: String? = null,
    val xrayApiScanResult: XrayApiScanResult?,
    val proxyChecks: List<LocalProxyCheckResult> = emptyList(),
    val findings: List<Finding>,
    val detected: Boolean,
    val needsReview: Boolean = false,
    val evidence: List<EvidenceItem> = emptyList(),
)

enum class IpCheckerScope {
    RU,
    NON_RU,
}

data class IpCheckerResponse(
    val label: String,
    val url: String,
    val scope: IpCheckerScope,
    val ip: String? = null,
    val error: String? = null,
    val ipv4Records: List<String> = emptyList(),
    val ipv6Records: List<String> = emptyList(),
    val ignoredIpv6Error: Boolean = false,
)

data class IpCheckerGroupResult(
    val title: String,
    val detected: Boolean,
    val needsReview: Boolean = false,
    val statusLabel: String,
    val summary: String,
    val canonicalIp: String? = null,
    val responses: List<IpCheckerResponse>,
    val ignoredIpv6ErrorCount: Int = 0,
)

data class IpComparisonResult(
    val detected: Boolean,
    val needsReview: Boolean = false,
    val summary: String,
    val ruGroup: IpCheckerGroupResult,
    val nonRuGroup: IpCheckerGroupResult,
)

data class CdnPullingResponse(
    val targetLabel: String,
    val url: String,
    val ip: String? = null,
    val ipv4: String? = null,
    val ipv6: String? = null,
    val ipv4Unavailable: Boolean = false,
    val ipv4Error: String? = null,
    val ipv6Error: String? = null,
    val importantFields: Map<String, String> = emptyMap(),
    val rawBody: String? = null,
    val error: String? = null,
)

data class CdnPullingResult(
    val detected: Boolean,
    val needsReview: Boolean = false,
    val hasError: Boolean = false,
    val summary: String,
    val responses: List<CdnPullingResponse> = emptyList(),
    val findings: List<Finding> = emptyList(),
) {
    companion object {
        fun empty(): CdnPullingResult = CdnPullingResult(
            detected = false,
            needsReview = false,
            hasError = false,
            summary = "",
            responses = emptyList(),
            findings = emptyList(),
        )
    }
}

data class CheckResult(
    val geoIp: CategoryResult,
    val ipComparison: IpComparisonResult,
    val cdnPulling: CdnPullingResult = CdnPullingResult.empty(),
    val directSigns: CategoryResult,
    val indirectSigns: CategoryResult,
    val locationSignals: CategoryResult,
    val bypassResult: BypassResult,
    val verdict: Verdict,
    val tunProbeDiagnostics: TunProbeDiagnostics? = null,
    val nativeSigns: CategoryResult = CategoryResult(
        name = "",
        detected = false,
        findings = emptyList(),
    ),
    val icmpSpoofing: CategoryResult = CategoryResult(
        name = "",
        detected = false,
        findings = emptyList(),
    ),
    val ipConsensus: IpConsensusResult = IpConsensusResult.empty(),
)
