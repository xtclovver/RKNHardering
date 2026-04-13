package com.notcvnt.rknhardering.model

import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.XrayApiScanResult

enum class EvidenceConfidence {
    LOW,
    MEDIUM,
    HIGH,
}

enum class EvidenceSource {
    GEO_IP,
    DIRECT_NETWORK_CAPABILITIES,
    INDIRECT_NETWORK_CAPABILITIES,
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
)

data class ActiveVpnApp(
    val packageName: String?,
    val serviceName: String?,
    val family: String?,
    val kind: VpnAppKind?,
    val source: EvidenceSource,
    val confidence: EvidenceConfidence,
)

data class LocalProxyOwner(
    val uid: Int,
    val packageNames: List<String>,
    val appLabels: List<String>,
    val confidence: EvidenceConfidence,
)

data class CategoryResult(
    val name: String,
    val detected: Boolean,
    val findings: List<Finding>,
    val needsReview: Boolean = false,
    val evidence: List<EvidenceItem> = emptyList(),
    val matchedApps: List<MatchedVpnApp> = emptyList(),
    val activeApps: List<ActiveVpnApp> = emptyList(),
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
    val callTransportLeaks: List<CallTransportLeakResult> = emptyList(),
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

data class CheckResult(
    val geoIp: CategoryResult,
    val ipComparison: IpComparisonResult,
    val directSigns: CategoryResult,
    val indirectSigns: CategoryResult,
    val locationSignals: CategoryResult,
    val bypassResult: BypassResult,
    val verdict: Verdict,
)
