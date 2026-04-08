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
    NETWORK_CAPABILITIES,
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
    DUMPSYS,
    LOCATION_SIGNALS,
    VPN_GATEWAY_LEAK,
}

enum class VpnAppKind {
    TARGETED_BYPASS,
    GENERIC_VPN,
}

data class Finding(
    val description: String,
    val detected: Boolean = false,
    val needsReview: Boolean = false,
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

data class CategoryResult(
    val name: String,
    val detected: Boolean,
    val findings: List<Finding>,
    val needsReview: Boolean = false,
    val evidence: List<EvidenceItem> = emptyList(),
    val matchedApps: List<MatchedVpnApp> = emptyList(),
    val activeApps: List<ActiveVpnApp> = emptyList(),
)

enum class Verdict {
    NOT_DETECTED,
    NEEDS_REVIEW,
    DETECTED,
}

data class BypassResult(
    val proxyEndpoint: ProxyEndpoint?,
    val directIp: String?,
    val proxyIp: String?,
    val xrayApiScanResult: XrayApiScanResult?,
    val findings: List<Finding>,
    val detected: Boolean,
    val needsReview: Boolean = false,
    val evidence: List<EvidenceItem> = emptyList(),
)

data class CheckResult(
    val geoIp: CategoryResult,
    val directSigns: CategoryResult,
    val indirectSigns: CategoryResult,
    val locationSignals: CategoryResult,
    val bypassResult: BypassResult,
    val verdict: Verdict,
)
