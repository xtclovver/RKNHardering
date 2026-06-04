package com.notcvnt.rknhardering.customcheck

import java.io.Serializable
import java.util.UUID

// === Main Profile ===
data class CustomCheckProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val description: String = "",
    val author: String = "",
    val version: String = "1.0.0",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val checksConfig: ChecksConfig = ChecksConfig(),
    val customDomains: List<CustomDomain> = emptyList(),
    val networkConfig: NetworkConfig = NetworkConfig(),
    val marketplaceInfo: MarketplaceInfo? = null,
    val sourceProfileId: String? = null,
)

// === Checks Configuration ===
data class ChecksConfig(
    val geoIp: GeoIpConfig = GeoIpConfig(),
    val ipComparison: IpComparisonConfig = IpComparisonConfig(),
    val cdnPulling: CdnPullingConfig = CdnPullingConfig(enabled = false),
    val directSigns: DirectSignsConfig = DirectSignsConfig(),
    val indirectSigns: IndirectSignsConfig = IndirectSignsConfig(),
    val nativeSigns: CheckToggle = CheckToggle(),
    val locationSignals: LocationSignalsConfig = LocationSignalsConfig(),
    val icmpSpoofing: IcmpSpoofingConfig = IcmpSpoofingConfig(enabled = false),
    val rttTriangulation: RttTriangulationConfig = RttTriangulationConfig(enabled = false),
    val callTransport: CallTransportConfig = CallTransportConfig(enabled = false),
    val splitTunnel: SplitTunnelConfig = SplitTunnelConfig(),
    val domainReachabilityEnabled: Boolean = true,
)

// === Base toggle ===
data class CheckToggle(val enabled: Boolean = true)

// === Response Mapping — universal API response field mapper ===
enum class ResponseType {
    JSON,           // Standard JSON, fields via JSONPath ($.field.nested)
    PLAIN_TEXT,     // Plain text (single IP in response)
    KEY_VALUE,      // Format key=value\n (like cloudflare trace)
    REGEX,          // Regex with named groups
}

data class ResponseMapping(
    val responseType: ResponseType = ResponseType.JSON,
    val ipPath: String? = null,
    val countryCodePath: String? = null,
    val countryNamePath: String? = null,
    val ispPath: String? = null,
    val orgPath: String? = null,
    val asnPath: String? = null,
    val isHostingPath: String? = null,
    val isProxyPath: String? = null,
) : Serializable

// === GeoIP with full customization ===
data class GeoIpConfig(
    val enabled: Boolean = true,
    val timeoutMs: Int = 10_000,
    val builtinProviders: Map<String, Boolean> = emptyMap(),
    val customProviders: List<CustomGeoIpProvider> = emptyList(),
)

data class CustomGeoIpProvider(
    val name: String,
    val url: String,
    val enabled: Boolean = true,
    val responseMapping: ResponseMapping = ResponseMapping(),
)

// === IP Comparison ===
enum class EndpointScope { RU, NON_RU }

data class IpComparisonConfig(
    val enabled: Boolean = true,
    val timeoutMs: Int = 8_000,
    val builtinRuCheckersEnabled: Boolean = true,
    val builtinNonRuCheckersEnabled: Boolean = true,
    val customEndpoints: List<CustomIpEndpoint> = emptyList(),
)

data class CustomIpEndpoint(
    val label: String,
    val url: String,
    val scope: EndpointScope = EndpointScope.RU,
    val enabled: Boolean = true,
    val responseMapping: ResponseMapping = ResponseMapping(responseType = ResponseType.PLAIN_TEXT),
)

// === CDN Pulling ===
data class CdnPullingConfig(
    val enabled: Boolean = false,
    val timeoutMs: Int = 10_000,
    val meduzaEnabled: Boolean = true,
    val rutrackerEnabled: Boolean = true,
    val builtinTargetsEnabled: Boolean = true,
    val customTargets: List<CustomCdnTarget> = emptyList(),
)

data class CustomCdnTarget(
    val label: String,
    val url: String,
    val enabled: Boolean = true,
    val responseMapping: ResponseMapping = ResponseMapping(responseType = ResponseType.KEY_VALUE),
)

// === Direct Signs — granular toggles ===
data class DirectSignsConfig(
    val enabled: Boolean = true,
    val checkTransportVpn: Boolean = true,
    val checkHttpProxy: Boolean = true,
    val checkSocksProxy: Boolean = true,
    val checkProxyInfo: Boolean = true,
    val checkVpnService: Boolean = true,
)

// === Indirect Signs — granular toggles ===
data class IndirectSignsConfig(
    val enabled: Boolean = true,
    val checkNotVpnCap: Boolean = true,
    val checkVpnInterfaces: Boolean = true,
    val checkMtuAnomaly: Boolean = true,
    val checkIpsec: Boolean = true,
    val checkRouting: Boolean = true,
    val checkDns: Boolean = true,
    val checkProxyTools: Boolean = true,
    val checkLocalListeners: Boolean = true,
    val checkDumpsys: Boolean = true,
    val listenerPortThreshold: Int = 5,
)

// === Location Signals ===
data class LocationSignalsConfig(
    val enabled: Boolean = true,
    val checkBeacondb: Boolean = true,
    val checkCellTowers: Boolean = true,
    val checkWifiSignals: Boolean = true,
)

// === ICMP Spoofing with custom targets ===
data class IcmpSpoofingConfig(
    val enabled: Boolean = true,
    val timeoutMs: Int = 5_000,
    val pingCount: Int = 3,
    val builtinTargetsEnabled: Boolean = true,
    val customTargets: List<IcmpTarget> = emptyList(),
)

data class IcmpTarget(
    val host: String,
    val label: String,
    val isControl: Boolean = false,
)

// === RTT Triangulation ===
data class RttTriangulationConfig(
    val enabled: Boolean = false,
    val timeoutMs: Int = 5_000,
    val pingCount: Int = 5,
    val builtinTargetsEnabled: Boolean = true,
    val customTargets: List<RttTarget> = emptyList(),
)

data class RttTarget(
    val host: String,
    val label: String,
    val expectedLocation: String = "",
)

// === Call Transport & STUN ===
data class CallTransportConfig(
    val enabled: Boolean = false,
    val timeoutMs: Int = 5_000,
    val builtinGlobalStunEnabled: Boolean = true,
    val builtinRuStunEnabled: Boolean = true,
    val checkMtproto: Boolean = true,
    val customStunServers: List<StunServer> = emptyList(),
)

data class StunServer(
    val host: String,
    val port: Int = 3478,
    val label: String,
)

// === Split Tunnel ===
data class SplitTunnelConfig(
    val enabled: Boolean = true,
    val proxyScan: Boolean = true,
    val xrayApiScan: Boolean = true,
    val portRange: String = "popular",
    val portRangeStart: Int = 1024,
    val portRangeEnd: Int = 65535,
    val connectTimeoutMs: Int = 300,
    val checkUnderlyingNetwork: Boolean = true,
    val checkVpnNetworkBinding: Boolean = true,
    val checkMtprotoViaProxy: Boolean = true,
)

// === Custom domains ===
data class CustomDomain(
    val domain: String,
    val checkType: String,
    val description: String = "",
    val expectedDnsAvailable: Boolean = true,
    val expectedTcpAvailable: Boolean = true,
    val expectedTlsAvailable: Boolean = true,
)

// === Network configuration ===
data class NetworkConfig(
    val networkRequestsEnabled: Boolean = true,
    val dnsMode: String = "system",
    val dnsPreset: String = "custom",
    val dnsServers: String = "",
    val dohUrl: String = "",
    val dohBootstrap: String = "",
)

// === Marketplace info ===
// signatureVerified: true only when this profile entered the device via a
// catalog whose Ed25519 signature validated against the bundled public key
// AND the profile body matched the catalog's expected_hash. Any other source
// (file import, clipboard, hand-edited storage) must store false. Drives the
// "Official" / "Verified" badges — the in-file flags official/verified are
// advisory and ignored unless signatureVerified is also true.
data class MarketplaceInfo(
    val sourceUrl: String? = null,
    val official: Boolean = false,
    val verified: Boolean = false,
    val signatureVerified: Boolean = false,
    val marketplaceId: String? = null,
    val originalHash: String? = null,
)
