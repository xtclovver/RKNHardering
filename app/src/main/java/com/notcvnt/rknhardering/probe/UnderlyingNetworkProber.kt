package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer
import com.notcvnt.rknhardering.network.ResolverBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class PerTargetProbe(
    val targetHost: String,
    val targetGroup: com.notcvnt.rknhardering.model.TargetGroup,
    val directIp: String? = null,
    val vpnIp: String? = null,
    val comparison: PublicIpNetworkComparison? = null,
    val error: String? = null,
)

private data class ProbeTarget(
    val displayHost: String,
    val urls: List<String>,
)

/**
 * Detects whether a non-VPN (underlying) network is reachable from this app.
 *
 * When VPN runs in split-tunnel / per-app mode, apps excluded from the tunnel
 * (or any app that can bind to the underlying network) can reach the VPN gateway
 * and any external host directly, leaking the real IP and confirming VPN usage.
 *
 * The probe enumerates all networks, finds one without TRANSPORT_VPN, binds an
 * HTTPS request to it, and fetches the public IP. Success means split-tunnel
 * vulnerability is present.
 */
object UnderlyingNetworkProber {
    internal data class NetworkSnapshot(
        val network: Network,
        val interfaceName: String?,
        val hasInternet: Boolean,
        val hasVpnTransport: Boolean,
    )

    internal data class ProbeEnvironment(
        val activeNetwork: Network?,
        val networks: List<NetworkSnapshot>,
    )

    internal data class Dependencies(
        val initNativeCurl: (Context) -> Unit = NativeCurlBridge::initIfNeeded,
        val environmentProvider: (Context) -> ProbeEnvironment = ::buildProbeEnvironment,
        val comparisonFetcher: suspend (
            NetworkSnapshot,
            DnsResolverConfig,
            Boolean,
            TunProbeModeOverride,
            List<String>?,
        ) -> PublicIpNetworkComparison = ::fetchIpViaNetworkComparison,
    )

    @Volatile
    internal var dependenciesOverride: Dependencies? = null

    data class ProbeResult(
        val vpnActive: Boolean,
        val underlyingReachable: Boolean = false,
        val ruTarget: PerTargetProbe = PerTargetProbe(
            targetHost = "",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.RU,
        ),
        val nonRuTarget: PerTargetProbe = PerTargetProbe(
            targetHost = "",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.NON_RU,
        ),
        val vpnError: String? = null,
        val underlyingError: String? = null,
        val dnsPathMismatch: Boolean = false,
        val vpnNetwork: android.net.Network? = null,
        val underlyingNetwork: android.net.Network? = null,
        val activeNetworkIsVpn: Boolean? = null,
        val tunProbeDiagnostics: TunProbeDiagnostics? = null,
    ) {
        private fun preferredComparisonTarget(): PerTargetProbe? {
            val candidates = listOf(nonRuTarget, ruTarget).filter {
                it.vpnIp != null || it.directIp != null
            }
            return candidates.firstOrNull { it.vpnIp != null && it.directIp != null && it.vpnIp != it.directIp }
                ?: candidates.firstOrNull { it.targetGroup == com.notcvnt.rknhardering.model.TargetGroup.NON_RU }
                ?: candidates.firstOrNull()
        }

        val vpnIp: String? get() = preferredComparisonTarget()?.vpnIp
        val underlyingIp: String? get() = preferredComparisonTarget()?.directIp
        val vpnIpComparison: PublicIpNetworkComparison?
            get() = preferredComparisonTarget()?.comparison ?: ruTarget.comparison ?: nonRuTarget.comparison
        val underlyingIpComparison: PublicIpNetworkComparison?
            get() = preferredComparisonTarget()?.comparison ?: ruTarget.comparison ?: nonRuTarget.comparison
    }

    private val RU_PROBE_TARGET = ProbeTarget(
        displayHost = "ipv4-internet.yandex.net",
        urls = listOf(
            "https://ipv4-internet.yandex.net/api/v0/ip",
            "https://ip.mail.ru",
        ),
    )
    private val NON_RU_PROBE_TARGET = ProbeTarget(
        displayHost = "api-ipv4.ip.sb",
        urls = listOf(
            "https://api-ipv4.ip.sb/ip",
            "https://checkip.amazonaws.com",
            "https://ifconfig.me/ip",
            "https://api4.ipify.org",
        ),
    )

    @Suppress("DEPRECATION")
    suspend fun probe(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        debugEnabled: Boolean = false,
        modeOverride: TunProbeModeOverride = TunProbeModeOverride.AUTO,
    ): ProbeResult = withContext(Dispatchers.IO) {
        val dependencies = dependenciesOverride ?: Dependencies()
        dependencies.initNativeCurl(context)
        val environment = dependencies.environmentProvider(context)
        val activeNetworkIsVpn = environment.activeNetwork
            ?.let { active -> environment.networks.firstOrNull { it.network == active } }
            ?.hasVpnTransport

        val internetNetworks = environment.networks.filter { it.hasInternet }
        val vpnNetwork = internetNetworks.firstOrNull { it.hasVpnTransport }
        val nonVpnNetworks = internetNetworks.filterNot { it.hasVpnTransport }

        if (vpnNetwork == null) {
            return@withContext ProbeResult(
                vpnActive = false,
                underlyingReachable = false,
                activeNetworkIsVpn = activeNetworkIsVpn,
                tunProbeDiagnostics = buildTunProbeDiagnostics(
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                        activeNetworkIsVpn = activeNetworkIsVpn,
                        vpnNetworkPresent = false,
                        underlyingNetworkPresent = nonVpnNetworks.isNotEmpty(),
                        vpnInterfaceName = null,
                        vpnComparison = null,
                    underlyingInterfaceName = nonVpnNetworks.firstOrNull()?.interfaceName,
                    underlyingComparison = null,
                ),
            )
        }

        val ruVpnComparison = dependencies.comparisonFetcher(
            vpnNetwork,
            resolverConfig,
            debugEnabled,
            modeOverride,
            RU_PROBE_TARGET.urls,
        )
        val nonRuVpnComparison = dependencies.comparisonFetcher(
            vpnNetwork,
            resolverConfig,
            debugEnabled,
            modeOverride,
            NON_RU_PROBE_TARGET.urls,
        )
        val vpnError = ruVpnComparison.selectedError ?: nonRuVpnComparison.selectedError

        val ruVpnProbe = PerTargetProbe(
            targetHost = RU_PROBE_TARGET.displayHost,
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.RU,
            vpnIp = ruVpnComparison.selectedIp,
            comparison = ruVpnComparison,
            error = ruVpnComparison.selectedError,
        )
        val nonRuVpnProbe = PerTargetProbe(
            targetHost = NON_RU_PROBE_TARGET.displayHost,
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.NON_RU,
            vpnIp = nonRuVpnComparison.selectedIp,
            comparison = nonRuVpnComparison,
            error = nonRuVpnComparison.selectedError,
        )

        if (nonVpnNetworks.isEmpty()) {
            return@withContext ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                ruTarget = ruVpnProbe,
                nonRuTarget = nonRuVpnProbe,
                vpnError = vpnError,
                dnsPathMismatch = ruVpnComparison.dnsPathMismatch,
                vpnNetwork = vpnNetwork.network,
                activeNetworkIsVpn = activeNetworkIsVpn,
                tunProbeDiagnostics = buildTunProbeDiagnostics(
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                    activeNetworkIsVpn = activeNetworkIsVpn,
                    vpnNetworkPresent = true,
                    underlyingNetworkPresent = false,
                    vpnInterfaceName = vpnNetwork.interfaceName,
                    vpnComparison = ruVpnComparison,
                    underlyingInterfaceName = null,
                    underlyingComparison = null,
                ),
            )
        }

        var ruUnderlyingIp: String? = null
        var ruUnderlyingError: String? = null
        var nonRuUnderlyingIp: String? = null
        var nonRuUnderlyingError: String? = null
        var usedNetwork: Network? = null
        var usedBoundNetwork: NetworkSnapshot? = null
        var ruUnderlyingComparison: PublicIpNetworkComparison? = null
        var nonRuUnderlyingComparison: PublicIpNetworkComparison? = null
        var lastUnderlyingNetwork: NetworkSnapshot? = null

        for (network in nonVpnNetworks) {
            lastUnderlyingNetwork = network

            // Probe RU target
            val ruResult = dependencies.comparisonFetcher(
                network,
                resolverConfig,
                debugEnabled,
                modeOverride,
                RU_PROBE_TARGET.urls,
            )
            ruUnderlyingComparison = ruResult
            ruUnderlyingIp = ruResult.selectedIp
            ruUnderlyingError = ruResult.selectedError ?: ruUnderlyingError

            // Probe non-RU target
            val nonRuResult = dependencies.comparisonFetcher(
                network,
                resolverConfig,
                debugEnabled,
                modeOverride,
                NON_RU_PROBE_TARGET.urls,
            )
            nonRuUnderlyingComparison = nonRuResult
            nonRuUnderlyingIp = nonRuResult.selectedIp
            nonRuUnderlyingError = nonRuResult.selectedError ?: nonRuUnderlyingError

            // Consider both targets successful if either reached
            if (ruUnderlyingIp != null || nonRuUnderlyingIp != null) {
                usedNetwork = network.network
                usedBoundNetwork = network
                break
            }
        }

        val ruTarget = ruVpnProbe.copy(
            directIp = ruUnderlyingIp,
            comparison = ruUnderlyingComparison ?: ruVpnComparison,
            error = ruVpnComparison.selectedError,
        )
        val nonRuTarget = nonRuVpnProbe.copy(
            directIp = nonRuUnderlyingIp,
            comparison = nonRuUnderlyingComparison ?: nonRuVpnComparison,
            error = nonRuVpnComparison.selectedError,
        )

        ProbeResult(
            vpnActive = true,
            underlyingReachable = ruUnderlyingIp != null || nonRuUnderlyingIp != null,
            ruTarget = ruTarget,
            nonRuTarget = nonRuTarget,
            vpnError = vpnError,
            underlyingError = ruUnderlyingError ?: nonRuUnderlyingError,
            dnsPathMismatch = ruVpnComparison.dnsPathMismatch ||
                nonRuVpnComparison.dnsPathMismatch ||
                (ruUnderlyingComparison?.dnsPathMismatch == true) ||
                (nonRuUnderlyingComparison?.dnsPathMismatch == true),
            vpnNetwork = vpnNetwork.network,
            underlyingNetwork = usedNetwork,
            activeNetworkIsVpn = activeNetworkIsVpn,
            tunProbeDiagnostics = buildTunProbeDiagnostics(
                debugEnabled = debugEnabled,
                modeOverride = modeOverride,
                activeNetworkIsVpn = activeNetworkIsVpn,
                vpnNetworkPresent = true,
                underlyingNetworkPresent = true,
                vpnInterfaceName = vpnNetwork.interfaceName,
                vpnComparison = ruVpnComparison,
                underlyingInterfaceName = (usedBoundNetwork ?: lastUnderlyingNetwork)?.interfaceName,
                underlyingComparison = ruUnderlyingComparison ?: nonRuUnderlyingComparison,
            ),
        )
    }

    private fun buildProbeEnvironment(context: Context): ProbeEnvironment {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networks = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            NetworkSnapshot(
                network = network,
                interfaceName = NetworkInterfaceNameNormalizer.canonicalName(
                    cm.getLinkProperties(network)?.interfaceName,
                ),
                hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                hasVpnTransport = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            )
        }
        return ProbeEnvironment(
            activeNetwork = cm.activeNetwork,
            networks = networks,
        )
    }

    private suspend fun fetchIpViaNetworkComparison(
        networkSnapshot: NetworkSnapshot,
        resolverConfig: DnsResolverConfig,
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
        targetUrls: List<String>? = null,
    ): PublicIpNetworkComparison {
        val fallbackBinding = networkSnapshot.interfaceName
            ?.takeIf { it.isNotBlank() }
            ?.let { ResolverBinding.OsDeviceBinding(it, dnsMode = ResolverBinding.DnsMode.SYSTEM) }

        return IfconfigClient.fetchIpViaNetworkComparison(
            primaryBinding = ResolverBinding.AndroidNetworkBinding(networkSnapshot.network),
            fallbackBinding = fallbackBinding,
            resolverConfig = resolverConfig,
            modeOverride = modeOverride,
            collectTrace = debugEnabled,
            targetUrls = targetUrls,
        )
    }

    internal fun resetForTests() {
        dependenciesOverride = null
    }

    internal fun buildTunProbeDiagnostics(
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
        activeNetworkIsVpn: Boolean?,
        vpnNetworkPresent: Boolean,
        underlyingNetworkPresent: Boolean,
        vpnInterfaceName: String?,
        vpnComparison: PublicIpNetworkComparison?,
        underlyingInterfaceName: String?,
        underlyingComparison: PublicIpNetworkComparison?,
    ): TunProbeDiagnostics? {
        if (!debugEnabled) return null

        return TunProbeDiagnostics(
            enabled = true,
            modeOverride = modeOverride,
            activeNetworkIsVpn = activeNetworkIsVpn,
            vpnNetworkPresent = vpnNetworkPresent,
            underlyingNetworkPresent = underlyingNetworkPresent,
            vpnPath = vpnComparison?.toPathDiagnostics(vpnInterfaceName),
            underlyingPath = underlyingComparison?.toPathDiagnostics(underlyingInterfaceName),
        )
    }
}
