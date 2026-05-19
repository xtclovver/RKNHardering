package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer
import com.notcvnt.rknhardering.network.ResolverBinding
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
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

private data class TargetComparisons(
    val ru: PublicIpNetworkComparison,
    val nonRu: PublicIpNetworkComparison,
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
        // Used when no Android network object is available (per-app VPN exclusion case).
        val osDeviceComparisonFetcher: suspend (
            String,
            DnsResolverConfig,
            Boolean,
            TunProbeModeOverride,
            List<String>?,
        ) -> PublicIpNetworkComparison = ::fetchIpViaOsDeviceBinding,
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
        tunInterfacePresent: Boolean = false,
        tunInterfaceName: String? = null,
        underlyingInterfaceName: String? = null,
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
            // Per-app whitelist fallback: tun0 is physically present but excluded app
            // cannot see it in cm.allNetworks because per-app VPN does not expose the VPN
            // network to excluded packages. Use OS device binding directly on tun interface.
            if (tunInterfacePresent && tunInterfaceName != null) {
                return@withContext probeViaOsDeviceBinding(
                    tunInterfaceName = tunInterfaceName,
                    underlyingInterfaceName = underlyingInterfaceName,
                    resolverConfig = resolverConfig,
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                    activeNetworkIsVpn = activeNetworkIsVpn,
                    dependencies = dependencies,
                )
            }
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

        val vpnComparisons = fetchTargetComparisons(
            snapshot = vpnNetwork,
            dependencies = dependencies,
            resolverConfig = resolverConfig,
            debugEnabled = debugEnabled,
            modeOverride = modeOverride,
        )
        val ruVpnComparison = vpnComparisons.ru
        val nonRuVpnComparison = vpnComparisons.nonRu
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

            val comparisons = fetchTargetComparisons(
                snapshot = network,
                dependencies = dependencies,
                resolverConfig = resolverConfig,
                debugEnabled = debugEnabled,
                modeOverride = modeOverride,
            )
            val ruResult = comparisons.ru
            ruUnderlyingComparison = ruResult
            ruUnderlyingIp = ruResult.selectedIp
            ruUnderlyingError = ruResult.selectedError ?: ruUnderlyingError

            val nonRuResult = comparisons.nonRu
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

    // Yandex DoH used for per-app fallback probes so that DNS goes through
    // CONFIGURED resolver and not the operator system DNS (which is in the
    // tunnel and unreachable for excluded apps).
    private val FALLBACK_RESOLVER_CONFIG = DnsResolverConfig(
        mode = com.notcvnt.rknhardering.network.DnsResolverMode.DOH,
        preset = com.notcvnt.rknhardering.network.DnsResolverPreset.YANDEX,
    )

    private suspend fun probeViaOsDeviceBinding(
        tunInterfaceName: String,
        underlyingInterfaceName: String?,
        resolverConfig: DnsResolverConfig,
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
        activeNetworkIsVpn: Boolean?,
        dependencies: Dependencies,
    ): ProbeResult = coroutineScope {
        // Pick a resolver that works for an excluded app: fall back to Yandex DoH
        // only if the caller provided system() — system DNS is inside the tunnel and
        // inaccessible from an excluded package.
        val effectiveResolver = if (resolverConfig.mode == com.notcvnt.rknhardering.network.DnsResolverMode.SYSTEM) {
            FALLBACK_RESOLVER_CONFIG
        } else {
            resolverConfig
        }

        val tunComparisons = fetchOsDeviceTargetComparisons(
            interfaceName = tunInterfaceName,
            dependencies = dependencies,
            resolverConfig = effectiveResolver,
            debugEnabled = debugEnabled,
            modeOverride = modeOverride,
        )

        val tunRuComparison = tunComparisons.ru
        val tunNonRuComparison = tunComparisons.nonRu

        val tunRuProbe = PerTargetProbe(
            targetHost = RU_PROBE_TARGET.displayHost,
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.RU,
            vpnIp = tunRuComparison.selectedIp,
            comparison = tunRuComparison,
            error = tunRuComparison.selectedError,
        )
        val tunNonRuProbe = PerTargetProbe(
            targetHost = NON_RU_PROBE_TARGET.displayHost,
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.NON_RU,
            vpnIp = tunNonRuComparison.selectedIp,
            comparison = tunNonRuComparison,
            error = tunNonRuComparison.selectedError,
        )

        // If no underlying interface is provided, we can only confirm tun is reachable
        // but cannot compare IPs to determine leak.
        if (underlyingInterfaceName == null) {
            val tunReachable = tunRuComparison.selectedIp != null || tunNonRuComparison.selectedIp != null
            return@coroutineScope ProbeResult(
                vpnActive = tunReachable,
                underlyingReachable = false,
                ruTarget = tunRuProbe,
                nonRuTarget = tunNonRuProbe,
                vpnError = tunRuComparison.selectedError ?: tunNonRuComparison.selectedError,
                dnsPathMismatch = tunRuComparison.dnsPathMismatch || tunNonRuComparison.dnsPathMismatch,
                activeNetworkIsVpn = activeNetworkIsVpn,
                tunProbeDiagnostics = buildTunProbeDiagnostics(
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                    activeNetworkIsVpn = activeNetworkIsVpn,
                    vpnNetworkPresent = false,
                    underlyingNetworkPresent = false,
                    vpnInterfaceName = tunInterfaceName,
                    vpnComparison = tunRuComparison,
                    underlyingInterfaceName = null,
                    underlyingComparison = null,
                ),
            )
        }

        val underlyingComparisons = fetchOsDeviceTargetComparisons(
            interfaceName = underlyingInterfaceName,
            dependencies = dependencies,
            resolverConfig = effectiveResolver,
            debugEnabled = debugEnabled,
            modeOverride = modeOverride,
        )

        val underlyingRuComparison = underlyingComparisons.ru
        val underlyingNonRuComparison = underlyingComparisons.nonRu

        val tunRuIp = tunRuComparison.selectedIp
        val tunNonRuIp = tunNonRuComparison.selectedIp
        val underlyingRuIp = underlyingRuComparison.selectedIp
        val underlyingNonRuIp = underlyingNonRuComparison.selectedIp

        val tunReachable = tunRuIp != null || tunNonRuIp != null
        val underlyingReachable = underlyingRuIp != null || underlyingNonRuIp != null

        // IPs differ between tun and underlying path → split-tunnel leak confirmed.
        val ipsDiffer = (tunRuIp != null && underlyingRuIp != null && tunRuIp != underlyingRuIp) ||
            (tunNonRuIp != null && underlyingNonRuIp != null && tunNonRuIp != underlyingNonRuIp)

        val finalRuProbe = tunRuProbe.copy(
            directIp = underlyingRuIp,
            comparison = underlyingRuComparison,
        )
        val finalNonRuProbe = tunNonRuProbe.copy(
            directIp = underlyingNonRuIp,
            comparison = underlyingNonRuComparison,
        )

        ProbeResult(
            vpnActive = tunReachable,
            underlyingReachable = underlyingReachable,
            ruTarget = finalRuProbe,
            nonRuTarget = finalNonRuProbe,
            vpnError = tunRuComparison.selectedError ?: tunNonRuComparison.selectedError,
            underlyingError = underlyingRuComparison.selectedError ?: underlyingNonRuComparison.selectedError,
            dnsPathMismatch = ipsDiffer ||
                tunRuComparison.dnsPathMismatch || tunNonRuComparison.dnsPathMismatch ||
                underlyingRuComparison.dnsPathMismatch || underlyingNonRuComparison.dnsPathMismatch,
            activeNetworkIsVpn = activeNetworkIsVpn,
            tunProbeDiagnostics = buildTunProbeDiagnostics(
                debugEnabled = debugEnabled,
                modeOverride = modeOverride,
                activeNetworkIsVpn = activeNetworkIsVpn,
                vpnNetworkPresent = false,
                underlyingNetworkPresent = underlyingReachable,
                vpnInterfaceName = tunInterfaceName,
                vpnComparison = tunRuComparison,
                underlyingInterfaceName = underlyingInterfaceName,
                underlyingComparison = underlyingRuComparison,
            ),
        )
    }

    private suspend fun fetchOsDeviceTargetComparisons(
        interfaceName: String,
        dependencies: Dependencies,
        resolverConfig: DnsResolverConfig,
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
    ): TargetComparisons = coroutineScope {
        val ruDeferred = async {
            dependencies.osDeviceComparisonFetcher(
                interfaceName,
                resolverConfig,
                debugEnabled,
                modeOverride,
                RU_PROBE_TARGET.urls,
            )
        }
        val nonRuDeferred = async {
            dependencies.osDeviceComparisonFetcher(
                interfaceName,
                resolverConfig,
                debugEnabled,
                modeOverride,
                NON_RU_PROBE_TARGET.urls,
            )
        }
        TargetComparisons(
            ru = ruDeferred.await(),
            nonRu = nonRuDeferred.await(),
        )
    }

    private suspend fun fetchTargetComparisons(
        snapshot: NetworkSnapshot,
        dependencies: Dependencies,
        resolverConfig: DnsResolverConfig,
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
    ): TargetComparisons = coroutineScope {
        val ruDeferred = async {
            dependencies.comparisonFetcher(
                snapshot,
                resolverConfig,
                debugEnabled,
                modeOverride,
                RU_PROBE_TARGET.urls,
            )
        }
        val nonRuDeferred = async {
            dependencies.comparisonFetcher(
                snapshot,
                resolverConfig,
                debugEnabled,
                modeOverride,
                NON_RU_PROBE_TARGET.urls,
            )
        }
        TargetComparisons(
            ru = ruDeferred.await(),
            nonRu = nonRuDeferred.await(),
        )
    }

    private fun buildProbeEnvironment(context: Context): ProbeEnvironment {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        // cm.allNetworks is deprecated since API 31. NetworkCallback is the
        // recommended replacement but only emits events asynchronously; this
        // prober needs a synchronous snapshot to compare VPN vs underlying
        // paths within a single probe.
        @Suppress("DEPRECATION")
        val allNetworks = cm.allNetworks
        val networks = allNetworks.mapNotNull { network ->
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
            ?.let { ResolverBinding.OsDeviceBinding(it, dnsMode = ResolverBinding.DnsMode.CONFIGURED) }

        return IfconfigClient.fetchIpViaNetworkComparison(
            primaryBinding = ResolverBinding.AndroidNetworkBinding(networkSnapshot.network),
            fallbackBinding = fallbackBinding,
            resolverConfig = resolverConfig,
            modeOverride = modeOverride,
            collectTrace = debugEnabled,
            targetUrls = targetUrls,
        )
    }

    private suspend fun fetchIpViaOsDeviceBinding(
        interfaceName: String,
        resolverConfig: DnsResolverConfig,
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
        targetUrls: List<String>? = null,
    ): PublicIpNetworkComparison {
        // OsDeviceBinding with CONFIGURED mode: DNS resolved via config (DoH/direct),
        // not the system DNS that may be unreachable inside a per-app excluded tunnel.
        val binding = ResolverBinding.OsDeviceBinding(
            interfaceName = interfaceName,
            dnsMode = ResolverBinding.DnsMode.CONFIGURED,
        )
        return IfconfigClient.fetchIpViaOsDeviceBinding(
            binding = binding,
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
