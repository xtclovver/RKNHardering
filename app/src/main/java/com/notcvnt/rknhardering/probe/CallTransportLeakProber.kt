package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.BuildConfig
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress

object CallTransportLeakProber {

    internal data class PathDescriptor(
        val path: CallTransportNetworkPath,
        val network: Network? = null,
        val interfaceName: String? = null,
        val vpnProtected: Boolean = false,
    )

    internal data class Dependencies(
        val loadCatalog: (Context, Boolean) -> CallTransportTargetCatalog.Catalog =
            CallTransportTargetCatalog::load,
        val loadPaths: (Context) -> List<PathDescriptor> = ::loadNetworkPaths,
        val stunProbe: (CallTransportTargetCatalog.CallTransportTarget, DnsResolverConfig, ResolverBinding?) -> Result<StunBindingClient.BindingResult> =
            { target, resolverConfig, binding ->
                StunBindingClient.probe(
                    host = target.host,
                    port = target.port,
                    resolverConfig = resolverConfig,
                    binding = binding,
                )
            },
        val publicIpFetcher: suspend (PathDescriptor, DnsResolverConfig) -> Result<String> =
            { path, resolverConfig ->
                when (path.path) {
                    CallTransportNetworkPath.ACTIVE -> IfconfigClient.fetchDirectIp(resolverConfig = resolverConfig)
                    CallTransportNetworkPath.UNDERLYING ->
                        if (path.network != null)
                            IfconfigClient.fetchIpViaNetwork(
                                primaryBinding = ResolverBinding.AndroidNetworkBinding(path.network),
                                fallbackBinding = path.fallbackBinding(),
                                resolverConfig = resolverConfig,
                            )
                        else
                            Result.failure(IllegalStateException("Underlying network is unavailable"))
                    CallTransportNetworkPath.LOCAL_PROXY ->
                        Result.failure(IllegalStateException("Local proxy paths do not have a bound network"))
                }
            },
        val proxyProbe: suspend (ProxyEndpoint) -> ProxyProbeOutcome = { proxyEndpoint ->
            val mtProto = MtProtoProber.probe(proxyEndpoint.host, proxyEndpoint.port)
            val proxyIp = runCatching { IfconfigClient.fetchIpViaProxy(proxyEndpoint).getOrNull() }.getOrNull()
            ProxyProbeOutcome(
                reachable = mtProto.reachable,
                targetHost = mtProto.targetAddress?.address?.hostAddress,
                targetPort = mtProto.targetAddress?.port,
                observedPublicIp = proxyIp,
            )
        },
        val proxyUdpStunProbe: suspend (ProxyEndpoint, CallTransportTargetCatalog.CallTransportTarget, DnsResolverConfig) -> Result<StunBindingClient.BindingResult> =
            { proxyEndpoint, target, resolverConfig ->
                probeProxyAssistedUdpStun(proxyEndpoint, target, resolverConfig)
            },
    )

    internal data class ProxyProbeOutcome(
        val reachable: Boolean,
        val targetHost: String? = null,
        val targetPort: Int? = null,
        val observedPublicIp: String? = null,
    )

    @Volatile
    internal var dependenciesOverride: Dependencies? = null

    suspend fun probeDirect(
        context: Context,
        resolverConfig: DnsResolverConfig,
        experimentalCallTransportEnabled: Boolean = BuildConfig.DEBUG,
        onProgress: (suspend (String, String) -> Unit)? = null,
    ): List<CallTransportLeakResult> = withContext(Dispatchers.IO) {
        val dependencies = dependenciesOverride ?: Dependencies()
        val results = mutableListOf<CallTransportLeakResult>()
        val publicIpCache = mutableMapOf<PathDescriptor, Result<String>>()

        suspend fun fetchPublicIp(path: PathDescriptor): Result<String> {
            val cached = publicIpCache[path]
            if (cached != null) {
                return cached
            }
            val value = dependencies.publicIpFetcher(path, resolverConfig)
            publicIpCache[path] = value
            return value
        }

        val catalog = runCatching {
            dependencies.loadCatalog(context, experimentalCallTransportEnabled)
        }.getOrElse { error ->
            return@withContext listOf(
                CallTransportLeakResult(
                    service = CallTransportService.TELEGRAM,
                    probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                    networkPath = CallTransportNetworkPath.ACTIVE,
                    status = CallTransportStatus.ERROR,
                    summary = "Call transport target catalog is unavailable: ${error.message ?: error::class.java.simpleName}",
                    confidence = EvidenceConfidence.LOW,
                ),
            )
        }
        val paths = runCatching { dependencies.loadPaths(context) }
            .getOrElse { error ->
                return@withContext listOf(
                    CallTransportLeakResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        networkPath = CallTransportNetworkPath.ACTIVE,
                        status = CallTransportStatus.ERROR,
                        summary = "Call transport network paths are unavailable: ${error.message ?: error::class.java.simpleName}",
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
            }

        for (path in paths) {
            val targets = catalog.telegramTargets
            if (targets.isEmpty()) {
                continue
            }

            onProgress?.invoke(
                labelForService(CallTransportService.TELEGRAM),
                labelForPath(path.path),
            )

            probeServiceTargets(
                service = CallTransportService.TELEGRAM,
                targets = targets,
                path = path,
                fetchPublicIp = { fetchPublicIp(path) },
                stunProbe = { target ->
                    dependencies.stunProbe(target, resolverConfig, path.primaryBinding())
                },
            )?.let(results::add)
        }

        if (experimentalCallTransportEnabled) {
            for (path in paths) {
                if (catalog.whatsappTargets.isEmpty()) {
                    continue
                }
                onProgress?.invoke(
                    labelForService(CallTransportService.WHATSAPP),
                    labelForPath(path.path),
                )
                probeServiceTargets(
                    service = CallTransportService.WHATSAPP,
                    targets = catalog.whatsappTargets,
                    path = path,
                    fetchPublicIp = { fetchPublicIp(path) },
                    stunProbe = { target ->
                        dependencies.stunProbe(target, resolverConfig, path.primaryBinding())
                    },
                    experimental = true,
                )?.let(results::add)
            }
        } else {
            results += CallTransportLeakResult(
                service = CallTransportService.WHATSAPP,
                probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                networkPath = CallTransportNetworkPath.ACTIVE,
                status = CallTransportStatus.UNSUPPORTED,
                summary = "WhatsApp experimental trace is disabled in release builds",
                experimental = true,
            )
        }

        results
    }

    suspend fun probeProxyAssistedTelegram(
        context: Context,
        proxyEndpoint: ProxyEndpoint,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): List<CallTransportLeakResult> = withContext(Dispatchers.IO) {
        val dependencies = dependenciesOverride ?: Dependencies()
        if (proxyEndpoint.type != ProxyType.SOCKS5) {
            return@withContext emptyList()
        }

        val results = mutableListOf<CallTransportLeakResult>()
        var cachedProxyPublicIp: String? = null
        suspend fun fetchProxyPublicIp(): String? {
            if (cachedProxyPublicIp != null) return cachedProxyPublicIp
            cachedProxyPublicIp = runCatching {
                IfconfigClient.fetchIpViaProxy(proxyEndpoint, resolverConfig = resolverConfig).getOrNull()
            }.getOrNull()
            return cachedProxyPublicIp
        }

        runCatching { dependencies.proxyProbe(proxyEndpoint) }
            .getOrNull()
            ?.takeIf { it.reachable }
            ?.let { proxyOutcome ->
                cachedProxyPublicIp = proxyOutcome.observedPublicIp ?: cachedProxyPublicIp
                results += CallTransportLeakResult(
                    service = CallTransportService.TELEGRAM,
                    probeKind = CallTransportProbeKind.PROXY_ASSISTED_TELEGRAM,
                    networkPath = CallTransportNetworkPath.LOCAL_PROXY,
                    status = CallTransportStatus.NEEDS_REVIEW,
                    targetHost = proxyOutcome.targetHost,
                    targetPort = proxyOutcome.targetPort,
                    observedPublicIp = proxyOutcome.observedPublicIp,
                    summary = buildProxySummary(
                        proxyEndpoint = proxyEndpoint,
                        targetHost = proxyOutcome.targetHost,
                        targetPort = proxyOutcome.targetPort,
                        publicIp = proxyOutcome.observedPublicIp,
                    ),
                    confidence = EvidenceConfidence.MEDIUM,
                    experimental = false,
                )
            }

        val telegramTargets = runCatching {
            dependencies.loadCatalog(context, false).telegramTargets
        }.getOrDefault(emptyList())

        probeServiceTargets(
            service = CallTransportService.TELEGRAM,
            targets = telegramTargets,
            path = PathDescriptor(path = CallTransportNetworkPath.LOCAL_PROXY),
            fetchPublicIp = {
                fetchProxyPublicIp()?.let { Result.success(it) }
                    ?: Result.failure(IllegalStateException("Proxy public IP is unavailable"))
            },
            stunProbe = { target ->
                dependencies.proxyUdpStunProbe(proxyEndpoint, target, resolverConfig)
            },
            probeKind = CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN,
        )?.let(results::add)

        results
    }

    private suspend fun probeServiceTargets(
        service: CallTransportService,
        targets: List<CallTransportTargetCatalog.CallTransportTarget>,
        path: PathDescriptor,
        fetchPublicIp: suspend () -> Result<String>,
        stunProbe: suspend (CallTransportTargetCatalog.CallTransportTarget) -> Result<StunBindingClient.BindingResult>,
        experimental: Boolean = false,
        probeKind: CallTransportProbeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
    ): CallTransportLeakResult? {
        for (target in targets) {
            val binding = stunProbe(target)
            if (binding.isSuccess) {
                val result = binding.getOrThrow()
                val publicIp = fetchPublicIp().getOrNull()
                val status = classifyDirectSignal(
                    path = path,
                    mappedIp = result.mappedIp,
                    publicIp = publicIp,
                )
                val confidence = when {
                    publicIp != null && publicIp != result.mappedIp -> EvidenceConfidence.HIGH
                    publicIp != null -> EvidenceConfidence.MEDIUM
                    else -> EvidenceConfidence.LOW
                }
                return CallTransportLeakResult(
                    service = service,
                    probeKind = probeKind,
                    networkPath = path.path,
                    status = status,
                    targetHost = target.host,
                    targetPort = target.port,
                    resolvedIps = result.resolvedIps,
                    mappedIp = result.mappedIp,
                    observedPublicIp = publicIp,
                    summary = buildDirectSummary(
                        service = service,
                        path = path.path,
                        targetHost = target.host,
                        targetPort = target.port,
                        mappedIp = result.mappedIp,
                        publicIp = publicIp,
                    ),
                    confidence = confidence,
                    experimental = experimental,
                )
            }
        }
        return null
    }

    private fun classifyDirectSignal(
        path: PathDescriptor,
        mappedIp: String,
        publicIp: String?,
    ): CallTransportStatus {
        return when (path.path) {
            CallTransportNetworkPath.UNDERLYING -> CallTransportStatus.NEEDS_REVIEW
            CallTransportNetworkPath.LOCAL_PROXY -> CallTransportStatus.NEEDS_REVIEW
            CallTransportNetworkPath.ACTIVE ->
                if (
                    path.vpnProtected &&
                    publicIp != null &&
                    sameIpFamily(publicIp, mappedIp) &&
                    publicIp != mappedIp
                ) {
                    CallTransportStatus.NEEDS_REVIEW
                } else {
                    CallTransportStatus.NO_SIGNAL
                }
        }
    }

    private fun sameIpFamily(first: String, second: String): Boolean {
        return runCatching {
            InetAddress.getByName(first)::class.java == InetAddress.getByName(second)::class.java
        }.getOrDefault(false)
    }

    private fun buildDirectSummary(
        service: CallTransportService,
        path: CallTransportNetworkPath,
        targetHost: String,
        targetPort: Int,
        mappedIp: String,
        publicIp: String?,
    ): String {
        val target = formatHostPort(targetHost, targetPort)
        val base = "${labelForService(service)} call transport via ${labelForPath(path)}: STUN endpoint $target responded"
        return if (publicIp.isNullOrBlank()) {
            "$base (mapped IP: $mappedIp)"
        } else {
            "$base (mapped IP: $mappedIp, public IP: $publicIp)"
        }
    }

    private fun buildProxySummary(
        proxyEndpoint: ProxyEndpoint,
        targetHost: String?,
        targetPort: Int?,
        publicIp: String?,
    ): String {
        val proxyLabel = formatHostPort(proxyEndpoint.host, proxyEndpoint.port)
        val targetLabel = if (!targetHost.isNullOrBlank() && targetPort != null) {
            formatHostPort(targetHost, targetPort)
        } else {
            "Telegram DC"
        }
        val base = "Telegram call transport via local SOCKS5 proxy $proxyLabel: $targetLabel is reachable"
        return if (publicIp.isNullOrBlank()) base else "$base (public IP: $publicIp)"
    }

    private suspend fun probeProxyAssistedUdpStun(
        proxyEndpoint: ProxyEndpoint,
        target: CallTransportTargetCatalog.CallTransportTarget,
        resolverConfig: DnsResolverConfig,
    ): Result<StunBindingClient.BindingResult> = withContext(Dispatchers.IO) {
        val resolvedIps = runCatching {
            ResolverNetworkStack.lookup(target.host, resolverConfig)
                .mapNotNull { it.hostAddress }
                .distinct()
        }.getOrDefault(emptyList())

        runCatching {
            Socks5UdpAssociateClient.open(
                proxyHost = proxyEndpoint.host,
                proxyPort = proxyEndpoint.port,
            ).use { session ->
                StunBindingClient.probeWithDatagramExchange(
                    host = target.host,
                    port = target.port,
                    resolvedIps = resolvedIps,
                    exchange = { payload ->
                        session.exchange(
                            targetHost = target.host,
                            targetPort = target.port,
                            payload = payload,
                        )
                    },
                ).getOrThrow()
            }
        }
    }

    private fun labelForService(service: CallTransportService): String {
        return when (service) {
            CallTransportService.TELEGRAM -> "Telegram"
            CallTransportService.WHATSAPP -> "WhatsApp"
        }
    }

    private fun labelForPath(path: CallTransportNetworkPath): String {
        return when (path) {
            CallTransportNetworkPath.ACTIVE -> "active network"
            CallTransportNetworkPath.UNDERLYING -> "underlying network"
            CallTransportNetworkPath.LOCAL_PROXY -> "local proxy"
        }
    }

    private fun formatHostPort(host: String, port: Int): String {
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }

    private fun PathDescriptor.primaryBinding(): ResolverBinding? {
        return network?.let(ResolverBinding::AndroidNetworkBinding)
    }

    private fun PathDescriptor.fallbackBinding(): ResolverBinding.OsDeviceBinding? {
        return interfaceName
            ?.takeIf { it.isNotBlank() }
            ?.let { ResolverBinding.OsDeviceBinding(it, dnsMode = ResolverBinding.DnsMode.SYSTEM) }
    }

    private fun loadNetworkPaths(context: Context): List<PathDescriptor> {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        val activeCaps = activeNetwork?.let(cm::getNetworkCapabilities)
        val vpnActive = activeCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val paths = mutableListOf(
            PathDescriptor(
                path = CallTransportNetworkPath.ACTIVE,
                vpnProtected = vpnActive,
            ),
        )
        if (!vpnActive) {
            return paths
        }

        val nonVpnNetworks = cm.allNetworks.filter { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@filter false
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
        val underlyingNetworks = if (nonVpnNetworks.size == 1) nonVpnNetworks else emptyList()
        for (underlyingNetwork in underlyingNetworks) {
            paths += PathDescriptor(
                path = CallTransportNetworkPath.UNDERLYING,
                network = underlyingNetwork,
                interfaceName = cm.getLinkProperties(underlyingNetwork)?.interfaceName,
            )
        }
        return paths
    }
}
