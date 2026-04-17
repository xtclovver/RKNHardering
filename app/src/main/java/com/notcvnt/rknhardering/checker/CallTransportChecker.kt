package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.BuildConfig
import com.notcvnt.rknhardering.rethrowIfCancellation
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer
import com.notcvnt.rknhardering.network.ResolverBinding
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import com.notcvnt.rknhardering.probe.IfconfigClient
import com.notcvnt.rknhardering.probe.LocalSocketInspector
import com.notcvnt.rknhardering.probe.LocalSocketListener
import com.notcvnt.rknhardering.probe.MtProtoProber
import com.notcvnt.rknhardering.probe.NativeCurlBridge
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyScanner
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.ScanMode
import com.notcvnt.rknhardering.probe.Socks5UdpAssociateClient
import com.notcvnt.rknhardering.probe.StunBindingClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress

object CallTransportChecker {

    internal data class PathDescriptor(
        val path: CallTransportNetworkPath,
        val network: Network? = null,
        val interfaceName: String? = null,
        val vpnProtected: Boolean = false,
    )

    data class Evaluation(
        val results: List<CallTransportLeakResult> = emptyList(),
        val findings: List<Finding> = emptyList(),
        val evidence: List<EvidenceItem> = emptyList(),
        val needsReview: Boolean = false,
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
        val findLocalProxyEndpoint: suspend () -> ProxyEndpoint? = {
            ProxyScanner().findOpenProxyEndpoint(
                mode = ScanMode.POPULAR_ONLY,
                manualPort = null,
                onProgress = { _ -> },
                preferredType = ProxyType.SOCKS5,
            )
        },
        val proxyProbe: suspend (ProxyEndpoint) -> ProxyProbeOutcome = { proxyEndpoint ->
            val mtProto = MtProtoProber.probe(proxyEndpoint.host, proxyEndpoint.port)
            val proxyIp = cancellationAwareRunCatching {
                IfconfigClient.fetchIpViaProxy(proxyEndpoint).getOrNull()
            }.getOrNull()
            ProxyProbeOutcome(
                reachable = mtProto.reachable,
                targetHost = mtProto.targetAddress?.address?.hostAddress,
                targetPort = mtProto.targetAddress?.port,
                observedPublicIp = proxyIp,
            )
        },
        val proxyUdpStunProbe: suspend (Context, ProxyEndpoint, CallTransportTargetCatalog.CallTransportTarget, DnsResolverConfig) -> Result<StunBindingClient.BindingResult> =
            { context, proxyEndpoint, target, resolverConfig ->
                probeProxyAssistedUdpStun(context, proxyEndpoint, target, resolverConfig)
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

    suspend fun check(
        context: Context,
        resolverConfig: DnsResolverConfig,
        callTransportEnabled: Boolean,
        experimentalCallTransportEnabled: Boolean = BuildConfig.DEBUG,
        onProgress: (suspend (String, String) -> Unit)? = null,
    ): Evaluation = withContext(Dispatchers.IO) {
        if (!callTransportEnabled) {
            return@withContext Evaluation()
        }
        NativeCurlBridge.initIfNeeded(context)

        val dependencies = dependenciesOverride ?: Dependencies()
        val results = mutableListOf<CallTransportLeakResult>()
        results += probeDirect(
            context = context,
            resolverConfig = resolverConfig,
            experimentalCallTransportEnabled = experimentalCallTransportEnabled,
            onProgress = onProgress,
        )

        val proxyEndpoint = cancellationAwareRunCatchingSuspend { dependencies.findLocalProxyEndpoint() }.getOrNull()
        if (proxyEndpoint?.type == ProxyType.SOCKS5) {
            onProgress?.invoke(labelForService(CallTransportService.TELEGRAM), labelForPath(CallTransportNetworkPath.LOCAL_PROXY))
            results += probeProxyAssistedTelegram(
                context = context,
                proxyEndpoint = proxyEndpoint,
                resolverConfig = resolverConfig,
            )
        }

        val deduplicated = deduplicate(results)
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        reportResults(deduplicated, findings, evidence)

        Evaluation(
            results = deduplicated,
            findings = findings,
            evidence = evidence,
            needsReview = deduplicated.any { it.status == CallTransportStatus.NEEDS_REVIEW },
        )
    }

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

        val catalog = cancellationAwareRunCatching {
            dependencies.loadCatalog(context, experimentalCallTransportEnabled)
        }.getOrElse { error ->
            return@withContext listOf(
                errorResult(
                    service = CallTransportService.TELEGRAM,
                    probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                    path = CallTransportNetworkPath.ACTIVE,
                    summary = "Telegram call transport target catalog is unavailable: ${error.message ?: error::class.java.simpleName}",
                ),
                if (experimentalCallTransportEnabled)
                    errorResult(
                        service = CallTransportService.WHATSAPP,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        path = CallTransportNetworkPath.ACTIVE,
                        summary = "WhatsApp call transport target catalog is unavailable: ${error.message ?: error::class.java.simpleName}",
                        experimental = true,
                    )
                else
                    unsupportedResult(
                        service = CallTransportService.WHATSAPP,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        path = CallTransportNetworkPath.ACTIVE,
                        summary = "WhatsApp experimental trace is disabled in release builds",
                        experimental = true,
                    ),
            )
        }
        val paths = cancellationAwareRunCatching { dependencies.loadPaths(context) }
            .getOrElse { error ->
                return@withContext listOf(
                    errorResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        path = CallTransportNetworkPath.ACTIVE,
                        summary = "Call transport network paths are unavailable: ${error.message ?: error::class.java.simpleName}",
                    ),
                    if (experimentalCallTransportEnabled)
                        errorResult(
                            service = CallTransportService.WHATSAPP,
                            probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                            path = CallTransportNetworkPath.ACTIVE,
                            summary = "Call transport network paths are unavailable: ${error.message ?: error::class.java.simpleName}",
                            experimental = true,
                        )
                    else
                        unsupportedResult(
                            service = CallTransportService.WHATSAPP,
                            probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                            path = CallTransportNetworkPath.ACTIVE,
                            summary = "WhatsApp experimental trace is disabled in release builds",
                            experimental = true,
                        ),
                )
            }

        if (catalog.telegramTargets.isEmpty()) {
            results += unsupportedResult(
                service = CallTransportService.TELEGRAM,
                probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                path = CallTransportNetworkPath.ACTIVE,
                summary = "Telegram call transport targets are unavailable",
            )
        } else {
            for (path in paths) {
                onProgress?.invoke(labelForService(CallTransportService.TELEGRAM), labelForPath(path.path))
                results += probeServiceTargets(
                    service = CallTransportService.TELEGRAM,
                    targets = catalog.telegramTargets,
                    path = path,
                    fetchPublicIp = { fetchPublicIp(path) },
                    stunProbe = { target ->
                        probeStunWithFallback(dependencies, target, resolverConfig, path)
                    },
                )
            }
        }

        if (experimentalCallTransportEnabled) {
            if (catalog.whatsappTargets.isEmpty()) {
                results += unsupportedResult(
                    service = CallTransportService.WHATSAPP,
                    probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                    path = CallTransportNetworkPath.ACTIVE,
                    summary = "WhatsApp experimental call transport targets are unavailable",
                    experimental = true,
                )
            } else {
                for (path in paths) {
                    onProgress?.invoke(labelForService(CallTransportService.WHATSAPP), labelForPath(path.path))
                    results += probeServiceTargets(
                        service = CallTransportService.WHATSAPP,
                        targets = catalog.whatsappTargets,
                        path = path,
                        fetchPublicIp = { fetchPublicIp(path) },
                        stunProbe = { target ->
                            probeStunWithFallback(dependencies, target, resolverConfig, path)
                        },
                        experimental = true,
                    )
                }
            }
        } else {
            results += unsupportedResult(
                service = CallTransportService.WHATSAPP,
                probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                path = CallTransportNetworkPath.ACTIVE,
                summary = "WhatsApp experimental trace is disabled in release builds",
                experimental = true,
            )
        }

        deduplicate(results)
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
            cachedProxyPublicIp = cancellationAwareRunCatchingSuspend {
                IfconfigClient.fetchIpViaProxy(proxyEndpoint, resolverConfig = resolverConfig).getOrNull()
            }.getOrNull()
            return cachedProxyPublicIp
        }

        val proxyLabel = formatHostPort(proxyEndpoint.host, proxyEndpoint.port)
        val proxyOutcome = cancellationAwareRunCatchingSuspend { dependencies.proxyProbe(proxyEndpoint) }.getOrNull()
        if (proxyOutcome?.reachable == true) {
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
            )
        } else if (proxyOutcome != null) {
            results += CallTransportLeakResult(
                service = CallTransportService.TELEGRAM,
                probeKind = CallTransportProbeKind.PROXY_ASSISTED_TELEGRAM,
                networkPath = CallTransportNetworkPath.LOCAL_PROXY,
                status = CallTransportStatus.NO_SIGNAL,
                summary = "Telegram call transport via local SOCKS5 proxy $proxyLabel did not expose a reachable Telegram DC",
            )
        }

        val telegramTargets = cancellationAwareRunCatching {
            dependencies.loadCatalog(context, false).telegramTargets
        }.getOrElse { error ->
            return@withContext results + errorResult(
                service = CallTransportService.TELEGRAM,
                probeKind = CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN,
                path = CallTransportNetworkPath.LOCAL_PROXY,
                summary = "Telegram call transport target catalog is unavailable: ${error.message ?: error::class.java.simpleName}",
            )
        }

        results += probeServiceTargets(
            service = CallTransportService.TELEGRAM,
            targets = telegramTargets,
            path = PathDescriptor(path = CallTransportNetworkPath.LOCAL_PROXY),
            fetchPublicIp = {
                fetchProxyPublicIp()?.let { Result.success(it) }
                    ?: Result.failure(IllegalStateException("Proxy public IP is unavailable"))
            },
            stunProbe = { target ->
                dependencies.proxyUdpStunProbe(context, proxyEndpoint, target, resolverConfig)
            },
            probeKind = CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN,
        )

        deduplicate(results)
    }

    private suspend fun probeServiceTargets(
        service: CallTransportService,
        targets: List<CallTransportTargetCatalog.CallTransportTarget>,
        path: PathDescriptor,
        fetchPublicIp: suspend () -> Result<String>,
        stunProbe: suspend (CallTransportTargetCatalog.CallTransportTarget) -> Result<StunBindingClient.BindingResult>,
        experimental: Boolean = false,
        probeKind: CallTransportProbeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
    ): CallTransportLeakResult {
        if (targets.isEmpty()) {
            return unsupportedResult(
                service = service,
                probeKind = probeKind,
                path = path.path,
                summary = "${labelForService(service)} call transport targets are unavailable",
                experimental = experimental,
            )
        }

        var lastError: Throwable? = null
        for (target in targets) {
            val binding = stunProbe(target)
            if (binding.isSuccess) {
                val result = binding.getOrThrow()
                val publicIp = fetchPublicIp().getOrNull()
                val status = classifySignal(
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
            lastError = binding.exceptionOrNull()
        }

        return CallTransportLeakResult(
            service = service,
            probeKind = probeKind,
            networkPath = path.path,
            status = CallTransportStatus.NO_SIGNAL,
            targetHost = targets.firstOrNull()?.host,
            targetPort = targets.firstOrNull()?.port,
            summary = buildNoSignalSummary(
                service = service,
                path = path.path,
                probeKind = probeKind,
                lastError = lastError,
            ),
            experimental = experimental,
        )
    }

    private suspend fun probeStunWithFallback(
        dependencies: Dependencies,
        target: CallTransportTargetCatalog.CallTransportTarget,
        resolverConfig: DnsResolverConfig,
        path: PathDescriptor,
    ): Result<StunBindingClient.BindingResult> {
        var lastError: Throwable? = null
        for (binding in path.stunBindings()) {
            val result = dependencies.stunProbe(target, resolverConfig, binding)
            if (result.isSuccess) {
                return result
            }
            lastError = result.exceptionOrNull() ?: lastError
        }
        return Result.failure(lastError ?: IllegalStateException("Call transport STUN probe failed"))
    }

    private fun classifySignal(
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
                    CallTransportStatus.BASELINE
                }
        }
    }

    private fun sameIpFamily(first: String, second: String): Boolean {
        return cancellationAwareRunCatching {
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

    private fun buildNoSignalSummary(
        service: CallTransportService,
        path: CallTransportNetworkPath,
        probeKind: CallTransportProbeKind,
        lastError: Throwable?,
    ): String {
        val suffix = lastError?.message?.takeIf { it.isNotBlank() }?.let { ": $it" }.orEmpty()
        return when (probeKind) {
            CallTransportProbeKind.PROXY_ASSISTED_TELEGRAM ->
                "${labelForService(service)} call transport via ${labelForPath(path)} did not expose a reachable Telegram DC$suffix"
            CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN,
            CallTransportProbeKind.DIRECT_UDP_STUN,
            -> "${labelForService(service)} call transport via ${labelForPath(path)} did not receive a STUN response$suffix"
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
        context: Context,
        proxyEndpoint: ProxyEndpoint,
        target: CallTransportTargetCatalog.CallTransportTarget,
        resolverConfig: DnsResolverConfig,
    ): Result<StunBindingClient.BindingResult> = withContext(Dispatchers.IO) {
        val resolvedIps = cancellationAwareRunCatching {
            ResolverNetworkStack.lookup(
                hostname = target.host,
                config = resolverConfig,
                cancellationSignal = com.notcvnt.rknhardering.ScanExecutionContext.currentOrDefault().cancellationSignal,
            )
                .mapNotNull { it.hostAddress }
                .distinct()
        }.getOrDefault(emptyList())

        cancellationAwareRunCatching {
            try {
                Socks5UdpAssociateClient.open(
                    proxyHost = proxyEndpoint.host,
                    proxyPort = proxyEndpoint.port,
                ).use { session ->
                    probeProxyUdpSession(session, target, resolvedIps)
                }
            } catch (error: Socks5UdpAssociateClient.AuthenticationRequiredException) {
                val listeners = LocalSocketInspector.collect(
                    context,
                    protocols = setOf("tcp", "tcp6", "udp", "udp6"),
                )
                var lastError: Throwable = error
                for (relay in findReusableProxyUdpRelays(proxyEndpoint, listeners)) {
                    val candidateResult = cancellationAwareRunCatching {
                        Socks5UdpAssociateClient.openRelay(
                            relayHost = relay.relayHost,
                            relayPort = relay.relayPort,
                        ).use { session ->
                            probeProxyUdpSession(session, target, resolvedIps)
                        }
                    }
                    if (candidateResult.isSuccess) {
                        return@cancellationAwareRunCatching candidateResult.getOrThrow()
                    }
                    lastError = candidateResult.exceptionOrNull() ?: lastError
                }
                throw lastError
            }
        }
    }

    private fun probeProxyUdpSession(
        session: Socks5UdpAssociateClient.Session,
        target: CallTransportTargetCatalog.CallTransportTarget,
        resolvedIps: List<String>,
    ): StunBindingClient.BindingResult {
        val executionContext = com.notcvnt.rknhardering.ScanExecutionContext.currentOrDefault()
        return StunBindingClient.probeWithDatagramExchange(
            host = target.host,
            port = target.port,
            resolvedIps = resolvedIps,
            executionContext = executionContext,
            exchange = { payload ->
                session.exchange(
                    targetHost = target.host,
                    targetPort = target.port,
                    payload = payload,
                    executionContext = executionContext,
                )
            },
        ).getOrThrow()
    }

    internal fun findReusableProxyUdpRelays(
        proxyEndpoint: ProxyEndpoint,
        listeners: List<LocalSocketListener>,
    ): List<Socks5UdpAssociateClient.SessionInfo> {
        val tcpListeners = listeners.filter { it.protocol.startsWith("tcp") }
        val proxyOwner = BypassChecker.matchProxyOwner(proxyEndpoint, tcpListeners).owner ?: return emptyList()
        return listeners
            .asSequence()
            .filter { it.protocol.startsWith("udp") }
            .filter { it.uid == proxyOwner.uid }
            .filter { it.port != proxyEndpoint.port }
            .filter { isReusableProxyRelayHost(it.host) }
            .sortedWith(
                compareByDescending<LocalSocketListener> {
                    normalizeLocalRelayHost(it.host) == normalizeLocalRelayHost(proxyEndpoint.host)
                }.thenByDescending { it.port },
            )
            .map { listener ->
                Socks5UdpAssociateClient.SessionInfo(
                    relayHost = reusableRelayHost(listener.host, proxyEndpoint.host),
                    relayPort = listener.port,
                )
            }
            .distinct()
            .toList()
    }

    private fun reusableRelayHost(listenerHost: String, proxyHost: String): String {
        return if (isWildcardLocalRelayHost(listenerHost)) proxyHost else listenerHost
    }

    private fun isReusableProxyRelayHost(host: String): Boolean {
        return isWildcardLocalRelayHost(host) || cancellationAwareRunCatching {
            java.net.InetAddress.getByName(normalizeLocalRelayHost(host)).isLoopbackAddress
        }.getOrDefault(false)
    }

    private inline fun <T> cancellationAwareRunCatching(block: () -> T): Result<T> {
        return runCatching(block).onFailure { error ->
            if (error is Exception) {
                rethrowIfCancellation(error)
            }
        }
    }

    private suspend inline fun <T> cancellationAwareRunCatchingSuspend(crossinline block: suspend () -> T): Result<T> {
        return runCatching { block() }.onFailure { error ->
            if (error is Exception) {
                rethrowIfCancellation(error)
            }
        }
    }

    private fun isWildcardLocalRelayHost(host: String): Boolean {
        return normalizeLocalRelayHost(host) in setOf("0.0.0.0", "::", "0:0:0:0:0:0:0:0", ":::")
    }

    private fun normalizeLocalRelayHost(host: String): String = host.substringBefore('%').lowercase()

    private fun deduplicate(results: List<CallTransportLeakResult>): List<CallTransportLeakResult> {
        data class Key(
            val service: CallTransportService,
            val probeKind: CallTransportProbeKind,
            val networkPath: CallTransportNetworkPath,
            val targetHost: String?,
            val targetPort: Int?,
            val mappedIp: String?,
            val observedPublicIp: String?,
        )

        val deduplicated = linkedMapOf<Key, CallTransportLeakResult>()
        for (result in results) {
            val key = Key(
                service = result.service,
                probeKind = result.probeKind,
                networkPath = result.networkPath,
                targetHost = result.targetHost,
                targetPort = result.targetPort,
                mappedIp = result.mappedIp,
                observedPublicIp = result.observedPublicIp,
            )
            val existing = deduplicated[key]
            if (existing == null || statusPriority(result.status) > statusPriority(existing.status)) {
                deduplicated[key] = result
            }
        }
        return deduplicated.values.toList()
    }

    private fun statusPriority(status: CallTransportStatus): Int {
        return when (status) {
            CallTransportStatus.NEEDS_REVIEW -> 4
            CallTransportStatus.ERROR -> 3
            CallTransportStatus.BASELINE -> 2
            CallTransportStatus.NO_SIGNAL -> 1
            CallTransportStatus.UNSUPPORTED -> 0
        }
    }

    private fun reportResults(
        results: List<CallTransportLeakResult>,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ) {
        for (result in results) {
            when (result.status) {
                CallTransportStatus.NEEDS_REVIEW -> {
                    findings += Finding(
                        description = result.summary,
                        needsReview = true,
                        source = result.service.toEvidenceSource(),
                        confidence = result.confidence ?: EvidenceConfidence.MEDIUM,
                    )
                    evidence += EvidenceItem(
                        source = result.service.toEvidenceSource(),
                        detected = true,
                        confidence = result.confidence ?: EvidenceConfidence.MEDIUM,
                        description = result.summary,
                        family = result.service.name,
                    )
                }
                CallTransportStatus.ERROR -> {
                    findings += Finding(
                        description = result.summary,
                        isError = true,
                        source = result.service.toEvidenceSource(),
                        confidence = result.confidence,
                    )
                }
                CallTransportStatus.BASELINE,
                CallTransportStatus.NO_SIGNAL,
                CallTransportStatus.UNSUPPORTED,
                -> Unit
            }
        }
    }

    private fun errorResult(
        service: CallTransportService,
        probeKind: CallTransportProbeKind,
        path: CallTransportNetworkPath,
        summary: String,
        experimental: Boolean = false,
    ): CallTransportLeakResult {
        return CallTransportLeakResult(
            service = service,
            probeKind = probeKind,
            networkPath = path,
            status = CallTransportStatus.ERROR,
            summary = summary,
            confidence = EvidenceConfidence.LOW,
            experimental = experimental,
        )
    }

    private fun unsupportedResult(
        service: CallTransportService,
        probeKind: CallTransportProbeKind,
        path: CallTransportNetworkPath,
        summary: String,
        experimental: Boolean = false,
    ): CallTransportLeakResult {
        return CallTransportLeakResult(
            service = service,
            probeKind = probeKind,
            networkPath = path,
            status = CallTransportStatus.UNSUPPORTED,
            summary = summary,
            experimental = experimental,
        )
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

    private fun PathDescriptor.stunBindings(): List<ResolverBinding?> {
        val bindings = mutableListOf<ResolverBinding?>(primaryBinding())
        val fallbackBinding = fallbackBinding()
        if (fallbackBinding != null && fallbackBinding !in bindings) {
            bindings += fallbackBinding
        }
        return bindings
    }

    private fun PathDescriptor.fallbackBinding(): ResolverBinding.OsDeviceBinding? {
        return NetworkInterfaceNameNormalizer.canonicalName(interfaceName)
            ?.takeIf { it.isNotBlank() }
            ?.let { ResolverBinding.OsDeviceBinding(it, dnsMode = ResolverBinding.DnsMode.SYSTEM) }
    }

    @Suppress("DEPRECATION")
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
        for (underlyingNetwork in nonVpnNetworks.distinctBy { it.toString() }) {
            paths += PathDescriptor(
                path = CallTransportNetworkPath.UNDERLYING,
                network = underlyingNetwork,
                interfaceName = NetworkInterfaceNameNormalizer.canonicalName(
                    cm.getLinkProperties(underlyingNetwork)?.interfaceName,
                ),
            )
        }
        return paths
    }

    private fun CallTransportService.toEvidenceSource(): EvidenceSource {
        return when (this) {
            CallTransportService.TELEGRAM -> EvidenceSource.TELEGRAM_CALL_TRANSPORT
            CallTransportService.WHATSAPP -> EvidenceSource.WHATSAPP_CALL_TRANSPORT
        }
    }
}
