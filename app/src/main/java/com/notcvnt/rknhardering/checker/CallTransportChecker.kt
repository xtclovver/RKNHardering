package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.StunProbeGroupResult
import com.notcvnt.rknhardering.model.StunProbeResult
import com.notcvnt.rknhardering.customcheck.CallTransportConfig
import com.notcvnt.rknhardering.model.StunScope
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
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import java.util.Collections

object CallTransportChecker {
    private const val STUN_HTTP_TIMEOUT_MS = 4_000
    private const val STUN_HTTP_OKHTTP_RETRY_COUNT = 0
    private const val STUN_HTTP_NATIVE_CURL_RETRY_COUNT = 0
    private const val STUN_SWEEP_MAX_CONCURRENCY = 8
    private const val STUN_SERVICE_MAX_CONCURRENCY = 6
    private const val STUN_PRIORITY_BATCH_SIZE = 8

    private val PREFERRED_STUN_HOSTS = listOf(
        "stun.fitauto.ru",
        "stun.sberbank.ru",
        "stun.l.google.com",
        "stun1.l.google.com",
        "stun2.l.google.com",
        "stun3.l.google.com",
        "stun4.l.google.com",
        "stun.cloudflare.com",
        "global.stun.twilio.com",
        "stun.nextcloud.com",
    )

    internal data class PathDescriptor(
        val path: CallTransportNetworkPath,
        val network: Network? = null,
        val interfaceName: String? = null,
        val vpnProtected: Boolean = false,
    )

    internal data class Evaluation(
        val results: List<CallTransportLeakResult> = emptyList(),
        val stunGroups: List<StunProbeGroupResult> = emptyList(),
        val findings: List<Finding> = emptyList(),
        val evidence: List<EvidenceItem> = emptyList(),
        val needsReview: Boolean = false,
        val diagnostics: CallTransportPerformanceDiagnostics? = null,
    )

    private data class StunSweepResult(
        val groups: List<StunProbeGroupResult>,
        val scopeTimings: List<StunScopeTiming>,
        val error: CallTransportLeakResult? = null,
    )

    internal data class Dependencies(
        val loadCatalog: (Context) -> CallTransportTargetCatalog.Catalog =
            { ctx -> CallTransportTargetCatalog.load(ctx) },
        val loadPaths: (Context) -> List<PathDescriptor> = ::loadNetworkPaths,
        val stunDualStackProbe: (CallTransportTargetCatalog.StunTarget, DnsResolverConfig, ResolverBinding?) -> StunBindingClient.DualStackBindingResult =
            { target, resolverConfig, binding ->
                StunBindingClient.probeDualStack(
                    host = target.host,
                    port = target.port,
                    resolverConfig = resolverConfig,
                    binding = binding,
                )
            },
        val publicIpFetcher: suspend (PathDescriptor, DnsResolverConfig, Int) -> Result<String> =
            { path, resolverConfig, timeoutMs ->
                when (path.path) {
                    CallTransportNetworkPath.ACTIVE ->
                        IfconfigClient.fetchDirectIp(
                            timeoutMs = timeoutMs,
                            resolverConfig = resolverConfig,
                            okHttpRetryCount = STUN_HTTP_OKHTTP_RETRY_COUNT,
                            nativeCurlRetryCount = STUN_HTTP_NATIVE_CURL_RETRY_COUNT,
                        )
                    CallTransportNetworkPath.UNDERLYING ->
                        if (path.network != null)
                            IfconfigClient.fetchIpViaNetwork(
                                primaryBinding = ResolverBinding.AndroidNetworkBinding(path.network),
                                fallbackBinding = path.fallbackBinding(),
                                timeoutMs = timeoutMs,
                                resolverConfig = resolverConfig,
                                okHttpRetryCount = STUN_HTTP_OKHTTP_RETRY_COUNT,
                                nativeCurlRetryCount = STUN_HTTP_NATIVE_CURL_RETRY_COUNT,
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
        val proxyUdpStunProbe: suspend (Context, ProxyEndpoint, CallTransportTargetCatalog.StunTarget, DnsResolverConfig) -> Result<StunBindingClient.BindingResult> =
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

    internal suspend fun check(
        context: Context,
        resolverConfig: DnsResolverConfig,
        callTransportEnabled: Boolean,
        onProgress: (suspend (String, String) -> Unit)? = null,
        config: CallTransportConfig = CallTransportConfig(enabled = false),
    ): Evaluation = withContext(Dispatchers.IO) {
        if (!callTransportEnabled) {
            return@withContext Evaluation()
        }
        NativeCurlBridge.initIfNeeded(context)

        val dependencies = dependenciesOverride ?: Dependencies()
        val startedAtMs = IndirectCheckPerformanceSupport.monotonicNowMs()
        val stepTimings = Collections.synchronizedList(mutableListOf<DebugStepTiming>())

        val results = mutableListOf<CallTransportLeakResult>()
        val proxyEndpointDeferred = async {
            IndirectCheckPerformanceSupport.measureSuspendStep("findLocalProxyEndpoint", stepTimings) {
                cancellationAwareRunCatchingSuspend { dependencies.findLocalProxyEndpoint() }.getOrNull()
            }
        }
        val stunSweepDeferred = async {
            IndirectCheckPerformanceSupport.measureSuspendStep("probeStunTargets", stepTimings) {
                probeStunTargetsDetailed(
                    context = context,
                    resolverConfig = resolverConfig,
                    onProgress = onProgress,
                    config = config,
                )
            }
        }
        val effectiveTimeoutMs = config.timeoutMs.coerceAtLeast(1)
        val directDeferred = async {
            IndirectCheckPerformanceSupport.measureSuspendStep("probeDirect", stepTimings) {
                probeDirect(
                    context = context,
                    resolverConfig = resolverConfig,
                    onProgress = onProgress,
                    activeStunGroupsProvider = { stunSweepDeferred.await().groups },
                    timeoutMs = effectiveTimeoutMs,
                )
            }
        }

        val proxyAssistedDeferred = async {
            if (!config.checkMtproto) {
                IndirectCheckPerformanceSupport.markSkippedStep("probeProxyAssistedTelegram", stepTimings)
                return@async emptyList()
            }
            val proxyEndpoint = proxyEndpointDeferred.await()
            if (proxyEndpoint?.type != ProxyType.SOCKS5) {
                IndirectCheckPerformanceSupport.markSkippedStep("probeProxyAssistedTelegram", stepTimings)
                return@async emptyList()
            }

            onProgress?.invoke("Telegram", labelForPath(CallTransportNetworkPath.LOCAL_PROXY))
            IndirectCheckPerformanceSupport.measureSuspendStep("probeProxyAssistedTelegram", stepTimings) {
                probeProxyAssistedTelegram(
                    context = context,
                    proxyEndpoint = proxyEndpoint,
                    resolverConfig = resolverConfig,
                    timeoutMs = effectiveTimeoutMs,
                )
            }
        }

        results += directDeferred.await()
        results += proxyAssistedDeferred.await()

        val stunSweep = stunSweepDeferred.await()
        stunSweep.error?.let(results::add)
        val stunGroups = stunSweep.groups

        val deduplicated = deduplicate(results)
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        reportResults(deduplicated, findings, evidence)

        Evaluation(
            results = deduplicated,
            stunGroups = stunGroups,
            findings = findings,
            evidence = evidence,
            needsReview = deduplicated.any { it.status == CallTransportStatus.NEEDS_REVIEW },
            diagnostics = CallTransportPerformanceDiagnostics(
                totalDurationMs = IndirectCheckPerformanceSupport.elapsedSince(startedAtMs),
                steps = stepTimings.toList(),
                stunScopeTimings = stunSweep.scopeTimings,
            ),
        )
    }

    suspend fun probeStunTargets(
        context: Context,
        resolverConfig: DnsResolverConfig,
        onProgress: (suspend (String, String) -> Unit)? = null,
    ): List<StunProbeGroupResult> = withContext(Dispatchers.IO) {
        probeStunTargetsDetailed(
            context = context,
            resolverConfig = resolverConfig,
            onProgress = onProgress,
        ).groups
    }

    private suspend fun probeStunTargetsDetailed(
        context: Context,
        resolverConfig: DnsResolverConfig,
        onProgress: (suspend (String, String) -> Unit)? = null,
        config: CallTransportConfig = CallTransportConfig(enabled = false),
    ): StunSweepResult = withContext(Dispatchers.IO) {
        val dependencies = dependenciesOverride ?: Dependencies()
        val rawCatalog = cancellationAwareRunCatching { dependencies.loadCatalog(context) }
            .getOrElse { error ->
                return@withContext StunSweepResult(
                    groups = emptyList(),
                    scopeTimings = emptyList(),
                    error = errorResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        path = CallTransportNetworkPath.ACTIVE,
                        summary = "STUN target catalog is unavailable: ${error.message ?: error::class.java.simpleName}",
                    ),
                )
            }
        val filteredBuiltin = rawCatalog.stunTargets.filter { target ->
            when (target.scope) {
                StunScope.GLOBAL -> config.builtinGlobalStunEnabled
                StunScope.RU -> config.builtinRuStunEnabled
            }
        }
        val customTargets = config.customStunServers
            .filter { it.host.isNotBlank() }
            .map { custom ->
                CallTransportTargetCatalog.StunTarget(
                    host = custom.host,
                    port = custom.port,
                    scope = StunScope.GLOBAL,
                    enabled = true,
                )
            }
        val catalog = CallTransportTargetCatalog.Catalog(stunTargets = filteredBuiltin + customTargets)

        val paths = cancellationAwareRunCatching { dependencies.loadPaths(context) }
            .getOrElse { error ->
                return@withContext StunSweepResult(
                    groups = emptyList(),
                    scopeTimings = emptyList(),
                    error = errorResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        path = CallTransportNetworkPath.ACTIVE,
                        summary = "Call transport network paths are unavailable: ${error.message ?: error::class.java.simpleName}",
                    ),
                )
            }

        val activePath = paths.firstOrNull { it.path == CallTransportNetworkPath.ACTIVE }
            ?: return@withContext StunSweepResult(emptyList(), emptyList())

        val binding = activePath.primaryBinding()
        val groupResults = supervisorScope {
            StunScope.entries.map { scope ->
                async {
                    val startedAtMs = IndirectCheckPerformanceSupport.monotonicNowMs()
                    val targets = catalog.stunTargets.filter { it.scope == scope }
                    onProgress?.invoke("STUN ${scope.name}", labelForPath(CallTransportNetworkPath.ACTIVE))
                    val probeResults = probeScopeTargetsConcurrently(
                        scope = scope,
                        targets = targets,
                        resolverConfig = resolverConfig,
                        binding = binding,
                        dependencies = dependencies,
                    )
                    val group = StunProbeGroupResult(scope = scope, results = probeResults)
                    val timing = StunScopeTiming(
                        scope = scope,
                        durationMs = IndirectCheckPerformanceSupport.elapsedSince(startedAtMs),
                        targetCount = targets.size,
                        respondedCount = group.respondedCount,
                        noResponseCount = group.totalCount - group.respondedCount,
                    )
                    group to timing
                }
            }.awaitAll()
        }

        StunSweepResult(
            groups = groupResults.map { it.first },
            scopeTimings = groupResults.map { it.second },
        )
    }

    suspend fun probeDirect(
        context: Context,
        resolverConfig: DnsResolverConfig,
        onProgress: (suspend (String, String) -> Unit)? = null,
        activeStunGroupsProvider: (suspend () -> List<StunProbeGroupResult>)? = null,
        timeoutMs: Int = STUN_HTTP_TIMEOUT_MS,
    ): List<CallTransportLeakResult> = withContext(Dispatchers.IO) {
        val dependencies = dependenciesOverride ?: Dependencies()
        val paths = cancellationAwareRunCatching { dependencies.loadPaths(context) }
            .getOrElse { error ->
                return@withContext listOf(
                    errorResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        path = CallTransportNetworkPath.ACTIVE,
                        summary = "Call transport network paths are unavailable: ${error.message ?: error::class.java.simpleName}",
                    ),
                )
            }
        val catalog = cancellationAwareRunCatching { dependencies.loadCatalog(context) }
            .getOrElse { error ->
                return@withContext listOf(
                    errorResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        path = CallTransportNetworkPath.ACTIVE,
                        summary = "STUN target catalog is unavailable: ${error.message ?: error::class.java.simpleName}",
                    ),
                )
            }

        val results = supervisorScope {
            paths.map { path ->
                async {
                    onProgress?.invoke("Telegram", labelForPath(path.path))
                    val reusedSweepResult = if (path.path == CallTransportNetworkPath.ACTIVE) {
                        activeStunGroupsProvider
                            ?.invoke()
                            ?.let { sweepGroups ->
                                buildDirectResultFromSweep(
                                    targets = catalog.stunTargets,
                                    path = path,
                                    sweepGroups = sweepGroups,
                                    fetchPublicIp = { dependencies.publicIpFetcher(path, resolverConfig, timeoutMs) },
                                )
                            }
                    } else {
                        null
                    }
                    if (reusedSweepResult != null) {
                        return@async reusedSweepResult
                    }
                    probeStunServiceTargets(
                        targets = catalog.stunTargets,
                        path = path,
                        fetchPublicIp = { dependencies.publicIpFetcher(path, resolverConfig, timeoutMs) },
                        stunProbe = { target ->
                            preferSuccessfulBinding(
                                dependencies.stunDualStackProbe(
                                    target,
                                    resolverConfig,
                                    path.primaryBinding(),
                                ),
                            )
                        },
                    )
                }
            }.awaitAll()
        }

        deduplicate(results)
    }

    suspend fun probeProxyAssistedTelegram(
        context: Context,
        proxyEndpoint: ProxyEndpoint,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        timeoutMs: Int = STUN_HTTP_TIMEOUT_MS,
    ): List<CallTransportLeakResult> = withContext(Dispatchers.IO) {
        val dependencies = dependenciesOverride ?: Dependencies()
        if (proxyEndpoint.type != ProxyType.SOCKS5) {
            return@withContext emptyList()
        }

        val results = mutableListOf<CallTransportLeakResult>()
        val proxyPublicIpDeferred = async(start = CoroutineStart.LAZY) {
            cancellationAwareRunCatchingSuspend {
                IfconfigClient.fetchIpViaProxy(
                    endpoint = proxyEndpoint,
                    timeoutMs = timeoutMs,
                    resolverConfig = resolverConfig,
                    okHttpRetryCount = STUN_HTTP_OKHTTP_RETRY_COUNT,
                    nativeCurlRetryCount = STUN_HTTP_NATIVE_CURL_RETRY_COUNT,
                ).getOrNull()
            }.getOrNull()
        }
        val proxyOutcomeDeferred = async {
            cancellationAwareRunCatchingSuspend { dependencies.proxyProbe(proxyEndpoint) }.getOrNull()
        }
        try {
            suspend fun fetchProxyPublicIp(): String? {
                if (proxyOutcomeDeferred.isCompleted) {
                    proxyOutcomeDeferred.await()?.observedPublicIp?.let { return it }
                }
                return proxyPublicIpDeferred.await()
            }
            val proxyLabel = formatHostPort(proxyEndpoint.host, proxyEndpoint.port)
            val udpStunDeferred = async {
                val catalog = cancellationAwareRunCatching { dependencies.loadCatalog(context) }
                    .getOrElse { error ->
                        return@async errorResult(
                            service = CallTransportService.TELEGRAM,
                            probeKind = CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN,
                            path = CallTransportNetworkPath.LOCAL_PROXY,
                            summary = "STUN target catalog is unavailable: ${error.message ?: error::class.java.simpleName}",
                        )
                    }

                probeStunServiceTargets(
                    targets = catalog.stunTargets,
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
            }

            val proxyOutcome = proxyOutcomeDeferred.await()
            if (proxyOutcome?.reachable == true) {
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

            results += udpStunDeferred.await()

            deduplicate(results)
        } finally {
            proxyPublicIpDeferred.cancel()
        }
    }

    private suspend fun probeStunServiceTargets(
        targets: List<CallTransportTargetCatalog.StunTarget>,
        path: PathDescriptor,
        fetchPublicIp: suspend () -> Result<String>,
        stunProbe: suspend (CallTransportTargetCatalog.StunTarget) -> Result<StunBindingClient.BindingResult>,
        probeKind: CallTransportProbeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
    ): CallTransportLeakResult {
        if (targets.isEmpty()) {
            return CallTransportLeakResult(
                service = CallTransportService.TELEGRAM,
                probeKind = probeKind,
                networkPath = path.path,
                status = CallTransportStatus.UNSUPPORTED,
                summary = "STUN targets are unavailable",
            )
        }

        val orderedTargets = orderTargetsForServiceProbe(targets)
        val priorityTargets = orderedTargets
            .filter { it.host in PREFERRED_STUN_HOSTS }
            .take(STUN_PRIORITY_BATCH_SIZE)
            .ifEmpty { orderedTargets.take(STUN_PRIORITY_BATCH_SIZE) }
        val priorityKeys = priorityTargets.map { it.host to it.port }.toSet()
        val fallbackTargets = orderedTargets.filterNot { (it.host to it.port) in priorityKeys }
        val firstSuccess = awaitFirstSuccessfulStunProbe(priorityTargets, stunProbe)
        val effectiveResult = if (firstSuccess.result != null || fallbackTargets.isEmpty()) {
            firstSuccess
        } else {
            awaitFirstSuccessfulStunProbe(
                targets = fallbackTargets,
                stunProbe = stunProbe,
                initialLastError = firstSuccess.lastError,
            )
        }
        if (effectiveResult.target != null && effectiveResult.result != null) {
            val target = effectiveResult.target
            val result = effectiveResult.result
            val publicIp = fetchPublicIp().getOrNull()
            val status = classifySignal(path = path, mappedIp = result.mappedIp, publicIp = publicIp)
            val confidence = when {
                publicIp != null && publicIp != result.mappedIp -> EvidenceConfidence.HIGH
                publicIp != null -> EvidenceConfidence.MEDIUM
                else -> EvidenceConfidence.LOW
            }
            return CallTransportLeakResult(
                service = CallTransportService.TELEGRAM,
                probeKind = probeKind,
                networkPath = path.path,
                status = status,
                targetHost = target.host,
                targetPort = target.port,
                mappedIp = result.mappedIp,
                observedPublicIp = publicIp,
                summary = buildDirectSummary(
                    path = path.path,
                    targetHost = target.host,
                    targetPort = target.port,
                    mappedIp = result.mappedIp,
                    publicIp = publicIp,
                ),
                confidence = confidence,
            )
        }

        return CallTransportLeakResult(
            service = CallTransportService.TELEGRAM,
            probeKind = probeKind,
            networkPath = path.path,
            status = CallTransportStatus.NO_SIGNAL,
            targetHost = orderedTargets.firstOrNull()?.host,
            targetPort = orderedTargets.firstOrNull()?.port,
            summary = buildNoSignalSummary(
                path = path.path,
                probeKind = probeKind,
                lastError = effectiveResult.lastError,
            ),
        )
    }

    private suspend fun buildDirectResultFromSweep(
        targets: List<CallTransportTargetCatalog.StunTarget>,
        path: PathDescriptor,
        sweepGroups: List<StunProbeGroupResult>,
        fetchPublicIp: suspend () -> Result<String>,
        probeKind: CallTransportProbeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
    ): CallTransportLeakResult? {
        val sweepResults = sweepGroups.flatMap { it.results }
        if (sweepResults.isEmpty()) {
            return null
        }

        val resultsByTarget = sweepResults.associateBy { it.host to it.port }
        val orderedTargets = orderTargetsForServiceProbe(targets)
        val successfulTarget = orderedTargets.firstNotNullOfOrNull { target ->
            val sweepResult = resultsByTarget[target.host to target.port] ?: return@firstNotNullOfOrNull null
            val mappedIp = preferredMappedIp(sweepResult) ?: return@firstNotNullOfOrNull null
            target to mappedIp
        }

        if (successfulTarget != null) {
            val (target, mappedIp) = successfulTarget
            val publicIp = fetchPublicIp().getOrNull()
            val status = classifySignal(path = path, mappedIp = mappedIp, publicIp = publicIp)
            val confidence = when {
                publicIp != null && publicIp != mappedIp -> EvidenceConfidence.HIGH
                publicIp != null -> EvidenceConfidence.MEDIUM
                else -> EvidenceConfidence.LOW
            }
            return CallTransportLeakResult(
                service = CallTransportService.TELEGRAM,
                probeKind = probeKind,
                networkPath = path.path,
                status = status,
                targetHost = target.host,
                targetPort = target.port,
                mappedIp = mappedIp,
                observedPublicIp = publicIp,
                summary = buildDirectSummary(
                    path = path.path,
                    targetHost = target.host,
                    targetPort = target.port,
                    mappedIp = mappedIp,
                    publicIp = publicIp,
                ),
                confidence = confidence,
            )
        }

        val lastError = orderedTargets.asReversed()
            .firstNotNullOfOrNull { target ->
                resultsByTarget[target.host to target.port]?.error?.takeIf { it.isNotBlank() }
            }
            ?.let(::IllegalStateException)
        return CallTransportLeakResult(
            service = CallTransportService.TELEGRAM,
            probeKind = probeKind,
            networkPath = path.path,
            status = CallTransportStatus.NO_SIGNAL,
            targetHost = orderedTargets.firstOrNull()?.host,
            targetPort = orderedTargets.firstOrNull()?.port,
            summary = buildNoSignalSummary(
                path = path.path,
                probeKind = probeKind,
                lastError = lastError,
            ),
        )
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
            java.net.InetAddress.getByName(first)::class.java == java.net.InetAddress.getByName(second)::class.java
        }.getOrDefault(false)
    }

    private fun buildDirectSummary(
        path: CallTransportNetworkPath,
        targetHost: String,
        targetPort: Int,
        mappedIp: String,
        publicIp: String?,
    ): String {
        val target = formatHostPort(targetHost, targetPort)
        val base = "STUN via ${labelForPath(path)}: endpoint $target responded"
        return if (publicIp.isNullOrBlank()) "$base (mapped IP: $mappedIp)"
        else "$base (mapped IP: $mappedIp, public IP: $publicIp)"
    }

    private fun buildNoSignalSummary(
        path: CallTransportNetworkPath,
        probeKind: CallTransportProbeKind,
        lastError: Throwable?,
    ): String {
        val suffix = lastError?.message?.takeIf { it.isNotBlank() }?.let { ": $it" }.orEmpty()
        return when (probeKind) {
            CallTransportProbeKind.PROXY_ASSISTED_TELEGRAM ->
                "Telegram call transport via ${labelForPath(path)} did not expose a reachable Telegram DC$suffix"
            CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN,
            CallTransportProbeKind.DIRECT_UDP_STUN,
            -> "STUN via ${labelForPath(path)} did not receive a response$suffix"
        }
    }

    private fun buildProxySummary(
        proxyEndpoint: ProxyEndpoint,
        targetHost: String?,
        targetPort: Int?,
        publicIp: String?,
    ): String {
        val proxyLabel = formatHostPort(proxyEndpoint.host, proxyEndpoint.port)
        val targetLabel = if (!targetHost.isNullOrBlank() && targetPort != null)
            formatHostPort(targetHost, targetPort)
        else
            "Telegram DC"
        val base = "Telegram call transport via local SOCKS5 proxy $proxyLabel: $targetLabel is reachable"
        return if (publicIp.isNullOrBlank()) base else "$base (public IP: $publicIp)"
    }

    private suspend fun probeProxyAssistedUdpStun(
        context: Context,
        proxyEndpoint: ProxyEndpoint,
        target: CallTransportTargetCatalog.StunTarget,
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
        target: CallTransportTargetCatalog.StunTarget,
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
                com.notcvnt.rknhardering.ScanExecutionContext.currentOrDefault().throwIfCancelled(error)
            }
        }
    }

    private suspend inline fun <T> cancellationAwareRunCatchingSuspend(crossinline block: suspend () -> T): Result<T> {
        return runCatching { block() }.onFailure { error ->
            if (error is Exception) {
                com.notcvnt.rknhardering.ScanExecutionContext.currentOrDefault().throwIfCancelled(error)
            }
        }
    }

    private fun isWildcardLocalRelayHost(host: String): Boolean {
        return normalizeLocalRelayHost(host) in setOf("0.0.0.0", "::", "0:0:0:0:0:0:0:0", ":::")
    }

    private fun normalizeLocalRelayHost(host: String): String = host.substringBefore('%').lowercase()

    private fun orderTargetsForServiceProbe(
        targets: List<CallTransportTargetCatalog.StunTarget>,
    ): List<CallTransportTargetCatalog.StunTarget> {
        val priorityByHost = PREFERRED_STUN_HOSTS.withIndex().associate { (index, host) -> host to index }
        return targets.sortedWith(
            compareBy<CallTransportTargetCatalog.StunTarget> { priorityByHost[it.host] ?: Int.MAX_VALUE }
                .thenBy { it.scope.ordinal }
                .thenBy { it.host },
        )
    }

    private fun preferredMappedIp(result: StunProbeResult): String? {
        return result.mappedIpv4 ?: result.mappedIpv6
    }

    private data class TargetProbeCompletion<T>(
        val target: CallTransportTargetCatalog.StunTarget,
        val result: Result<T>,
    )

    private data class FirstSuccessfulStunProbe(
        val target: CallTransportTargetCatalog.StunTarget? = null,
        val result: StunBindingClient.BindingResult? = null,
        val lastError: Throwable? = null,
    )

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun probeScopeTargetsConcurrently(
        scope: StunScope,
        targets: List<CallTransportTargetCatalog.StunTarget>,
        resolverConfig: DnsResolverConfig,
        binding: ResolverBinding?,
        dependencies: Dependencies,
    ): List<StunProbeResult> = coroutineScope {
        val dispatcher = Dispatchers.IO.limitedParallelism(STUN_SWEEP_MAX_CONCURRENCY)
        orderTargetsForServiceProbe(targets).map { target ->
            async(dispatcher) {
                val dual = cancellationAwareRunCatching {
                    dependencies.stunDualStackProbe(target, resolverConfig, binding)
                }.getOrElse {
                    StunBindingClient.DualStackBindingResult(null, null)
                }
                StunProbeResult(
                    host = target.host,
                    port = target.port,
                    scope = scope,
                    mappedIpv4 = dual.ipv4Result?.getOrNull()?.mappedIp,
                    mappedIpv6 = dual.ipv6Result?.getOrNull()?.mappedIp,
                    error = when {
                        dual.ipv4Result == null && dual.ipv6Result == null ->
                            "Не удалось разрешить адрес"
                        dual.ipv4Result?.isSuccess != true && dual.ipv6Result?.isSuccess != true -> {
                            val err = dual.ipv4Result?.exceptionOrNull()
                                ?: dual.ipv6Result?.exceptionOrNull()
                            err?.message ?: "Нет ответа"
                        }
                        else -> null
                    },
                )
            }
        }.awaitAll()
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun awaitFirstSuccessfulStunProbe(
        targets: List<CallTransportTargetCatalog.StunTarget>,
        stunProbe: suspend (CallTransportTargetCatalog.StunTarget) -> Result<StunBindingClient.BindingResult>,
        initialLastError: Throwable? = null,
    ): FirstSuccessfulStunProbe = supervisorScope {
        if (targets.isEmpty()) return@supervisorScope FirstSuccessfulStunProbe()

        val dispatcher = Dispatchers.IO.limitedParallelism(STUN_SERVICE_MAX_CONCURRENCY)
        val completions = Channel<TargetProbeCompletion<StunBindingClient.BindingResult>>(capacity = targets.size)
        var lastError: Throwable? = initialLastError

        val jobs = targets.map { target ->
            async(dispatcher) {
                val result = stunProbe(target)
                completions.send(TargetProbeCompletion(target = target, result = result))
            }
        }

        try {
            repeat(targets.size) {
                val completion = completions.receive()
                if (completion.result.isSuccess) {
                    jobs.forEach { it.cancel() }
                    return@supervisorScope FirstSuccessfulStunProbe(
                        target = completion.target,
                        result = completion.result.getOrThrow(),
                        lastError = lastError,
                    )
                }
                lastError = completion.result.exceptionOrNull() ?: lastError
            }
        } finally {
            jobs.forEach { it.cancel() }
            completions.close()
        }

        FirstSuccessfulStunProbe(lastError = lastError)
    }

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

    private fun preferSuccessfulBinding(
        dual: StunBindingClient.DualStackBindingResult,
    ): Result<StunBindingClient.BindingResult> {
        dual.ipv4Result?.takeIf { it.isSuccess }?.let { return it }
        dual.ipv6Result?.takeIf { it.isSuccess }?.let { return it }
        return dual.ipv4Result
            ?: dual.ipv6Result
            ?: Result.failure(IllegalStateException("No STUN response"))
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
                        source = EvidenceSource.TELEGRAM_CALL_TRANSPORT,
                        confidence = result.confidence ?: EvidenceConfidence.MEDIUM,
                    )
                    evidence += EvidenceItem(
                        source = EvidenceSource.TELEGRAM_CALL_TRANSPORT,
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
                        source = EvidenceSource.TELEGRAM_CALL_TRANSPORT,
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
    ): CallTransportLeakResult {
        return CallTransportLeakResult(
            service = service,
            probeKind = probeKind,
            networkPath = path,
            status = CallTransportStatus.ERROR,
            summary = summary,
            confidence = EvidenceConfidence.LOW,
        )
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
}
