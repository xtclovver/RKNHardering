package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.os.SystemClock
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.BetaCheckResult
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceMaturity
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.NetworkEpoch
import com.notcvnt.rknhardering.model.NetworkEpochChangeReason
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.AdvancedNetlinkProbe
import com.notcvnt.rknhardering.probe.BetaCanaryStatus
import com.notcvnt.rknhardering.probe.privileged.PrivilegedProbeCoordinator
import com.notcvnt.rknhardering.probe.privileged.PrivilegedProbeKind
import com.notcvnt.rknhardering.probe.privileged.PrivilegedProbeResult
import com.notcvnt.rknhardering.probe.privileged.PrivilegedProbeSettings
import java.util.UUID
import java.net.NetworkInterface
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.withContext

internal fun interface BetaChecksDependency {
    suspend fun check(request: BetaChecksRequest): BetaCheckResult
}

internal data class BetaChecksRequest(
    val context: Context,
    val settings: BetaCheckSettings,
    val resolverConfig: DnsResolverConfig,
    val networkRequestsEnabled: Boolean,
    val executionContext: ScanExecutionContext,
)

internal object BetaChecksChecker : BetaChecksDependency {
    internal const val SOCKET_ORACLES_ROLLOUT_READY = true
    private const val NETWORK_STABILIZATION_DELAY_MS = 250L

    private data class BetaCheckAttempt(
        val result: BetaCheckResult,
        val epochStable: Boolean,
    )

    override suspend fun check(request: BetaChecksRequest): BetaCheckResult {
        if (!request.settings.enabled) return BetaCheckResult.disabled()
        val retry = retryOnceOnNetworkEpochChange(
            beforeRetry = {
                request.executionContext.throwIfCancelled()
                delay(NETWORK_STABILIZATION_DELAY_MS)
                request.executionContext.throwIfCancelled()
            },
        ) {
            val attempt = checkAttempt(request)
            NetworkEpochAttempt(attempt.result, attempt.epochStable)
        }
        return retry.value.copy(
            networkEpochChanges = retry.attempts.flatMapTo(linkedSetOf()) { it.value.networkEpochChanges },
            networkEpochRetryCount = retry.retryCount,
        )
    }

    private suspend fun checkAttempt(request: BetaChecksRequest): BetaCheckAttempt = withContext(Dispatchers.IO) {
        request.executionContext.throwIfCancelled()
        val initialEpoch = captureNetworkEpoch(request.context)
        return@withContext withCloseableResource(NetworkEpochMonitor(request.context, initialEpoch)) { epochMonitor ->
        val epoch = epochMonitor.awaitBaseline()
        request.executionContext.throwIfCancelled()
        val executionContext = if (request.settings.profileIsolation) {
            ExecutionContextChecker.check(
                context = request.context,
                networkEpochId = epoch.id,
                observedAtElapsedMs = SystemClock.elapsedRealtime(),
                hiddenApiEnabled = request.settings.hiddenAndroidApis,
            )
        } else {
            null
        }
        val socketObservations = if (request.settings.socketOracles && SOCKET_ORACLES_ROLLOUT_READY) {
            AdvancedNetlinkProbe.check(
                context = request.context,
                aggressive = request.settings.aggressive,
                epochId = epoch.id,
                observedAtElapsedMs = SystemClock.elapsedRealtime(),
                executionContext = request.executionContext,
            )
        } else {
            emptyList()
        }
        val supportingObservations = SupportingBetaChecker.check(
            context = request.context,
            proxySelectorEnabled = request.settings.socketOracles,
            interfaceDriverEnabled = request.settings.kernelNetlink,
            epochId = epoch.id,
            observedAtElapsedMs = SystemClock.elapsedRealtime(),
        )
        val hiddenObservations = if (request.settings.hiddenAndroidApis) {
            HiddenAndroidBetaChecker.check(
                context = request.context,
                executionFacts = executionContext?.facts,
                epochId = epoch.id,
                observedAtElapsedMs = SystemClock.elapsedRealtime(),
            )
        } else {
            emptyList()
        }
        val sandboxObservations = if (request.settings.sandboxIntegrity) {
            SandboxIntegrityChecker.check(
                context = request.context,
                aggressive = request.settings.aggressive,
                networkEpochId = epoch.id,
                observedAtElapsedMs = SystemClock.elapsedRealtime(),
            )
        } else {
            emptyList()
        }
        val localKernelObservations = if (request.settings.kernelNetlink) {
            listOf(KernelBetaChecker.checkTunOnly(
                context = request.context,
                epochId = epoch.id,
                at = SystemClock.elapsedRealtime(),
                executionContext = request.executionContext,
            ))
        } else emptyList()
        val privilegedSettings = PrivilegedProbeSettings(
            betaMasterEnabled = request.settings.enabled,
            privilegedMasterEnabled = request.settings.privilegedChecksEnabled,
            provider = request.settings.privilegedProvider,
        )
        val privilegedCoordinator = PrivilegedProbeCoordinator(request.context)
        val causalKinds = if (
            request.settings.kernelNetlink && request.settings.aggressive && request.settings.privilegedChecksEnabled
        ) {
            linkedSetOf(PrivilegedProbeKind.WIREGUARD, PrivilegedProbeKind.OVPN)
        } else emptySet()
        val privilegedBeforeResults = privilegedCoordinator.runBatch(privilegedSettings, causalKinds)
        val interfaceTrafficBefore = if (request.settings.aggressive) {
            SupportingBetaChecker.sampleInterfaceTraffic(request.context)
        } else null
        val canaryEvaluation = if (request.settings.aggressive) {
            BetaCanaryChecker.check(
                context = request.context,
                epoch = epoch,
                observedAtElapsedMs = SystemClock.elapsedRealtime(),
                executionContext = request.executionContext,
                networkRequestsEnabled = request.networkRequestsEnabled,
            )
        } else {
            null
        }
        val privilegedKinds = buildSet {
            if (request.settings.privilegedChecksEnabled && request.settings.kernelNetlink) {
                add(PrivilegedProbeKind.WIREGUARD)
                add(PrivilegedProbeKind.OVPN)
                add(PrivilegedProbeKind.XFRM)
            }
            if (request.settings.privilegedChecksEnabled && request.settings.bpfNetfilter) {
                add(PrivilegedProbeKind.BPF_NETFILTER)
            }
        }
        val initialProviderFailure = privilegedBeforeResults.values.firstOrNull()
            ?.takeUnless { it is PrivilegedProbeResult.Available }
        val privilegedResults = if (initialProviderFailure != null) {
            privilegedKinds.associateWith { initialProviderFailure }
        } else {
            privilegedCoordinator.runBatch(
                privilegedSettings,
                privilegedKinds,
                imsContext = hasImsOrEmergencyNetwork(request.context),
            )
        }
        val privilegedKernelObservations = KernelBetaChecker.privilegedObservations(
            request.context,
            privilegedResults,
            epoch.id,
            SystemClock.elapsedRealtime(),
        )
        val interfaceTrafficObservation = interfaceTrafficBefore?.let { before ->
            SupportingBetaChecker.interfaceTrafficObservation(
                request.context,
                before,
                SupportingBetaChecker.sampleInterfaceTraffic(request.context),
                canaryEvaluation?.result?.status == BetaCanaryStatus.AVAILABLE,
                epoch.id,
                SystemClock.elapsedRealtime(),
            )
        }
        val kernelWithCausalDelta = if (privilegedBeforeResults.isNotEmpty() && canaryEvaluation != null) {
            val fallback = PrivilegedProbeResult.Unavailable(request.settings.privilegedProvider)
            val activeInterfaceIndex = runCatching {
                epoch.activeInterface?.let(NetworkInterface::getByName)?.index
            }.getOrNull()
            val wireGuardCausal = KernelBetaChecker.wireGuardDeltaObservation(
                context = request.context,
                before = KernelBetaChecker.wireGuardSample(
                    privilegedBeforeResults[PrivilegedProbeKind.WIREGUARD] ?: fallback,
                ),
                after = KernelBetaChecker.wireGuardSample(
                    privilegedResults[PrivilegedProbeKind.WIREGUARD] ?: fallback,
                ),
                canaryTransferred = canaryEvaluation.result.status == BetaCanaryStatus.AVAILABLE,
                expectedInterfaceIndex = activeInterfaceIndex,
                epochId = epoch.id,
                at = SystemClock.elapsedRealtime(),
            )
            val ovpnCausal = KernelBetaChecker.ovpnDeltaObservation(
                context = request.context,
                before = KernelBetaChecker.ovpnSample(
                    privilegedBeforeResults[PrivilegedProbeKind.OVPN] ?: fallback,
                ),
                after = KernelBetaChecker.ovpnSample(
                    privilegedResults[PrivilegedProbeKind.OVPN] ?: fallback,
                ),
                canaryTransferred = canaryEvaluation.result.status == BetaCanaryStatus.AVAILABLE,
                expectedInterfaceIndex = activeInterfaceIndex,
                epochId = epoch.id,
                at = SystemClock.elapsedRealtime(),
            )
            localKernelObservations + privilegedKernelObservations.filterNot {
                it.checkId == "beta.wireguard_genl" || it.checkId == "beta.ovpn_genl"
            } + wireGuardCausal + ovpnCausal
        } else {
            localKernelObservations + privilegedKernelObservations
        }
        val foregroundObservations = hiddenObservations.filter { it.checkId == "beta.foreground_user" }
        val networkObservations = socketObservations + supportingObservations + kernelWithCausalDelta +
            listOfNotNull(interfaceTrafficObservation) +
            canaryEvaluation?.observations.orEmpty() +
            hiddenObservations.filterNot { it.checkId == "beta.foreground_user" }
        val repeatedObservations = buildMap {
            if (request.settings.hiddenAndroidApis) {
                request.executionContext.throwIfCancelled()
                put(
                    "beta.vpn_binder",
                    HiddenAndroidBetaChecker.checkVpnOnly(
                        request.context,
                        epoch.id,
                        SystemClock.elapsedRealtime(),
                    ),
                )
            }
            if (request.settings.kernelNetlink) {
                request.executionContext.throwIfCancelled()
                put(
                    "beta.tun_fd",
                    KernelBetaChecker.checkTunOnly(
                        request.context,
                        epoch.id,
                        SystemClock.elapsedRealtime(),
                        request.executionContext,
                    ),
                )
            }
        }
        val closingEpoch = captureNetworkEpoch(request.context, epoch.id)
        val monitorSnapshot = epochMonitor.stop()
        val epochChanges = monitorSnapshot.changeReasons + monitorSnapshot.baseline.changeReasons(closingEpoch)
        val epochStable = epochChanges.isEmpty()
        val effectiveNetworkObservations = if (epochStable) {
            networkObservations
        } else {
            networkObservations.map { observation ->
                observation.copy(
                    availability = ProbeAvailability.RACE,
                    polarity = com.notcvnt.rknhardering.model.ObservationPolarity.INCONCLUSIVE,
                    suppressions = observation.suppressions +
                        com.notcvnt.rknhardering.model.BetaSuppressionRuleId.NETWORK_EPOCH_CHANGED,
                )
            }
        }
        val runObservations = listOfNotNull(executionContext?.observation) + sandboxObservations +
            foregroundObservations + effectiveNetworkObservations
        val runCheckIds = runObservations.map { it.checkId }.toSet()
        val observations = runObservations.toMutableList().apply {
            BetaCheckRegistry.definitions.values.forEach { definition ->
                if (definition.checkId !in runCheckIds) {
                    add(
                        BetaObservation(
                            checkId = definition.checkId,
                            source = definition.source,
                            availability = ProbeAvailability.SKIPPED,
                            polarity = com.notcvnt.rknhardering.model.ObservationPolarity.INCONCLUSIVE,
                            authority = com.notcvnt.rknhardering.model.ObservationAuthority.HEURISTIC,
                            confidence = com.notcvnt.rknhardering.model.EvidenceConfidence.LOW,
                            independenceGroup = definition.independenceGroup,
                            detectionDomain = definition.detectionDomain,
                            observedAtElapsedMs = SystemClock.elapsedRealtime(),
                            networkEpochId = epoch.id,
                            facts = mapOf("summary" to "Check skipped or not executed"),
                        )
                    )
                }
            }
        }
        val repeatValidations = observations.mapNotNull { observation ->
            val repeated = repeatedObservations[observation.checkId] ?: return@mapNotNull null
            val successful = listOf(observation, repeated).count {
                it.availability == ProbeAvailability.AVAILABLE
            }
            observation.checkId to BetaRepeatValidation(
                successfulSamples = successful,
                classificationsMatch = observation.availability == repeated.availability &&
                    observation.polarity == repeated.polarity,
                epochStable = epochStable,
            )
        }.toMap().toMutableMap().apply {
            mapOf(
                "beta.wireguard_genl" to PrivilegedProbeKind.WIREGUARD,
                "beta.ovpn_genl" to PrivilegedProbeKind.OVPN,
            ).forEach { (checkId, kind) ->
                val before = privilegedBeforeResults[kind] ?: return@forEach
                val after = privilegedResults[kind] ?: return@forEach
                put(
                    checkId,
                    BetaRepeatValidation(
                        successfulSamples = listOf(before, after).count {
                            it is PrivilegedProbeResult.Available
                        },
                        classificationsMatch = before::class == after::class,
                        epochStable = epochStable,
                    ),
                )
            }
        }
        val evaluated = observations.map { observation ->
            BetaEvidencePolicy.evaluate(
                observation,
                BetaEvaluationContext(
                    networkEpochId = if (epochStable) epoch.id else "${epoch.id}:changed",
                    repeatValidations = repeatValidations,
                ),
            )
        }
        val availability = buildMap {
            observations.forEach { observation ->
                if (observation.facts["summary"] != "Check skipped or not executed") {
                    put(observation.availability, (get(observation.availability) ?: 0) + 1)
                }
            }
        }
        val coverageFinding = Finding(
            description = request.context.getString(
                com.notcvnt.rknhardering.R.string.beta_coverage_summary,
                availability[ProbeAvailability.AVAILABLE] ?: 0,
                availability[ProbeAvailability.UNSUPPORTED] ?: 0,
                availability[ProbeAvailability.PERMISSION_DENIED] ?: 0,
                availability[ProbeAvailability.UNAVAILABLE] ?: 0,
                availability[ProbeAvailability.ERROR] ?: 0,
                availability[ProbeAvailability.MALFORMED_RESPONSE] ?: 0,
                availability[ProbeAvailability.TRUNCATED] ?: 0,
                availability[ProbeAvailability.SKIPPED] ?: 0,
                availability[ProbeAvailability.RACE] ?: 0,
            ),
            isInformational = true,
            maturity = EvidenceMaturity.BETA,
            checkId = "beta.coverage",
            availability = ProbeAvailability.AVAILABLE,
        )
        runCatching {
            val cacheable = setOf(
                ProbeAvailability.AVAILABLE,
                ProbeAvailability.UNSUPPORTED,
                ProbeAvailability.PERMISSION_DENIED,
                ProbeAvailability.UNAVAILABLE,
            )
            val providerIdentity = privilegedResults.values
                .filterIsInstance<PrivilegedProbeResult.Available>()
                .firstOrNull()
                ?.identity
            val fingerprint = BetaCapabilityCache.currentFingerprint(
                request.context,
                privilegedProvider = request.settings.privilegedProvider,
                privilegedProviderUid = providerIdentity?.uid,
                privilegedProtocolVersion = providerIdentity?.protocolVersion,
                privilegedBackendVersion = providerIdentity?.backendVersion,
            )
            val cached = BetaCapabilityCache.load(request.context, fingerprint)
            val current = observations.asSequence()
                .filter { it.availability in cacheable }
                .groupBy(BetaObservation::checkId)
                .mapValues { (_, values) -> values.first().availability }
            BetaCapabilityCache.store(
                request.context,
                cached + current,
                fingerprint,
            )
        }
        BetaCheckAttempt(
            result = BetaCheckResult(
                category = CategoryResult(
                    name = "β Бета-проверки",
                    detected = evaluated.any { it.finding.detected },
                    needsReview = evaluated.any { it.finding.needsReview },
                    findings = evaluated.map { it.finding } + coverageFinding,
                    evidence = evaluated.mapNotNull { it.evidence },
                    maturity = EvidenceMaturity.BETA,
                ),
                executionContext = executionContext?.facts,
                availabilitySummary = availability,
                networkEpochChanges = epochChanges,
            ),
            epochStable = epochStable,
        )
        }
    }

    private fun captureNetworkEpoch(context: Context, id: String = UUID.randomUUID().toString()): NetworkEpoch {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val active = connectivity?.activeNetwork
        val capabilities = active?.let(connectivity::getNetworkCapabilities)
        val linkProperties = active?.let(connectivity::getLinkProperties)
        return NetworkEpoch(
            id = id,
            startedAtElapsedMs = SystemClock.elapsedRealtime(),
            activeNetworkHandle = active?.networkHandle,
            networkHandles = active?.let { setOf(it.networkHandle) }.orEmpty(),
            activeTransports = capabilities.transportTypes(),
            activeInterface = linkProperties?.interfaceName,
            validated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            captivePortal = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            vpnTransport = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            vcnTransport = null,
            privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                linkProperties?.isPrivateDnsActive
            } else {
                null
            },
            nat64Prefix = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                linkProperties?.nat64Prefix?.toString()
            } else {
                null
            },
            telephonyNetworkType = null,
            roaming = null,
            currentUserId = Process.myUid() / 100_000,
            routes = linkProperties?.routes.orEmpty().mapTo(linkedSetOf()) { it.toString() },
            linkAddresses = linkProperties?.linkAddresses.orEmpty().mapTo(linkedSetOf()) { it.toString() },
            dnsServers = linkProperties?.dnsServers.orEmpty().mapTo(linkedSetOf()) { it.hostAddress ?: it.toString() },
            domains = linkProperties?.domains,
            privateDnsServerName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                linkProperties?.privateDnsServerName
            } else {
                null
            },
            httpProxy = linkProperties?.httpProxy?.toString(),
        )
    }

    private fun hasImsOrEmergencyNetwork(context: Context): Boolean {
        val connectivity = context.getSystemService(ConnectivityManager::class.java) ?: return false
        return connectivity.allNetworks.any { network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@any false
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_IMS) ||
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_EIMS)
        }
    }
}

internal fun NetworkEpoch.hasSameNetworkState(other: NetworkEpoch): Boolean = changeReasons(other).isEmpty()

internal fun NetworkEpoch.changeReasons(other: NetworkEpoch): Set<NetworkEpochChangeReason> = buildSet {
    if (activeNetworkHandle != other.activeNetworkHandle) add(NetworkEpochChangeReason.DEFAULT_NETWORK_CHANGED)
    if (activeTransports != other.activeTransports) add(NetworkEpochChangeReason.TRANSPORTS_CHANGED)
    if (activeInterface != other.activeInterface) add(NetworkEpochChangeReason.ACTIVE_INTERFACE_CHANGED)
    if (validated != other.validated) add(NetworkEpochChangeReason.VALIDATION_CHANGED)
    if (captivePortal != other.captivePortal) add(NetworkEpochChangeReason.CAPTIVE_PORTAL_CHANGED)
    if (vpnTransport != other.vpnTransport) add(NetworkEpochChangeReason.VPN_TRANSPORT_CHANGED)
    if (privateDnsActive != other.privateDnsActive || privateDnsServerName != other.privateDnsServerName) {
        add(NetworkEpochChangeReason.PRIVATE_DNS_CHANGED)
    }
    if (nat64Prefix != other.nat64Prefix) add(NetworkEpochChangeReason.NAT64_CHANGED)
    if (routes != other.routes) add(NetworkEpochChangeReason.ROUTES_CHANGED)
    if (linkAddresses != other.linkAddresses) add(NetworkEpochChangeReason.LINK_ADDRESSES_CHANGED)
    if (dnsServers != other.dnsServers) add(NetworkEpochChangeReason.DNS_SERVERS_CHANGED)
    if (domains != other.domains) add(NetworkEpochChangeReason.DOMAINS_CHANGED)
    if (httpProxy != other.httpProxy) add(NetworkEpochChangeReason.HTTP_PROXY_CHANGED)
    if (currentUserId != other.currentUserId) add(NetworkEpochChangeReason.CURRENT_USER_CHANGED)
}

private fun NetworkCapabilities?.transportTypes(): Set<Int> = buildSet {
    val capabilities = this@transportTypes ?: return@buildSet
    for (transport in 0..10) {
        if (capabilities.hasTransport(transport)) add(transport)
    }
}

private class NetworkEpochMonitor(
    context: Context,
    initial: NetworkEpoch,
) : AutoCloseable {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val tracker = DefaultNetworkEpochTracker(initial)
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            tracker.onAvailable(network.networkHandle)
        }

        override fun onLost(network: Network) {
            tracker.onLost(network.networkHandle)
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            tracker.onCapabilities(
                network.networkHandle,
                capabilities.transportTypes(),
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            )
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            tracker.onLinkProperties(network.networkHandle) { baseline ->
                baseline.copy(
                    activeInterface = linkProperties.interfaceName,
                    privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) linkProperties.isPrivateDnsActive else null,
                    nat64Prefix = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) linkProperties.nat64Prefix?.toString() else null,
                    routes = linkProperties.routes.mapTo(linkedSetOf()) { it.toString() },
                    linkAddresses = linkProperties.linkAddresses.mapTo(linkedSetOf()) { it.toString() },
                    dnsServers = linkProperties.dnsServers.mapTo(linkedSetOf()) { it.hostAddress ?: it.toString() },
                    domains = linkProperties.domains,
                    privateDnsServerName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) linkProperties.privateDnsServerName else null,
                    httpProxy = linkProperties.httpProxy?.toString(),
                )
            }
        }
    }
    private val registered = connectivity?.let { manager ->
        runCatching {
            manager.registerDefaultNetworkCallback(callback)
            true
        }.getOrDefault(false)
    } == true
    private var stopped = false

    init {
        if (!registered) tracker.monitorUnavailable()
    }

    suspend fun awaitBaseline(): NetworkEpoch = tracker.awaitBaseline()

    @Synchronized
    fun stop(): NetworkEpochTrackerSnapshot {
        if (!stopped) {
            if (registered) runCatching { connectivity?.unregisterNetworkCallback(callback) }
            stopped = true
        }
        return tracker.stopAndSnapshot()
    }

    override fun close() {
        stop()
    }
}

internal class NetworkEpochTransitionLatch {
    private val firstReason = AtomicReference<NetworkEpochChangeReason?>(null)
    val changed: Boolean get() = firstReason.get() != null
    val reason: NetworkEpochChangeReason? get() = firstReason.get()
    fun markChanged(reason: NetworkEpochChangeReason = NetworkEpochChangeReason.DEFAULT_NETWORK_CHANGED) {
        firstReason.compareAndSet(null, reason)
    }
}

internal class DefaultNetworkEpochTracker(initial: NetworkEpoch) {
    private val baselineRef = AtomicReference(initial)
    private val reasons = linkedSetOf<NetworkEpochChangeReason>()
    private val baselineReady = CompletableDeferred<NetworkEpoch>()
    private var trackedHandle = initial.activeNetworkHandle
    private var awaitingInitialAvailable = trackedHandle != null
    private var awaitingInitialCapabilities = trackedHandle != null
    private var awaitingInitialLinkProperties = trackedHandle != null
    private var monitoring = trackedHandle == null
    private var closed = false

    init {
        if (monitoring) baselineReady.complete(initial)
    }

    val changeReasons: Set<NetworkEpochChangeReason>
        get() = synchronized(this) { reasons.toSet() }

    suspend fun awaitBaseline(): NetworkEpoch = withTimeoutOrNull(750L) {
        baselineReady.await()
    } ?: bootstrapTimedOut()

    @Synchronized
    fun monitorUnavailable() {
        reasons += NetworkEpochChangeReason.CALLBACK_MONITOR_UNAVAILABLE
        finishBootstrapLocked()
    }

    @Synchronized
    internal fun bootstrapTimedOut(): NetworkEpoch {
        reasons += NetworkEpochChangeReason.CALLBACK_BOOTSTRAP_TIMEOUT
        finishBootstrapLocked()
        return baselineRef.get()
    }

    @Synchronized
    fun stopAndSnapshot(): NetworkEpochTrackerSnapshot {
        closed = true
        finishBootstrapLocked()
        return NetworkEpochTrackerSnapshot(baselineRef.get(), reasons.toSet())
    }

    @Synchronized
    fun onAvailable(handle: Long) {
        if (closed) return
        if (!monitoring) {
            awaitingInitialAvailable = false
            if (handle != trackedHandle) {
                trackedHandle = handle
                awaitingInitialCapabilities = true
                awaitingInitialLinkProperties = true
                baselineRef.set(
                    baselineRef.get().copy(activeNetworkHandle = handle, networkHandles = setOf(handle)),
                )
            }
            return
        }
        if (awaitingInitialAvailable && handle == trackedHandle) {
            awaitingInitialAvailable = false
            return
        }
        if (handle != trackedHandle) {
            reasons += NetworkEpochChangeReason.DEFAULT_NETWORK_CHANGED
            trackedHandle = handle
            awaitingInitialCapabilities = true
            awaitingInitialLinkProperties = true
        }
    }

    @Synchronized
    fun onLost(handle: Long) {
        if (closed || handle != trackedHandle) return
        if (!monitoring) {
            trackedHandle = null
            baselineRef.set(
                baselineRef.get().copy(
                    activeNetworkHandle = null,
                    networkHandles = emptySet(),
                    activeTransports = emptySet(),
                    activeInterface = null,
                    validated = null,
                    captivePortal = null,
                    vpnTransport = null,
                    routes = emptySet(),
                    linkAddresses = emptySet(),
                    dnsServers = emptySet(),
                ),
            )
            finishBootstrapLocked()
        } else {
            reasons += NetworkEpochChangeReason.DEFAULT_NETWORK_LOST
        }
    }

    @Synchronized
    fun onCapabilities(
        handle: Long,
        transports: Set<Int>,
        validated: Boolean,
        captivePortal: Boolean,
        vpnTransport: Boolean,
    ) {
        if (closed || handle != trackedHandle) return
        val previous = baselineRef.get()
        val current = previous.copy(
            activeNetworkHandle = handle,
            networkHandles = setOf(handle),
            activeTransports = transports,
            validated = validated,
            captivePortal = captivePortal,
            vpnTransport = vpnTransport,
        )
        baselineRef.set(current)
        if (awaitingInitialCapabilities) {
            awaitingInitialCapabilities = false
            completeBootstrapIfReady()
        } else {
            reasons += previous.changeReasons(current)
        }
    }

    @Synchronized
    fun onLinkProperties(handle: Long, update: (NetworkEpoch) -> NetworkEpoch) {
        if (closed || handle != trackedHandle) return
        val previous = baselineRef.get()
        val current = update(previous)
        baselineRef.set(current)
        if (awaitingInitialLinkProperties) {
            awaitingInitialLinkProperties = false
            completeBootstrapIfReady()
        } else {
            reasons += previous.changeReasons(current)
        }
    }

    private fun completeBootstrapIfReady() {
        if (!awaitingInitialCapabilities && !awaitingInitialLinkProperties) finishBootstrapLocked()
    }

    private fun finishBootstrapLocked() {
        if (monitoring) return
        monitoring = true
        awaitingInitialAvailable = false
        awaitingInitialCapabilities = false
        awaitingInitialLinkProperties = false
        baselineReady.complete(baselineRef.get())
    }
}

internal data class NetworkEpochTrackerSnapshot(
    val baseline: NetworkEpoch,
    val changeReasons: Set<NetworkEpochChangeReason>,
)

internal data class NetworkEpochAttempt<T>(val value: T, val stable: Boolean)

internal data class NetworkEpochRetryResult<T>(val attempts: List<NetworkEpochAttempt<T>>) {
    val value: T get() = attempts.last().value
    val retryCount: Int get() = attempts.size - 1
}

internal suspend fun <T> retryOnceOnNetworkEpochChange(
    beforeRetry: suspend () -> Unit = {},
    attempt: suspend () -> NetworkEpochAttempt<T>,
): NetworkEpochRetryResult<T> {
    val first = attempt()
    if (first.stable) return NetworkEpochRetryResult(listOf(first))
    beforeRetry()
    return NetworkEpochRetryResult(listOf(first, attempt()))
}

internal inline fun <R : AutoCloseable, T> withCloseableResource(resource: R, block: (R) -> T): T =
    try {
        block(resource)
    } finally {
        resource.close()
    }
