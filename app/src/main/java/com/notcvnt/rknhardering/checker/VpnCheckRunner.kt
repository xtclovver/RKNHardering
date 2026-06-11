package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.checker.ipconsensus.AsnResolver
import com.notcvnt.rknhardering.checker.ipconsensus.IpConsensusBuilder
import com.notcvnt.rknhardering.customcheck.CallTransportConfig
import com.notcvnt.rknhardering.customcheck.CdnPullingConfig
import com.notcvnt.rknhardering.customcheck.CustomCdnTarget
import com.notcvnt.rknhardering.customcheck.CustomDomain
import com.notcvnt.rknhardering.customcheck.CustomGeoIpProvider
import com.notcvnt.rknhardering.customcheck.CustomIpEndpoint
import com.notcvnt.rknhardering.customcheck.DirectSignsConfig
import com.notcvnt.rknhardering.customcheck.GeoIpConfig
import com.notcvnt.rknhardering.customcheck.IcmpSpoofingConfig
import com.notcvnt.rknhardering.customcheck.IcmpTarget
import com.notcvnt.rknhardering.customcheck.IndirectSignsConfig
import com.notcvnt.rknhardering.customcheck.IpComparisonConfig
import com.notcvnt.rknhardering.customcheck.LocationSignalsConfig
import com.notcvnt.rknhardering.customcheck.RttTarget
import com.notcvnt.rknhardering.customcheck.RttTriangulationConfig
import com.notcvnt.rknhardering.customcheck.StunServer
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.DomainReachabilityResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.GeoIpFacts
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.LocationSignalsFacts
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.WhitelistAwareDnsFailureCounter
import com.notcvnt.rknhardering.probe.OperatorWhitelistProbe
import com.notcvnt.rknhardering.probe.OperatorWhitelistProbeResult
import com.notcvnt.rknhardering.probe.TunProbeModeOverride
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import com.notcvnt.rknhardering.checker.TunInterfaceInfo
import kotlin.coroutines.EmptyCoroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext

data class CheckSettings(
    val splitTunnelEnabled: Boolean = true,
    val proxyScanEnabled: Boolean = true,
    val proxyAuthProbeEnabled: Boolean = false,
    val xrayApiScanEnabled: Boolean = true,
    val clashApiScanEnabled: Boolean = true,
    val networkRequestsEnabled: Boolean = true,
    val callTransportProbeEnabled: Boolean = false,
    val cdnPullingEnabled: Boolean = false,
    val cdnPullingMeduzaEnabled: Boolean = true,
    val icmpSpoofingEnabled: Boolean = true,
    val rttTriangulationEnabled: Boolean = false,
    val nativeSignsEnabled: Boolean = true,
    val tunProbeDebugEnabled: Boolean = false,
    val tunProbeModeOverride: TunProbeModeOverride = TunProbeModeOverride.AUTO,
    val resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    val portRange: String = "full",
    val portRangeStart: Int = 1024,
    val portRangeEnd: Int = 65535,
    val splitTunnelConnectTimeoutMs: Int = 80,
    val splitTunnelCheckUnderlyingNetwork: Boolean = true,
    val splitTunnelCheckVpnNetworkBinding: Boolean = true,
    val splitTunnelCheckMtprotoViaProxy: Boolean = true,

    // === Per-checker custom-profile parameters (defaults preserve legacy behaviour) ===
    val geoIp: GeoIpConfig = GeoIpConfig(),
    val ipComparison: IpComparisonConfig = IpComparisonConfig(),
    val cdnPulling: CdnPullingConfig = CdnPullingConfig(enabled = false),
    val directSigns: DirectSignsConfig = DirectSignsConfig(),
    val indirectSigns: IndirectSignsConfig = IndirectSignsConfig(),
    val locationSignals: LocationSignalsConfig = LocationSignalsConfig(),
    val icmpSpoofing: IcmpSpoofingConfig = IcmpSpoofingConfig(enabled = true),
    val rttTriangulation: RttTriangulationConfig = RttTriangulationConfig(enabled = false),
    val callTransport: CallTransportConfig = CallTransportConfig(enabled = false),

    // Domain reachability (DPI detection)
    val domainReachabilityEnabled: Boolean = false,
    val reachabilityDomains: List<CustomDomain> = emptyList(),
)

sealed interface CheckUpdate {
    data class GeoIpReady(val result: CategoryResult) : CheckUpdate
    data class IpComparisonReady(val result: IpComparisonResult) : CheckUpdate
    data class CdnPullingReady(val result: CdnPullingResult) : CheckUpdate
    data class IcmpSpoofingReady(val result: CategoryResult) : CheckUpdate
    data class RttTriangulationReady(val result: CategoryResult) : CheckUpdate
    data class DirectSignsReady(val result: CategoryResult) : CheckUpdate
    data class IndirectSignsReady(val result: CategoryResult) : CheckUpdate
    data class LocationSignalsReady(val result: CategoryResult) : CheckUpdate
    data class NativeSignsReady(val result: CategoryResult) : CheckUpdate
    data class BypassProgress(val progress: BypassChecker.Progress) : CheckUpdate
    data class BypassReady(val result: BypassResult) : CheckUpdate
    data class IpConsensusReady(val result: IpConsensusResult) : CheckUpdate
    data class DomainReachabilityReady(val result: DomainReachabilityResult) : CheckUpdate
    data class VerdictReady(val verdict: Verdict) : CheckUpdate
}

object VpnCheckRunner {

    internal data class Dependencies(
        val geoIpCheck: suspend (Context, DnsResolverConfig, GeoIpConfig) -> CategoryResult =
            { ctx, resolverConfig, geoIpConfig -> GeoIpChecker.check(ctx, resolverConfig, geoIpConfig) },
        val ipComparisonCheck: suspend (Context, DnsResolverConfig, IpComparisonConfig) -> IpComparisonResult =
            { ctx, resolverConfig, ipComparisonConfig ->
                IpComparisonChecker.check(ctx, resolverConfig = resolverConfig, config = ipComparisonConfig)
            },
        val cdnPullingCheck: suspend (Context, DnsResolverConfig, CdnPullingConfig) -> CdnPullingResult =
            { ctx, resolverConfig, cdnConfig ->
                CdnPullingChecker.check(ctx, resolverConfig = resolverConfig, config = cdnConfig)
            },
        val icmpSpoofingCheck: suspend (Context, DnsResolverConfig, IcmpSpoofingConfig) -> CategoryResult =
            { ctx, resolverConfig, icmpConfig -> IcmpSpoofingChecker.check(ctx, resolverConfig, icmpConfig) },
        val rttTriangulationCheck: suspend (Context, DnsResolverConfig, GeoIpFacts?, RttTriangulationConfig) -> CategoryResult =
            { ctx, cfg, geo, rttConfig -> RttTriangulationChecker.check(ctx, cfg, geo, rttConfig) },
        val underlyingProbe: suspend (
            Context,
            DnsResolverConfig,
            Boolean,
            TunProbeModeOverride,
            Boolean,
            String?,
            String?,
        ) -> UnderlyingNetworkProber.ProbeResult =
            { ctx, resolverConfig, debugEnabled, modeOverride, tunInterfacePresent, tunInterfaceName, underlyingInterfaceName ->
                UnderlyingNetworkProber.probe(
                    context = ctx,
                    resolverConfig = resolverConfig,
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                    tunInterfacePresent = tunInterfacePresent,
                    tunInterfaceName = tunInterfaceName,
                    underlyingInterfaceName = underlyingInterfaceName,
                )
            },
        val directCheck: suspend (Context, UnderlyingNetworkProber.ProbeResult?, Boolean, DirectSignsConfig) -> CategoryResult =
            { ctx, tunActiveProbeResult, tunInterfacePresent, directConfig ->
                DirectSignsChecker.check(
                    ctx,
                    tunActiveProbeResult = tunActiveProbeResult,
                    tunInterfacePresent = tunInterfacePresent,
                    config = directConfig,
                )
            },
        val tunInterfaceInfoCollector: (Context) -> TunInterfaceInfo =
            { ctx -> IndirectSignsChecker.collectTunInterfaceInfo(ctx) },
        val operatorWhitelistProbe: suspend () -> OperatorWhitelistProbeResult =
            { OperatorWhitelistProbe.probe() },
        val indirectCheck: suspend (Context, Boolean, Boolean, DnsResolverConfig, IndirectSignsConfig, CallTransportConfig) -> CategoryResult =
            { ctx, networkRequestsEnabled, callTransportProbeEnabled, resolverConfig, indirectConfig, callTransportConfig ->
                IndirectSignsChecker.check(
                    context = ctx,
                    networkRequestsEnabled = networkRequestsEnabled,
                    callTransportProbeEnabled = callTransportProbeEnabled,
                    resolverConfig = resolverConfig,
                    config = indirectConfig,
                    callTransportConfig = callTransportConfig,
                )
            },
        val locationCheck: suspend (Context, Boolean, DnsResolverConfig, LocationSignalsConfig) -> CategoryResult =
            { ctx, networkRequestsEnabled, resolverConfig, locationConfig ->
                LocationSignalsChecker.check(
                    ctx,
                    networkRequestsEnabled = networkRequestsEnabled,
                    resolverConfig = resolverConfig,
                    config = locationConfig,
                )
            },
        val nativeCheck: suspend (Context) -> CategoryResult =
            { ctx -> NativeSignsChecker.check(ctx) },
        val domainReachabilityCheck: suspend (Context, List<CustomDomain>, DnsResolverConfig) -> DomainReachabilityResult =
            { ctx, domains, resolverConfig -> DomainReachabilityChecker.check(ctx, domains, resolverConfig) },
        val bypassCheck: suspend (
            Context,
            DnsResolverConfig,
            Boolean,
            Boolean,
            Boolean,
            Boolean,
            Boolean,
            String,
            Int,
            Int,
            Int,
            Boolean,
            Boolean,
            Boolean,
            kotlinx.coroutines.Deferred<UnderlyingNetworkProber.ProbeResult>?,
            (suspend (BypassChecker.Progress) -> Unit)?,
        ) -> BypassResult =
            { ctx, resolverConfig, splitTunnelEnabled, proxyScanEnabled, proxyAuthProbeEnabled, xrayApiScanEnabled, clashApiScanEnabled, portRange, portRangeStart, portRangeEnd, connectTimeoutMs, checkUnderlyingNetwork, checkVpnNetworkBinding, checkMtprotoViaProxy, underlyingProbeDeferred, onProgress ->
                BypassChecker.check(
                    ctx,
                    resolverConfig,
                    splitTunnelEnabled,
                    proxyScanEnabled,
                    proxyAuthProbeEnabled,
                    xrayApiScanEnabled,
                    clashApiScanEnabled,
                    portRange,
                    portRangeStart,
                    portRangeEnd,
                    connectTimeoutMs,
                    checkUnderlyingNetwork,
                    checkVpnNetworkBinding,
                    checkMtprotoViaProxy,
                    underlyingProbeDeferred,
                    onProgress,
                )
            },
    )

    @Volatile
    internal var dependenciesOverride: Dependencies? = null

    private fun <T> CoroutineScope.safeAsync(
        context: kotlin.coroutines.CoroutineContext = EmptyCoroutineContext,
        fallback: (Throwable) -> T,
        block: suspend CoroutineScope.() -> T,
    ): Deferred<T> = async(context) {
        try {
            block()
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (error: Throwable) {
            fallback(error)
        }
    }

    private object Fallbacks {
        fun geoIp(error: Throwable): CategoryResult = CategoryResult(
            name = "GeoIP",
            detected = false,
            findings = listOf(Finding(error.message ?: error::class.java.simpleName, isError = true)),
            geoFacts = GeoIpFacts(fetchError = true),
        )
        fun ipComparison(context: Context, error: Throwable): IpComparisonResult = IpComparisonResult(
            detected = false,
            needsReview = true,
            hasError = true,
            summary = error.message ?: error::class.java.simpleName,
            ruGroup = IpCheckerGroupResult(
                title = context.getString(R.string.checker_ip_comp_ru_checkers),
                detected = false, statusLabel = "", summary = "", responses = emptyList(),
            ),
            nonRuGroup = IpCheckerGroupResult(
                title = context.getString(R.string.checker_ip_comp_non_ru_checkers),
                detected = false, statusLabel = "", summary = "", responses = emptyList(),
            ),
        )
        fun cdn(error: Throwable): CdnPullingResult = CdnPullingResult(
            detected = false,
            needsReview = true,
            hasError = true,
            summary = error.message ?: error::class.java.simpleName,
            findings = listOf(Finding(error.message ?: error::class.java.simpleName, isError = true)),
        )
        fun probe(error: Throwable): UnderlyingNetworkProber.ProbeResult =
            UnderlyingNetworkProber.ProbeResult(
                vpnActive = false,
                vpnError = error.message,
            )
        fun icmp(context: Context, error: Throwable): CategoryResult = CategoryResult(
            name = context.getString(R.string.main_card_icmp_spoofing),
            detected = false,
            findings = listOf(
                Finding(
                    context.getString(R.string.checker_icmp_summary_unavailable),
                    isInformational = true,
                ),
                Finding(
                    error.message ?: error::class.java.simpleName,
                    isError = true,
                    source = EvidenceSource.ICMP_SPOOFING,
                ),
            ),
        )
        fun rtt(error: Throwable): CategoryResult = CategoryResult(
            name = "RTT triangulation",
            detected = false,
            needsReview = true,
            findings = listOf(
                Finding(
                    error.message ?: error::class.java.simpleName,
                    isError = true,
                    source = EvidenceSource.RTT_TRIANGULATION,
                ),
            ),
        )
        fun direct(context: Context, error: Throwable): CategoryResult = CategoryResult(
            name = context.getString(R.string.checker_direct_category_name),
            detected = false,
            needsReview = true,
            findings = listOf(Finding(error.message ?: error::class.java.simpleName, isError = true)),
        )
        fun indirect(error: Throwable): CategoryResult = CategoryResult(
            name = "Indirect",
            detected = false,
            needsReview = true,
            findings = listOf(Finding(error.message ?: error::class.java.simpleName, isError = true)),
        )
        fun location(error: Throwable): CategoryResult = CategoryResult(
            name = "Location",
            detected = false,
            findings = listOf(Finding(error.message ?: error::class.java.simpleName, isError = true)),
        )
        fun domainReachability(error: Throwable): DomainReachabilityResult = DomainReachabilityResult.empty()
        fun native(error: Throwable): CategoryResult = CategoryResult(
            name = "Native",
            detected = false,
            findings = listOf(Finding(error.message ?: error::class.java.simpleName, isError = true)),
        )
        fun bypass(error: Throwable): BypassResult = BypassResult(
            proxyEndpoint = null,
            directIp = null,
            proxyIp = null,
            xrayApiScanResult = null,
            findings = listOf(Finding(error.message ?: error::class.java.simpleName, isError = true)),
            detected = false,
            needsReview = true,
        )
    }

    private fun annotateExpectedRoamingExit(
        geoIp: CategoryResult,
        locationFacts: LocationSignalsFacts?,
    ): CategoryResult {
        val geoFacts = geoIp.geoFacts ?: return geoIp
        if (locationFacts == null) return geoIp
        if (!locationFacts.homeRoutedRoaming) return geoIp
        val mcc = locationFacts.homeSimMcc ?: return geoIp
        val profile = HomeNetworkCatalog.lookup(mcc, locationFacts.homeSimMnc) ?: return geoIp
        val reason = HomeNetworkCatalog.matchExpectedExit(
            profile = profile,
            asn = geoFacts.asn,
            isp = geoFacts.isp,
            org = geoFacts.org,
        ) ?: return geoIp
        return geoIp.copy(
            geoFacts = geoFacts.copy(
                expectedRoamingExit = true,
                expectedRoamingExitReason = reason,
            ),
        )
    }

    private fun relaxCdnPullingForHomeRoutedRoaming(result: CdnPullingResult): CdnPullingResult {
        // Home-routed roaming legitimately exposes a foreign IP in CDN trace
        // responses. The original detection still records it informationally,
        // but it must not raise needsReview when the signal is fully explained
        // by the SIM home network.
        if (!result.detected && !result.needsReview) return result
        return result.copy(
            detected = false,
            needsReview = false,
            findings = result.findings.map { finding ->
                when {
                    finding.isError -> finding.copy(needsReview = false)
                    finding.detected || finding.needsReview ->
                        finding.copy(detected = false, needsReview = false, isInformational = true)
                    else -> finding
                }
            },
        )
    }

    private fun relaxIcmpSpoofingForHomeRoutedRoaming(result: CategoryResult): CategoryResult {
        // The ICMP-spoofing checker assumes a Russian egress; with home-routed
        // roaming the egress is intentionally abroad, so blocked targets that
        // reply via ICMP cannot be treated as suspicious.
        if (!result.needsReview && result.evidence.none { it.detected }) return result
        return result.copy(
            detected = false,
            needsReview = false,
            evidence = result.evidence.map { item ->
                if (item.source == EvidenceSource.ICMP_SPOOFING && item.detected) {
                    item.copy(detected = false, confidence = EvidenceConfidence.LOW)
                } else item
            },
            findings = result.findings.map { finding ->
                if (finding.needsReview) finding.copy(detected = false, needsReview = false, isInformational = true) else finding
            },
        )
    }

    // Wraps a checker deferred so its result is published as a CheckUpdate as
    // soon as it completes, preserving the await -> throwIfCancelled -> publish
    // sequence and the null contract (no deferred -> no wrapper).
    private fun <T> CoroutineScope.publishOnReady(
        deferred: Deferred<T>?,
        executionContext: ScanExecutionContext,
        onUpdate: (suspend (CheckUpdate) -> Unit)?,
        toUpdate: (T) -> CheckUpdate,
    ): Deferred<T>? = deferred?.let { d ->
        async {
            d.await().also { result ->
                executionContext.throwIfCancelled()
                onUpdate?.invoke(toUpdate(result))
            }
        }
    }

    suspend fun run(
        context: Context,
        settings: CheckSettings = CheckSettings(),
        executionContext: ScanExecutionContext = ScanExecutionContext(),
        onUpdate: (suspend (CheckUpdate) -> Unit)? = null,
    ): CheckResult = withContext(executionContext.asCoroutineContext()) {
        WhitelistAwareDnsFailureCounter.reset()
        executionContext.throwIfCancelled()
        supervisorScope {
        val dependencies = dependenciesOverride ?: Dependencies()
        val geoIpDeferred = if (settings.networkRequestsEnabled && settings.geoIp.enabled) {
            safeAsync(fallback = { Fallbacks.geoIp(it) }) {
                dependencies.geoIpCheck(context, settings.resolverConfig, settings.geoIp)
            }
        } else null

        val ipComparisonDeferred = if (settings.networkRequestsEnabled && settings.ipComparison.enabled) {
            safeAsync(fallback = { Fallbacks.ipComparison(context, it) }) {
                dependencies.ipComparisonCheck(context, settings.resolverConfig, settings.ipComparison)
            }
        } else null

        val cdnPullingDeferred = if (settings.networkRequestsEnabled && settings.cdnPullingEnabled) {
            safeAsync(fallback = { Fallbacks.cdn(it) }) {
                // Project meduzaEnabled toggle from settings into cdnPulling config
                val effectiveCdnConfig = settings.cdnPulling.copy(
                    enabled = true,
                    meduzaEnabled = settings.cdnPullingMeduzaEnabled,
                )
                dependencies.cdnPullingCheck(context, settings.resolverConfig, effectiveCdnConfig)
            }
        } else null

        val icmpSpoofingDeferred = if (settings.networkRequestsEnabled && settings.icmpSpoofingEnabled) {
            safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.icmp(context, it) }) {
                dependencies.icmpSpoofingCheck(context, settings.resolverConfig, settings.icmpSpoofing)
            }
        } else null

        val rttTriangulationDeferred = if (settings.networkRequestsEnabled && settings.rttTriangulationEnabled) {
            safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.rtt(it) }) {
                val geoFacts = geoIpDeferred?.await()?.geoFacts
                dependencies.rttTriangulationCheck(context, settings.resolverConfig, geoFacts, settings.rttTriangulation)
            }
        } else null

        val tunInterfaceInfo = runCatching {
            dependencies.tunInterfaceInfoCollector(context)
        }.getOrElse {
            TunInterfaceInfo(
                tunInterfacePresent = false,
                tunInterfaceName = null,
                underlyingInterfaceName = null,
            )
        }

        val operatorWhitelistDeferred = if (settings.networkRequestsEnabled) {
            safeAsync<OperatorWhitelistProbeResult?>(context = Dispatchers.IO, fallback = { null }) {
                dependencies.operatorWhitelistProbe()
            }
        } else null

        val tunActiveProbeDeferred = if (settings.splitTunnelEnabled) {
            safeAsync(fallback = { Fallbacks.probe(it) }) {
                dependencies.underlyingProbe(
                    context,
                    settings.resolverConfig,
                    settings.tunProbeDebugEnabled,
                    settings.tunProbeModeOverride,
                    tunInterfaceInfo.tunInterfacePresent,
                    tunInterfaceInfo.tunInterfaceName,
                    tunInterfaceInfo.underlyingInterfaceName,
                )
            }
        } else null

        val directDeferred = if (settings.directSigns.enabled) {
            safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.direct(context, it) }) {
                dependencies.directCheck(
                    context,
                    tunActiveProbeDeferred?.await(),
                    tunInterfaceInfo.tunInterfacePresent,
                    settings.directSigns,
                )
            }
        } else null
        val indirectDeferred = if (settings.indirectSigns.enabled) {
            safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.indirect(it) }) {
                dependencies.indirectCheck(
                    context,
                    settings.networkRequestsEnabled,
                    settings.callTransportProbeEnabled,
                    settings.resolverConfig,
                    settings.indirectSigns,
                    settings.callTransport,
                )
            }
        } else null
        val locationDeferred = if (settings.locationSignals.enabled) {
            safeAsync(fallback = { Fallbacks.location(it) }) {
                dependencies.locationCheck(context, settings.networkRequestsEnabled, settings.resolverConfig, settings.locationSignals)
            }
        } else null
        val nativeDeferred = if (settings.nativeSignsEnabled) {
            safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.native(it) }) {
                dependencies.nativeCheck(context)
            }
        } else null
        val domainReachabilityDeferred = if (settings.domainReachabilityEnabled && settings.reachabilityDomains.isNotEmpty()) {
            safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.domainReachability(it) }) {
                dependencies.domainReachabilityCheck(context, settings.reachabilityDomains, settings.resolverConfig)
            }
        } else null
        val bypassEnabled = settings.splitTunnelEnabled
        val bypassDeferred = if (bypassEnabled) {
            safeAsync(fallback = { Fallbacks.bypass(it) }) {
                dependencies.bypassCheck(
                    context,
                    settings.resolverConfig,
                    settings.splitTunnelEnabled,
                    settings.proxyScanEnabled,
                    settings.proxyAuthProbeEnabled,
                    settings.xrayApiScanEnabled,
                    settings.clashApiScanEnabled,
                    settings.portRange,
                    settings.portRangeStart,
                    settings.portRangeEnd,
                    settings.splitTunnelConnectTimeoutMs,
                    settings.splitTunnelCheckUnderlyingNetwork,
                    settings.splitTunnelCheckVpnNetworkBinding,
                    settings.splitTunnelCheckMtprotoViaProxy,
                    tunActiveProbeDeferred,
                    { progress ->
                        executionContext.throwIfCancelled()
                        onUpdate?.invoke(CheckUpdate.BypassProgress(progress))
                    },
                )
            }
        } else null

        val geoIpReadyDeferred = publishOnReady(geoIpDeferred, executionContext, onUpdate, CheckUpdate::GeoIpReady)
        val ipComparisonReadyDeferred = publishOnReady(ipComparisonDeferred, executionContext, onUpdate, CheckUpdate::IpComparisonReady)
        val cdnPullingReadyDeferred = publishOnReady(cdnPullingDeferred, executionContext, onUpdate, CheckUpdate::CdnPullingReady)
        val icmpSpoofingReadyDeferred = publishOnReady(icmpSpoofingDeferred, executionContext, onUpdate, CheckUpdate::IcmpSpoofingReady)
        val rttTriangulationReadyDeferred = publishOnReady(rttTriangulationDeferred, executionContext, onUpdate, CheckUpdate::RttTriangulationReady)
        val directReadyDeferred = publishOnReady(directDeferred, executionContext, onUpdate, CheckUpdate::DirectSignsReady)
        val indirectReadyDeferred = publishOnReady(indirectDeferred, executionContext, onUpdate, CheckUpdate::IndirectSignsReady)
        val locationReadyDeferred = publishOnReady(locationDeferred, executionContext, onUpdate, CheckUpdate::LocationSignalsReady)
        val nativeReadyDeferred = publishOnReady(nativeDeferred, executionContext, onUpdate, CheckUpdate::NativeSignsReady)
        val domainReachabilityReadyDeferred = publishOnReady(domainReachabilityDeferred, executionContext, onUpdate, CheckUpdate::DomainReachabilityReady)
        val bypassReadyDeferred = publishOnReady(bypassDeferred, executionContext, onUpdate, CheckUpdate::BypassReady)

        val emptyGeoIpCategory = CategoryResult(name = "GeoIP", detected = false, findings = emptyList())
        val emptyIpComparison = IpComparisonResult(
            detected = false,
            summary = "",
            ruGroup = IpCheckerGroupResult(
                title = context.getString(R.string.checker_ip_comp_ru_checkers),
                detected = false,
                statusLabel = "",
                summary = "",
                responses = emptyList(),
            ),
            nonRuGroup = IpCheckerGroupResult(
                title = context.getString(R.string.checker_ip_comp_non_ru_checkers),
                detected = false,
                statusLabel = "",
                summary = "",
                responses = emptyList(),
            ),
        )
        val emptyCdnPulling = CdnPullingResult.empty()
        val emptyIcmpSpoofing = CategoryResult(
            name = context.getString(R.string.main_card_icmp_spoofing),
            detected = false,
            findings = emptyList(),
        )
        val emptyRttTriangulation = CategoryResult(
            name = context.getString(R.string.main_card_rtt_triangulation),
            detected = false,
            findings = emptyList(),
        )
        val emptyBypass = BypassResult(
            proxyEndpoint = null,
            proxyOwner = null,
            directIp = null,
            proxyIp = null,
            vpnNetworkIp = null,
            underlyingIp = null,
            xrayApiScanResult = null,
            findings = emptyList(),
            detected = false,
        )

        val emptyDirect = CategoryResult(
            name = context.getString(R.string.checker_direct_category_name),
            detected = false,
            findings = emptyList(),
        )
        val emptyIndirect = CategoryResult(
            name = "Indirect",
            detected = false,
            findings = emptyList(),
        )
        val emptyLocation = CategoryResult(
            name = "Location",
            detected = false,
            findings = emptyList(),
        )
        val emptyNative = CategoryResult(
            name = "Native",
            detected = false,
            findings = emptyList(),
        )

        val rawGeoIp = geoIpReadyDeferred?.await() ?: emptyGeoIpCategory
        val ipComparison = ipComparisonReadyDeferred?.await() ?: emptyIpComparison
        val rawCdnPulling = cdnPullingReadyDeferred?.await() ?: emptyCdnPulling
        val rawIcmpSpoofing = icmpSpoofingReadyDeferred?.await() ?: emptyIcmpSpoofing
        val rttTriangulation = rttTriangulationReadyDeferred?.await() ?: emptyRttTriangulation
        val directSigns = directReadyDeferred?.await() ?: emptyDirect
        val indirectSigns = indirectReadyDeferred?.await() ?: emptyIndirect
        val locationSignals = locationReadyDeferred?.await() ?: emptyLocation
        val nativeSigns = nativeReadyDeferred?.await() ?: emptyNative
        val bypassResult = bypassReadyDeferred?.await() ?: emptyBypass
        val domainReachability = domainReachabilityReadyDeferred?.await() ?: DomainReachabilityResult.empty()
        val tunProbeResult = tunActiveProbeDeferred?.await()

        // Cross-checker reconciliation: when the SIM home network is foreign
        // and the visited network is in Russia, the ISP-level egress will
        // legitimately appear abroad. Try to confirm via ASN match against
        // GeoIP to suppress false positives in CDN/ICMP/GeoIP categories.
        val geoIp = annotateExpectedRoamingExit(rawGeoIp, locationSignals.locationFacts)
        val homeRoutedRoaming = locationSignals.locationFacts?.homeRoutedRoaming == true
        val cdnPulling = if (homeRoutedRoaming) {
            relaxCdnPullingForHomeRoutedRoaming(rawCdnPulling)
        } else rawCdnPulling
        val icmpSpoofing = if (homeRoutedRoaming) {
            relaxIcmpSpoofingForHomeRoutedRoaming(rawIcmpSpoofing)
        } else rawIcmpSpoofing

        val ipConsensus = runCatching {
            IpConsensusBuilder.build(
                geoIp = geoIp,
                ipComparison = ipComparison,
                cdnPulling = cdnPulling,
                tunProbe = tunProbeResult,
                bypass = bypassResult,
                callTransportLeaks = indirectSigns.callTransportLeaks,
                asnResolver = AsnResolver.default(settings.resolverConfig),
            )
        }.getOrElse { IpConsensusResult.empty(needsReview = true) }

        executionContext.throwIfCancelled()
        onUpdate?.invoke(CheckUpdate.IpConsensusReady(ipConsensus))

        executionContext.throwIfCancelled()
        val verdict = VerdictEngine.evaluate(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
            ipConsensus = ipConsensus,
            nativeSigns = nativeSigns,
            icmpSpoofing = icmpSpoofing,
            geoCheckAvailable = settings.networkRequestsEnabled,
        )
        executionContext.throwIfCancelled()
        onUpdate?.invoke(CheckUpdate.VerdictReady(verdict))

        val operatorWhitelistResult = operatorWhitelistDeferred?.await()

        CheckResult(
            geoIp = geoIp,
            ipComparison = ipComparison,
            cdnPulling = cdnPulling,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
            verdict = verdict,
            tunProbeDiagnostics = tunProbeResult?.tunProbeDiagnostics,
            nativeSigns = nativeSigns,
            icmpSpoofing = icmpSpoofing,
            rttTriangulation = rttTriangulation,
            ipConsensus = ipConsensus,
            operatorWhitelistProbe = operatorWhitelistResult,
            domainReachability = domainReachability,
        )
    }
}
}
