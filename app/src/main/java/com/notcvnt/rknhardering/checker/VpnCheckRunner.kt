package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.checker.ipconsensus.AsnResolver
import com.notcvnt.rknhardering.checker.ipconsensus.IpConsensusBuilder
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
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
    val xrayApiScanEnabled: Boolean = true,
    val networkRequestsEnabled: Boolean = true,
    val callTransportProbeEnabled: Boolean = false,
    val cdnPullingEnabled: Boolean = false,
    val cdnPullingMeduzaEnabled: Boolean = true,
    val icmpSpoofingEnabled: Boolean = true,
    val rttTriangulationEnabled: Boolean = false,
    val tunProbeDebugEnabled: Boolean = false,
    val tunProbeModeOverride: TunProbeModeOverride = TunProbeModeOverride.AUTO,
    val resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    val portRange: String = "full",
    val portRangeStart: Int = 1024,
    val portRangeEnd: Int = 65535,
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
    data class VerdictReady(val verdict: Verdict) : CheckUpdate
}

object VpnCheckRunner {

    internal data class Dependencies(
        val geoIpCheck: suspend (Context, DnsResolverConfig) -> CategoryResult =
            { ctx, resolverConfig -> GeoIpChecker.check(ctx, resolverConfig) },
        val ipComparisonCheck: suspend (Context, DnsResolverConfig) -> IpComparisonResult =
            { ctx, resolverConfig -> IpComparisonChecker.check(ctx, resolverConfig = resolverConfig) },
        val cdnPullingCheck: suspend (Context, DnsResolverConfig, Boolean) -> CdnPullingResult =
            { ctx, resolverConfig, meduzaEnabled -> CdnPullingChecker.check(ctx, resolverConfig = resolverConfig, meduzaEnabled = meduzaEnabled) },
        val icmpSpoofingCheck: suspend (Context, DnsResolverConfig) -> CategoryResult =
            { ctx, resolverConfig -> IcmpSpoofingChecker.check(ctx, resolverConfig) },
        val rttTriangulationCheck: suspend (Context, DnsResolverConfig, GeoIpFacts?) -> CategoryResult =
            { ctx, cfg, geo -> RttTriangulationChecker.check(ctx, cfg, geo) },
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
        val directCheck: suspend (Context, UnderlyingNetworkProber.ProbeResult?, Boolean) -> CategoryResult =
            { ctx, tunActiveProbeResult, tunInterfacePresent ->
                DirectSignsChecker.check(
                    ctx,
                    tunActiveProbeResult = tunActiveProbeResult,
                    tunInterfacePresent = tunInterfacePresent,
                )
            },
        val tunInterfaceInfoCollector: (Context) -> TunInterfaceInfo =
            { ctx -> IndirectSignsChecker.collectTunInterfaceInfo(ctx) },
        val operatorWhitelistProbe: suspend () -> OperatorWhitelistProbeResult =
            { OperatorWhitelistProbe.probe() },
        val indirectCheck: suspend (Context, Boolean, Boolean, DnsResolverConfig) -> CategoryResult =
            { ctx, networkRequestsEnabled, callTransportProbeEnabled, resolverConfig ->
                IndirectSignsChecker.check(
                    context = ctx,
                    networkRequestsEnabled = networkRequestsEnabled,
                    callTransportProbeEnabled = callTransportProbeEnabled,
                    resolverConfig = resolverConfig,
                )
            },
        val locationCheck: suspend (Context, Boolean, DnsResolverConfig) -> CategoryResult =
            { ctx, networkRequestsEnabled, resolverConfig ->
                LocationSignalsChecker.check(
                    ctx,
                    networkRequestsEnabled = networkRequestsEnabled,
                    resolverConfig = resolverConfig,
                )
            },
        val nativeCheck: suspend (Context) -> CategoryResult =
            { ctx -> NativeSignsChecker.check(ctx) },
        val bypassCheck: suspend (
            Context,
            DnsResolverConfig,
            Boolean,
            Boolean,
            Boolean,
            String,
            Int,
            Int,
            kotlinx.coroutines.Deferred<UnderlyingNetworkProber.ProbeResult>?,
            (suspend (BypassChecker.Progress) -> Unit)?,
        ) -> BypassResult =
            { ctx, resolverConfig, splitTunnelEnabled, proxyScanEnabled, xrayApiScanEnabled, portRange, portRangeStart, portRangeEnd, underlyingProbeDeferred, onProgress ->
                BypassChecker.check(
                    ctx,
                    resolverConfig,
                    splitTunnelEnabled,
                    proxyScanEnabled,
                    xrayApiScanEnabled,
                    portRange,
                    portRangeStart,
                    portRangeEnd,
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
        val geoIpDeferred = if (settings.networkRequestsEnabled) {
            safeAsync(fallback = { Fallbacks.geoIp(it) }) {
                dependencies.geoIpCheck(context, settings.resolverConfig)
            }
        } else null

        val ipComparisonDeferred = if (settings.networkRequestsEnabled) {
            safeAsync(fallback = { Fallbacks.ipComparison(context, it) }) {
                dependencies.ipComparisonCheck(context, settings.resolverConfig)
            }
        } else null

        val cdnPullingDeferred = if (settings.networkRequestsEnabled && settings.cdnPullingEnabled) {
            safeAsync(fallback = { Fallbacks.cdn(it) }) {
                dependencies.cdnPullingCheck(context, settings.resolverConfig, settings.cdnPullingMeduzaEnabled)
            }
        } else null

        val icmpSpoofingDeferred = if (settings.networkRequestsEnabled && settings.icmpSpoofingEnabled) {
            safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.icmp(context, it) }) {
                dependencies.icmpSpoofingCheck(context, settings.resolverConfig)
            }
        } else null

        val rttTriangulationDeferred = if (settings.networkRequestsEnabled && settings.rttTriangulationEnabled) {
            safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.rtt(it) }) {
                val geoFacts = geoIpDeferred?.await()?.geoFacts
                dependencies.rttTriangulationCheck(context, settings.resolverConfig, geoFacts)
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
            safeAsync<OperatorWhitelistProbeResult?>(fallback = { null }) {
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

        val directDeferred = safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.direct(context, it) }) {
            dependencies.directCheck(
                context,
                tunActiveProbeDeferred?.await(),
                tunInterfaceInfo.tunInterfacePresent,
            )
        }
        val indirectDeferred = safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.indirect(it) }) {
            dependencies.indirectCheck(
                context,
                settings.networkRequestsEnabled,
                settings.callTransportProbeEnabled,
                settings.resolverConfig,
            )
        }
        val locationDeferred = safeAsync(fallback = { Fallbacks.location(it) }) {
            dependencies.locationCheck(context, settings.networkRequestsEnabled, settings.resolverConfig)
        }
        val nativeDeferred = safeAsync(context = Dispatchers.IO, fallback = { Fallbacks.native(it) }) {
            dependencies.nativeCheck(context)
        }
        val bypassEnabled = settings.splitTunnelEnabled
        val bypassDeferred = if (bypassEnabled) {
            safeAsync(fallback = { Fallbacks.bypass(it) }) {
                dependencies.bypassCheck(
                    context,
                    settings.resolverConfig,
                    settings.splitTunnelEnabled,
                    settings.proxyScanEnabled,
                    settings.xrayApiScanEnabled,
                    settings.portRange,
                    settings.portRangeStart,
                    settings.portRangeEnd,
                    tunActiveProbeDeferred,
                    { progress ->
                        executionContext.throwIfCancelled()
                        onUpdate?.invoke(CheckUpdate.BypassProgress(progress))
                    },
                )
            }
        } else null

        val geoIpReadyDeferred = geoIpDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
                    executionContext.throwIfCancelled()
                    onUpdate?.invoke(CheckUpdate.GeoIpReady(result))
                }
            }
        }
        val ipComparisonReadyDeferred = ipComparisonDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
                    executionContext.throwIfCancelled()
                    onUpdate?.invoke(CheckUpdate.IpComparisonReady(result))
                }
            }
        }
        val cdnPullingReadyDeferred = cdnPullingDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
                    executionContext.throwIfCancelled()
                    onUpdate?.invoke(CheckUpdate.CdnPullingReady(result))
                }
            }
        }
        val icmpSpoofingReadyDeferred = icmpSpoofingDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
                    executionContext.throwIfCancelled()
                    onUpdate?.invoke(CheckUpdate.IcmpSpoofingReady(result))
                }
            }
        }
        val rttTriangulationReadyDeferred = rttTriangulationDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
                    executionContext.throwIfCancelled()
                    onUpdate?.invoke(CheckUpdate.RttTriangulationReady(result))
                }
            }
        }
        val directReadyDeferred = async {
            directDeferred.await().also { result ->
                executionContext.throwIfCancelled()
                onUpdate?.invoke(CheckUpdate.DirectSignsReady(result))
            }
        }
        val indirectReadyDeferred = async {
            indirectDeferred.await().also { result ->
                executionContext.throwIfCancelled()
                onUpdate?.invoke(CheckUpdate.IndirectSignsReady(result))
            }
        }
        val locationReadyDeferred = async {
            locationDeferred.await().also { result ->
                executionContext.throwIfCancelled()
                onUpdate?.invoke(CheckUpdate.LocationSignalsReady(result))
            }
        }
        val nativeReadyDeferred = async {
            nativeDeferred.await().also { result ->
                executionContext.throwIfCancelled()
                onUpdate?.invoke(CheckUpdate.NativeSignsReady(result))
            }
        }
        val bypassReadyDeferred = bypassDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
                    executionContext.throwIfCancelled()
                    onUpdate?.invoke(CheckUpdate.BypassReady(result))
                }
            }
        }

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

        val rawGeoIp = geoIpReadyDeferred?.await() ?: emptyGeoIpCategory
        val ipComparison = ipComparisonReadyDeferred?.await() ?: emptyIpComparison
        val rawCdnPulling = cdnPullingReadyDeferred?.await() ?: emptyCdnPulling
        val rawIcmpSpoofing = icmpSpoofingReadyDeferred?.await() ?: emptyIcmpSpoofing
        val rttTriangulation = rttTriangulationReadyDeferred?.await() ?: emptyRttTriangulation
        val directSigns = directReadyDeferred.await()
        val indirectSigns = indirectReadyDeferred.await()
        val locationSignals = locationReadyDeferred.await()
        val nativeSigns = nativeReadyDeferred.await()
        val bypassResult = bypassReadyDeferred?.await() ?: emptyBypass
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
        )
    }
}
}
