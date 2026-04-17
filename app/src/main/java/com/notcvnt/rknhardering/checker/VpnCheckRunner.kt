package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.TunProbeModeOverride
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext

data class CheckSettings(
    val splitTunnelEnabled: Boolean = true,
    val proxyScanEnabled: Boolean = true,
    val xrayApiScanEnabled: Boolean = true,
    val networkRequestsEnabled: Boolean = true,
    val callTransportProbeEnabled: Boolean = false,
    val cdnPullingEnabled: Boolean = false,
    val cdnPullingMeduzaEnabled: Boolean = true,
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
    data class DirectSignsReady(val result: CategoryResult) : CheckUpdate
    data class IndirectSignsReady(val result: CategoryResult) : CheckUpdate
    data class LocationSignalsReady(val result: CategoryResult) : CheckUpdate
    data class BypassProgress(val progress: BypassChecker.Progress) : CheckUpdate
    data class BypassReady(val result: BypassResult) : CheckUpdate
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
        val underlyingProbe: suspend (
            Context,
            DnsResolverConfig,
            Boolean,
            TunProbeModeOverride,
        ) -> UnderlyingNetworkProber.ProbeResult =
            { ctx, resolverConfig, debugEnabled, modeOverride ->
                UnderlyingNetworkProber.probe(
                    context = ctx,
                    resolverConfig = resolverConfig,
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                )
            },
        val directCheck: suspend (Context, UnderlyingNetworkProber.ProbeResult?) -> CategoryResult =
            { ctx, tunActiveProbeResult -> DirectSignsChecker.check(ctx, tunActiveProbeResult = tunActiveProbeResult) },
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

    suspend fun run(
        context: Context,
        settings: CheckSettings = CheckSettings(),
        executionContext: ScanExecutionContext = ScanExecutionContext(),
        onUpdate: (suspend (CheckUpdate) -> Unit)? = null,
    ): CheckResult = withContext(executionContext.asCoroutineContext()) {
        executionContext.throwIfCancelled()
        coroutineScope {
        val dependencies = dependenciesOverride ?: Dependencies()
        val geoIpDeferred = if (settings.networkRequestsEnabled) {
            async { dependencies.geoIpCheck(context, settings.resolverConfig) }
        } else null

        val ipComparisonDeferred = if (settings.networkRequestsEnabled) {
            async { dependencies.ipComparisonCheck(context, settings.resolverConfig) }
        } else null

        val cdnPullingDeferred = if (settings.networkRequestsEnabled && settings.cdnPullingEnabled) {
            async { dependencies.cdnPullingCheck(context, settings.resolverConfig, settings.cdnPullingMeduzaEnabled) }
        } else null

        val tunActiveProbeDeferred = if (settings.splitTunnelEnabled) {
            async {
                dependencies.underlyingProbe(
                    context,
                    settings.resolverConfig,
                    settings.tunProbeDebugEnabled,
                    settings.tunProbeModeOverride,
                )
            }
        } else null

        val directDeferred = async {
            dependencies.directCheck(
                context,
                tunActiveProbeDeferred?.await(),
            )
        }
        val indirectDeferred = async(Dispatchers.IO) {
            dependencies.indirectCheck(
                context,
                settings.networkRequestsEnabled,
                settings.callTransportProbeEnabled,
                settings.resolverConfig,
            )
        }
        val locationDeferred = async {
            dependencies.locationCheck(context, settings.networkRequestsEnabled, settings.resolverConfig)
        }
        val bypassEnabled = settings.splitTunnelEnabled
        val bypassDeferred = if (bypassEnabled) {
            async {
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

        val geoIp = geoIpReadyDeferred?.await() ?: emptyGeoIpCategory
        val ipComparison = ipComparisonReadyDeferred?.await() ?: emptyIpComparison
        val cdnPulling = cdnPullingReadyDeferred?.await() ?: emptyCdnPulling
        val directSigns = directReadyDeferred.await()
        val indirectSigns = indirectReadyDeferred.await()
        val locationSignals = locationReadyDeferred.await()
        val bypassResult = bypassReadyDeferred?.await() ?: emptyBypass
        val tunProbeResult = tunActiveProbeDeferred?.await()

        executionContext.throwIfCancelled()
        val verdict = VerdictEngine.evaluate(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
        )
        executionContext.throwIfCancelled()
        onUpdate?.invoke(CheckUpdate.VerdictReady(verdict))

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
        )
    }
    }
}
