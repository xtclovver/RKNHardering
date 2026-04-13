package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

data class CheckSettings(
    val splitTunnelEnabled: Boolean = true,
    val networkRequestsEnabled: Boolean = true,
    val callTransportProbeEnabled: Boolean = false,
    val resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    val portRange: String = "full",
    val portRangeStart: Int = 1024,
    val portRangeEnd: Int = 65535,
)

sealed interface CheckUpdate {
    data class GeoIpReady(val result: CategoryResult) : CheckUpdate
    data class IpComparisonReady(val result: IpComparisonResult) : CheckUpdate
    data class DirectSignsReady(val result: CategoryResult) : CheckUpdate
    data class IndirectSignsReady(val result: CategoryResult) : CheckUpdate
    data class LocationSignalsReady(val result: CategoryResult) : CheckUpdate
    data class BypassProgress(val progress: BypassChecker.Progress) : CheckUpdate
    data class BypassReady(val result: BypassResult) : CheckUpdate
    data class VerdictReady(val verdict: Verdict) : CheckUpdate
}

object VpnCheckRunner {

    suspend fun run(
        context: Context,
        settings: CheckSettings = CheckSettings(),
        onUpdate: (suspend (CheckUpdate) -> Unit)? = null,
    ): CheckResult = coroutineScope {
        val geoIpDeferred = if (settings.networkRequestsEnabled) {
            async { GeoIpChecker.check(context, settings.resolverConfig) }
        } else null

        val ipComparisonDeferred = if (settings.networkRequestsEnabled) {
            async { IpComparisonChecker.check(context, resolverConfig = settings.resolverConfig) }
        } else null

        val directDeferred = async { DirectSignsChecker.check(context) }
        val indirectDeferred = async { IndirectSignsChecker.check(context) }
        val locationDeferred = async {
            LocationSignalsChecker.check(
                context,
                networkRequestsEnabled = settings.networkRequestsEnabled,
                resolverConfig = settings.resolverConfig,
            )
        }
        val bypassEnabled = settings.splitTunnelEnabled ||
            (settings.networkRequestsEnabled && settings.callTransportProbeEnabled)
        val bypassDeferred = if (bypassEnabled) {
            async {
                BypassChecker.check(
                    context = context,
                    resolverConfig = settings.resolverConfig,
                    splitTunnelEnabled = settings.splitTunnelEnabled,
                    callTransportProbeEnabled = settings.networkRequestsEnabled && settings.callTransportProbeEnabled,
                    portRange = settings.portRange,
                    portRangeStart = settings.portRangeStart,
                    portRangeEnd = settings.portRangeEnd,
                    onProgress = { progress ->
                        onUpdate?.invoke(CheckUpdate.BypassProgress(progress))
                    },
                )
            }
        } else null

        val geoIpReadyDeferred = geoIpDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
                    onUpdate?.invoke(CheckUpdate.GeoIpReady(result))
                }
            }
        }
        val ipComparisonReadyDeferred = ipComparisonDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
                    onUpdate?.invoke(CheckUpdate.IpComparisonReady(result))
                }
            }
        }
        val directReadyDeferred = async {
            directDeferred.await().also { result ->
                onUpdate?.invoke(CheckUpdate.DirectSignsReady(result))
            }
        }
        val indirectReadyDeferred = async {
            indirectDeferred.await().also { result ->
                onUpdate?.invoke(CheckUpdate.IndirectSignsReady(result))
            }
        }
        val locationReadyDeferred = async {
            locationDeferred.await().also { result ->
                onUpdate?.invoke(CheckUpdate.LocationSignalsReady(result))
            }
        }
        val bypassReadyDeferred = bypassDeferred?.let { deferred ->
            async {
                deferred.await().also { result ->
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
        val emptyBypass = BypassResult(
            proxyEndpoint = null,
            proxyOwner = null,
            directIp = null,
            proxyIp = null,
            vpnNetworkIp = null,
            underlyingIp = null,
            xrayApiScanResult = null,
            callTransportLeaks = emptyList(),
            findings = emptyList(),
            detected = false,
        )

        val geoIp = geoIpReadyDeferred?.await() ?: emptyGeoIpCategory
        val ipComparison = ipComparisonReadyDeferred?.await() ?: emptyIpComparison
        val directSigns = directReadyDeferred.await()
        val indirectSigns = indirectReadyDeferred.await()
        val locationSignals = locationReadyDeferred.await()
        val bypassResult = bypassReadyDeferred?.await() ?: emptyBypass

        val verdict = VerdictEngine.evaluate(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
        )
        onUpdate?.invoke(CheckUpdate.VerdictReady(verdict))

        CheckResult(
            geoIp = geoIp,
            ipComparison = ipComparison,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
            verdict = verdict,
        )
    }
}
