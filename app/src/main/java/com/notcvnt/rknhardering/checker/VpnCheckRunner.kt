package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

data class CheckSettings(
    val splitTunnelEnabled: Boolean = true,
    val networkRequestsEnabled: Boolean = true,
    val portRange: String = "full",
    val portRangeStart: Int = 1024,
    val portRangeEnd: Int = 65535,
)

object VpnCheckRunner {

    suspend fun run(
        context: Context,
        settings: CheckSettings = CheckSettings(),
        onBypassProgress: (suspend (BypassChecker.Progress) -> Unit)? = null,
    ): CheckResult = coroutineScope {
        val geoIpDeferred = if (settings.networkRequestsEnabled) {
            async { GeoIpChecker.check() }
        } else null

        val ipComparisonDeferred = if (settings.networkRequestsEnabled) {
            async { IpComparisonChecker.check() }
        } else null

        val directDeferred = async { DirectSignsChecker.check(context) }
        val indirectDeferred = async { IndirectSignsChecker.check(context) }
        val locationDeferred = async {
            LocationSignalsChecker.check(context, networkRequestsEnabled = settings.networkRequestsEnabled)
        }
        val bypassDeferred = if (settings.splitTunnelEnabled) {
            async {
                BypassChecker.check(
                    context = context,
                    portRange = settings.portRange,
                    portRangeStart = settings.portRangeStart,
                    portRangeEnd = settings.portRangeEnd,
                    onProgress = onBypassProgress,
                )
            }
        } else null

        val emptyGeoIpCategory = CategoryResult(name = "GeoIP", detected = false, findings = emptyList())
        val emptyIpComparison = IpComparisonResult(
            detected = false,
            summary = "",
            ruGroup = IpCheckerGroupResult(
                title = "RU-чекеры",
                detected = false,
                statusLabel = "",
                summary = "",
                responses = emptyList(),
            ),
            nonRuGroup = IpCheckerGroupResult(
                title = "Не-RU чекеры",
                detected = false,
                statusLabel = "",
                summary = "",
                responses = emptyList(),
            ),
        )
        val emptyBypass = BypassResult(
            proxyEndpoint = null,
            directIp = null,
            proxyIp = null,
            xrayApiScanResult = null,
            findings = emptyList(),
            detected = false,
        )

        val geoIp = geoIpDeferred?.await() ?: emptyGeoIpCategory
        val ipComparison = ipComparisonDeferred?.await() ?: emptyIpComparison
        val directSigns = directDeferred.await()
        val indirectSigns = indirectDeferred.await()
        val locationSignals = locationDeferred.await()
        val bypassResult = bypassDeferred?.await() ?: emptyBypass

        val verdict = VerdictEngine.evaluate(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
        )

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
