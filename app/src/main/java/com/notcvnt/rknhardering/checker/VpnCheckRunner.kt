package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.model.CheckResult
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

object VpnCheckRunner {

    suspend fun run(
        context: Context,
        onBypassProgress: (suspend (BypassChecker.Progress) -> Unit)? = null,
    ): CheckResult = coroutineScope {
        val geoIpDeferred = async { GeoIpChecker.check() }
        val directDeferred = async { DirectSignsChecker.check(context) }
        val indirectDeferred = async { IndirectSignsChecker.check(context) }
        val locationDeferred = async { LocationSignalsChecker.check(context) }
        val bypassDeferred = async { BypassChecker.check(context = context, onProgress = onBypassProgress) }

        val geoIp = geoIpDeferred.await()
        val directSigns = directDeferred.await()
        val indirectSigns = indirectDeferred.await()
        val locationSignals = locationDeferred.await()
        val bypassResult = bypassDeferred.await()

        val verdict = VerdictEngine.evaluate(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
        )

        CheckResult(
            geoIp = geoIp,
            directSigns = directSigns,
            indirectSigns = indirectSigns,
            locationSignals = locationSignals,
            bypassResult = bypassResult,
            verdict = verdict,
        )
    }
}
