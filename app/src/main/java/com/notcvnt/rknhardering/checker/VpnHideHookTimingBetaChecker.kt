package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.BetaProbeRowParser
import com.notcvnt.rknhardering.probe.NativeSignsBridge
import com.notcvnt.rknhardering.probe.ParsedBetaProbeRow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

internal object VpnHideHookTimingBetaChecker {
    private const val KOTLIN_DEADLINE_MS = 1_000L
    private const val LIBC_CHECK = "vpnhide_hook_timing.libc"
    private const val KERNEL_CHECK = "vpnhide_hook_timing.kernel"

    suspend fun check(
        context: Context,
        observedAtElapsedMs: Long,
        executionContext: ScanExecutionContext,
    ): List<BetaObservation> {
        executionContext.throwIfCancelled()
        NativeSignsBridge.initIfNeeded()
        if (!NativeSignsBridge.isLibraryLoaded()) {
            return listOf(
                observation(context, LIBC_CHECK, unavailable(LIBC_CHECK), observedAtElapsedMs),
                observation(context, KERNEL_CHECK, unavailable(KERNEL_CHECK), observedAtElapsedMs),
            )
        }
        val rows = withTimeoutOrNull(KOTLIN_DEADLINE_MS) {
            withContext(Dispatchers.IO) {
                NativeSignsBridge.betaHookTimingProbe(executionContext.cancellationSignal)
            }
        }
        executionContext.throwIfCancelled()
        if (rows == null) {
            return listOf(
                observation(context, LIBC_CHECK, timeout(LIBC_CHECK), observedAtElapsedMs),
                observation(context, KERNEL_CHECK, timeout(KERNEL_CHECK), observedAtElapsedMs),
            )
        }
        return listOf(
            observation(context, LIBC_CHECK, BetaProbeRowParser.parse(rows, LIBC_CHECK), observedAtElapsedMs),
            observation(context, KERNEL_CHECK, BetaProbeRowParser.parse(rows, KERNEL_CHECK), observedAtElapsedMs),
        )
    }

    internal fun observation(
        context: Context,
        check: String,
        parsed: ParsedBetaProbeRow,
        observedAtElapsedMs: Long,
    ): BetaObservation {
        val timing = parsed.fields.strictBoolean("timing_anomaly")
        val semantic = parsed.fields.strictBoolean("semantic_mismatch")
        val corroborated = parsed.fields.strictBoolean("corroborated")
        val counterFrequency = parsed.fields["counter_hz"]?.toLongOrNull()
        val validPairs = parsed.fields["valid_pairs"]?.toIntOrNull()
        val fullBatches = parsed.fields["full_batches"]?.toIntOrNull()
        val cpuMigrations = parsed.fields["cpu_migrations"]?.toIntOrNull()
        val medianTicks = parsed.fields["median_ticks"]?.toLongOrNull()
        val madTicks = parsed.fields["mad_ticks"]?.toLongOrNull()
        val ratioMilli = parsed.fields["ratio_milli"]?.toLongOrNull()
        val aggregatesComplete = counterFrequency != null && counterFrequency > 0 &&
            validPairs != null && validPairs in 384..640 &&
            fullBatches != null && fullBatches in 3..5 &&
            cpuMigrations != null && cpuMigrations >= 0 &&
            medianTicks != null && medianTicks >= 0 &&
            madTicks != null && madTicks >= 0 &&
            ratioMilli != null && ratioMilli >= 0
        val availability = if (parsed.fields["reason"].isNullOrBlank()) {
            ProbeAvailability.MALFORMED_RESPONSE
        } else if (
            parsed.availability == ProbeAvailability.AVAILABLE &&
            (timing == null || semantic == null || corroborated == null || !aggregatesComplete ||
                (corroborated && !(timing && semantic)))
        ) {
            ProbeAvailability.MALFORMED_RESPONSE
        } else {
            parsed.availability
        }
        val confirmed = availability == ProbeAvailability.AVAILABLE && corroborated == true
        val summary = when {
            confirmed -> context.getString(com.notcvnt.rknhardering.R.string.beta_hook_timing_corroborated)
            availability == ProbeAvailability.UNSUPPORTED ->
                context.getString(com.notcvnt.rknhardering.R.string.beta_hook_timing_unsupported)
            availability != ProbeAvailability.AVAILABLE ->
                context.getString(com.notcvnt.rknhardering.R.string.beta_hook_timing_inconclusive)
            timing == true -> context.getString(com.notcvnt.rknhardering.R.string.beta_hook_timing_only)
            semantic == true -> context.getString(com.notcvnt.rknhardering.R.string.beta_hook_semantic_only)
            else -> context.getString(com.notcvnt.rknhardering.R.string.beta_hook_timing_not_confirmed)
        }
        return BetaObservation(
            checkId = "beta.$check",
            source = EvidenceSource.BETA_HOOK_TIMING,
            availability = availability,
            polarity = if (confirmed) ObservationPolarity.POSITIVE else ObservationPolarity.INCONCLUSIVE,
            authority = if (check == LIBC_CHECK) {
                ObservationAuthority.LIBC_OR_PRIVATE_LIBRARY
            } else {
                ObservationAuthority.KERNEL_QUERY
            },
            confidence = if (confirmed) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
            independenceGroup = "hook_consistency",
            detectionDomain = DetectionDomain.HOOK_OR_TAMPERING,
            facts = buildMap {
                put("summary", summary)
                parsed.fields["reason"]?.let { put("reason", it) }
                listOf(
                    "counter_hz", "valid_pairs", "full_batches", "cpu_migrations",
                    "median_ticks", "mad_ticks", "ratio_milli", "timing_anomaly",
                    "semantic_mismatch", "corroborated",
                ).forEach { key -> parsed.fields[key]?.let { put(key, it) } }
            },
            observedAtElapsedMs = observedAtElapsedMs,
            networkEpochId = null,
        )
    }

    private fun Map<String, String>.strictBoolean(key: String): Boolean? = when (this[key]) {
        "true" -> true
        "false" -> false
        else -> null
    }

    private fun unavailable(checkId: String) =
        ParsedBetaProbeRow(checkId, ProbeAvailability.UNAVAILABLE, mapOf("reason" to "native_library_unavailable"))

    private fun timeout(checkId: String) =
        ParsedBetaProbeRow(checkId, ProbeAvailability.TRUNCATED, mapOf("reason" to "timeout"))
}
