package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.ParsedBetaProbeRow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class VpnHideHookTimingBetaCheckerTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `timing without semantics is inconclusive low confidence`() {
        val observation = observation(timing = true, semantic = false, corroborated = false)
        val evaluated = BetaEvidencePolicy.evaluate(observation, BetaEvaluationContext(networkEpochId = null))

        assertEquals(ObservationPolarity.INCONCLUSIVE, observation.polarity)
        assertEquals(EvidenceConfidence.LOW, observation.confidence)
        assertFalse(evaluated.finding.needsReview)
        assertEquals(null, evaluated.evidence)
    }

    @Test
    fun `semantics without timing is inconclusive low confidence`() {
        val observation = observation(timing = false, semantic = true, corroborated = false)

        assertEquals(ObservationPolarity.INCONCLUSIVE, observation.polarity)
        assertEquals(EvidenceConfidence.LOW, observation.confidence)
    }

    @Test
    fun `uncorrelated timing and semantics remain valid inconclusive signals`() {
        val observation = observation(timing = true, semantic = true, corroborated = false)

        assertEquals(ProbeAvailability.AVAILABLE, observation.availability)
        assertEquals(ObservationPolarity.INCONCLUSIVE, observation.polarity)
        assertEquals(EvidenceConfidence.LOW, observation.confidence)
    }

    @Test
    fun `corroborated timing is medium positive review evidence`() {
        val observation = observation(timing = true, semantic = true, corroborated = true)
        val evaluated = BetaEvidencePolicy.evaluate(observation, BetaEvaluationContext(networkEpochId = null))

        assertEquals(ObservationPolarity.POSITIVE, observation.polarity)
        assertEquals(EvidenceConfidence.MEDIUM, observation.confidence)
        assertTrue(evaluated.finding.needsReview)
        assertFalse(evaluated.finding.detected)
        assertFalse(evaluated.evidence!!.hardSignal)
    }

    @Test
    fun `unsupported architecture stays typed inconclusive`() {
        val observation = VpnHideHookTimingBetaChecker.observation(
            context,
            "vpnhide_hook_timing.libc",
            ParsedBetaProbeRow(
                "vpnhide_hook_timing.libc",
                ProbeAvailability.UNSUPPORTED,
                mapOf("reason" to "unsupported_arch"),
            ),
            1L,
        )

        assertEquals(ProbeAvailability.UNSUPPORTED, observation.availability)
        assertEquals(ObservationPolarity.INCONCLUSIVE, observation.polarity)
        assertEquals("unsupported_arch", observation.facts["reason"])
    }

    @Test
    fun `timeout and native truncation stay typed inconclusive`() {
        listOf("timeout", "deadline_or_insufficient_data").forEach { reason ->
            val observation = VpnHideHookTimingBetaChecker.observation(
                context,
                "vpnhide_hook_timing.kernel",
                ParsedBetaProbeRow(
                    "vpnhide_hook_timing.kernel",
                    ProbeAvailability.TRUNCATED,
                    mapOf("reason" to reason),
                ),
                1L,
            )

            assertEquals(ProbeAvailability.TRUNCATED, observation.availability)
            assertEquals(ObservationPolarity.INCONCLUSIVE, observation.polarity)
            assertEquals(reason, observation.facts["reason"])
        }
    }

    @Test
    fun `missing or contradictory aggregate fields are malformed`() {
        val missing = VpnHideHookTimingBetaChecker.observation(
            context,
            "vpnhide_hook_timing.libc",
            ParsedBetaProbeRow(
                "vpnhide_hook_timing.libc",
                ProbeAvailability.AVAILABLE,
                mapOf(
                    "timing_anomaly" to "true",
                    "semantic_mismatch" to "true",
                    "corroborated" to "true",
                ),
            ),
            1L,
        )
        val contradictory = observation(timing = true, semantic = false, corroborated = true)
        val insufficient = VpnHideHookTimingBetaChecker.observation(
            context,
            "vpnhide_hook_timing.libc",
            ParsedBetaProbeRow(
                "vpnhide_hook_timing.libc",
                ProbeAvailability.AVAILABLE,
                aggregateFields(
                    timing = false,
                    semantic = false,
                    corroborated = false,
                ) + mapOf("valid_pairs" to "383", "full_batches" to "2"),
            ),
            1L,
        )

        assertEquals(ProbeAvailability.MALFORMED_RESPONSE, missing.availability)
        assertEquals(ProbeAvailability.MALFORMED_RESPONSE, contradictory.availability)
        assertEquals(ProbeAvailability.MALFORMED_RESPONSE, insufficient.availability)
    }

    private fun observation(
        timing: Boolean,
        semantic: Boolean,
        corroborated: Boolean,
    ) = VpnHideHookTimingBetaChecker.observation(
        context,
        "vpnhide_hook_timing.libc",
        ParsedBetaProbeRow(
            "vpnhide_hook_timing.libc",
            ProbeAvailability.AVAILABLE,
            aggregateFields(timing, semantic, corroborated),
        ),
        1L,
    )

    private fun aggregateFields(
        timing: Boolean,
        semantic: Boolean,
        corroborated: Boolean,
    ) = mapOf(
        "reason" to if (corroborated) "corroborated" else "no_corroboration",
        "counter_hz" to "19200000",
        "valid_pairs" to "384",
        "full_batches" to "3",
        "cpu_migrations" to "1",
        "median_ticks" to "12",
        "mad_ticks" to "1",
        "ratio_milli" to "1300",
        "timing_anomaly" to timing.toString(),
        "semantic_mismatch" to semantic.toString(),
        "corroborated" to corroborated.toString(),
    )
}
