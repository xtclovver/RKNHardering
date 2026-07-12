package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.ParsedBetaProbeRow
import com.notcvnt.rknhardering.probe.privileged.PrivilegedProbeKind
import com.notcvnt.rknhardering.probe.privileged.PrivilegedProbeResult
import com.notcvnt.rknhardering.model.PrivilegedProbeProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class KernelBetaCheckerTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `wireguard history stays neutral without causal delta while empty family is clean`() {
        val active = KernelBetaChecker.wireGuardObservation(
            context,
            row("wireguard_genl", mapOf("devices" to "1", "peers" to "1", "peers_with_handshake_or_counters" to "1")),
            "epoch",
            1L,
        )
        val empty = KernelBetaChecker.wireGuardObservation(
            context,
            row("wireguard_genl", mapOf("devices" to "0", "peers" to "0", "peers_with_handshake_or_counters" to "0")),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.INCONCLUSIVE, active.polarity)
        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, empty.polarity)
    }

    @Test
    fun `single wireguard counter delta remains suppressed until repeated`() {
        val beforeRow = row(
            "wireguard_genl",
            mapOf(
                "devices" to "1",
                "peers" to "1",
                "peers_with_handshake_or_counters" to "1",
                "interface_indexes" to "42",
                "rx_bytes" to "10",
                "tx_bytes" to "20",
            ),
        )
        val afterRow = beforeRow.copy(fields = beforeRow.fields + ("tx_bytes" to "120"))
        val observation = KernelBetaChecker.wireGuardDeltaObservation(
            context,
            KernelBetaChecker.WireGuardCounterSample(beforeRow, 10, 20),
            KernelBetaChecker.WireGuardCounterSample(afterRow, 10, 120),
            canaryTransferred = true,
            expectedInterfaceIndex = 42,
            epochId = "epoch",
            at = 1L,
        )

        assertEquals(ObservationPolarity.POSITIVE, observation.polarity)
        assertTrue(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS in observation.suppressions)
        val evaluated = BetaEvidencePolicy.evaluate(
            observation,
            BetaEvaluationContext(
                "epoch",
                mapOf("beta.wireguard_genl" to BetaRepeatValidation(2, true, true)),
            ),
        )
        assertEquals(false, evaluated.finding.detected)
    }

    @Test
    fun `single ovpn counter delta remains suppressed until repeated`() {
        val beforeRow = row(
            "ovpn_genl",
            mapOf("interfaces" to "1", "peers" to "1", "interface_indexes" to "42", "rx_bytes" to "5", "tx_bytes" to "7"),
        )
        val afterRow = beforeRow.copy(fields = beforeRow.fields + ("rx_bytes" to "55"))

        val observation = KernelBetaChecker.ovpnDeltaObservation(
            context,
            KernelBetaChecker.OvpnCounterSample(beforeRow, 5, 7),
            KernelBetaChecker.OvpnCounterSample(afterRow, 55, 7),
            canaryTransferred = true,
            expectedInterfaceIndex = 42,
            epochId = "epoch",
            at = 1L,
        )

        assertEquals(ObservationPolarity.POSITIVE, observation.polarity)
        assertTrue(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS in observation.suppressions)
        val evaluated = BetaEvidencePolicy.evaluate(
            observation,
            BetaEvaluationContext(
                "epoch",
                mapOf("beta.ovpn_genl" to BetaRepeatValidation(2, true, true)),
            ),
        )
        assertEquals(false, evaluated.finding.detected)
    }

    @Test
    fun `ims xfrm state is suppressed and not positive`() {
        val observation = KernelBetaChecker.xfrmObservation(
            context,
            row("xfrm", mapOf("classification" to "system_ims", "states_with_traffic" to "1")),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.INCONCLUSIVE, observation.polarity)
        assertTrue(BetaSuppressionRuleId.IMS_OR_EIMS_CONTEXT in observation.suppressions)
    }

    @Test
    fun `self owned tun fd is high-confidence positive and denial is neutral`() {
        val active = KernelBetaChecker.tunObservation(
            context,
            row("tun_fd", mapOf("inspected" to "12", "tun_fds" to "1")),
            "epoch",
            1L,
        )
        val denied = KernelBetaChecker.tunObservation(
            context,
            ParsedBetaProbeRow("tun_fd", ProbeAvailability.PERMISSION_DENIED, emptyMap()),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.POSITIVE, active.polarity)
        assertEquals(ObservationPolarity.INCONCLUSIVE, denied.polarity)
    }

    @Test
    fun `privileged provider denial is explicit and never positive`() {
        val observations = KernelBetaChecker.privilegedObservations(
            context,
            mapOf(
                PrivilegedProbeKind.WIREGUARD to
                    PrivilegedProbeResult.PermissionDenied(PrivilegedProbeProvider.SHIZUKU),
            ),
            "epoch",
            1L,
        )

        assertEquals(1, observations.size)
        assertEquals(ProbeAvailability.PERMISSION_DENIED, observations.single().availability)
        assertEquals(ObservationPolarity.INCONCLUSIVE, observations.single().polarity)
    }

    private fun row(checkId: String, fields: Map<String, String>) =
        ParsedBetaProbeRow(checkId, ProbeAvailability.AVAILABLE, fields)
}
