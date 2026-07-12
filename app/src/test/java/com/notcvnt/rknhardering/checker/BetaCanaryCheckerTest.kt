package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.NetworkEpoch
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.probe.BetaCanaryAddressFamily
import com.notcvnt.rknhardering.probe.BetaCanaryObservation
import com.notcvnt.rknhardering.probe.BetaCanaryRunResult
import com.notcvnt.rknhardering.probe.BetaCanaryStatus
import com.notcvnt.rknhardering.probe.BetaCanaryTransport
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BetaCanaryCheckerTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `controlled dns and transport divergence are positive`() {
        val result = BetaCanaryRunResult(
            status = BetaCanaryStatus.AVAILABLE,
            observations = listOf(
                available(BetaCanaryTransport.HTTP, "http-egress"),
                available(BetaCanaryTransport.DNS, "dns-egress"),
                available(BetaCanaryTransport.TCP, "tcp-egress"),
            ),
        )

        val observations = BetaCanaryChecker.observations(context, result, epoch(), 1L)

        assertEquals(
            ObservationPolarity.POSITIVE,
            observations.single { it.checkId == "beta.dns_netid" }.polarity,
        )
        assertEquals(
            ObservationPolarity.POSITIVE,
            observations.single { it.checkId == "beta.transport_matrix" }.polarity,
        )
        assertEquals(
            listOf(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS),
            observations.single { it.checkId == "beta.transport_matrix" }.suppressions,
        )
    }

    @Test
    fun `absent endpoint remains unavailable rather than clean`() {
        val observations = BetaCanaryChecker.observations(
            context,
            BetaCanaryRunResult(status = BetaCanaryStatus.UNAVAILABLE),
            epoch(),
            1L,
        )

        assertEquals(4, observations.size)
        assertEquals(setOf(ObservationPolarity.INCONCLUSIVE), observations.map { it.polarity }.toSet())
    }

    private fun available(transport: BetaCanaryTransport, hash: String) = BetaCanaryObservation(
        transport = transport,
        family = BetaCanaryAddressFamily.IPV4,
        status = BetaCanaryStatus.AVAILABLE,
        observedAddressHash = hash,
        serverFingerprintHash = "fingerprint",
    )

    private fun epoch() = NetworkEpoch(
        id = "epoch",
        startedAtElapsedMs = 1L,
        activeNetworkHandle = 100L,
        networkHandles = setOf(100L),
        activeTransports = setOf(1),
        activeInterface = "wlan0",
        validated = true,
        captivePortal = false,
        vpnTransport = false,
        vcnTransport = null,
        privateDnsActive = false,
        nat64Prefix = null,
        telephonyNetworkType = null,
        roaming = null,
        currentUserId = 0,
    )
}
