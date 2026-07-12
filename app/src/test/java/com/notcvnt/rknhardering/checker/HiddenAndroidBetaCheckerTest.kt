package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.ExecutionContextFacts
import com.notcvnt.rknhardering.model.ExecutionContextKind
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.HiddenCallResult
import com.notcvnt.rknhardering.probe.ConnectivityBinderSnapshot
import com.notcvnt.rknhardering.probe.LegacyVpnFacts
import com.notcvnt.rknhardering.probe.VpnConfigFacts
import com.notcvnt.rknhardering.probe.VpnManagerBinderSnapshot
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class HiddenAndroidBetaCheckerTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `active binder vpn is positive but disconnected always-on config is not`() {
        val active = HiddenAndroidBetaChecker.vpnObservation(
            context,
            HiddenCallResult.Success(snapshot(VpnConfigFacts(true, "tun0", "vpn", false))),
            "epoch",
            1L,
        )
        val disconnected = HiddenAndroidBetaChecker.vpnObservation(
            context,
            HiddenCallResult.Success(snapshot(VpnConfigFacts(true, null, "vpn", false))),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.POSITIVE, active.polarity)
        assertEquals(ObservationPolarity.INCONCLUSIVE, disconnected.polarity)
    }

    @Test
    fun `binder permission denial stays neutral and visible`() {
        val observation = HiddenAndroidBetaChecker.vpnObservation(
            context,
            HiddenCallResult.PermissionDenied("denied"),
            "epoch",
            1L,
        )

        assertEquals(ProbeAvailability.PERMISSION_DENIED, observation.availability)
        assertEquals(ObservationPolarity.INCONCLUSIVE, observation.polarity)
    }

    @Test
    fun `connectivity binder divergence is suppressed without route corroboration`() {
        val observation = HiddenAndroidBetaChecker.connectivityObservation(
            context,
            HiddenCallResult.Success(
                ConnectivityBinderSnapshot(
                    effectiveNetwork = null,
                    effectiveNetworkHandle = 101L,
                    publicActiveNetworkHandle = 100L,
                    differsFromPublicActiveNetwork = true,
                    capabilities = null,
                    linkProperties = null,
                ),
            ),
            "epoch",
            1L,
            vpnTransportOverride = true,
        )

        assertEquals(ObservationPolarity.POSITIVE, observation.polarity)
        assertEquals(
            listOf(BetaSuppressionRuleId.NO_CAUSAL_COUNTER_DELTA),
            observation.suppressions,
        )
    }

    @Test
    fun `foreground mismatch is supporting profile evidence`() {
        val observation = HiddenAndroidBetaChecker.foregroundObservation(
            context,
            ExecutionContextFacts(
                uid = 1_000_001,
                appId = 1,
                uidDerivedUserId = 10,
                foregroundUserId = 0,
                kind = ExecutionContextKind.MANAGED_PROFILE,
                confidence = EvidenceConfidence.HIGH,
            ),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.POSITIVE, observation.polarity)
    }

    private fun snapshot(config: VpnConfigFacts) = VpnManagerBinderSnapshot(
        config = HiddenCallResult.Success(config),
        legacyInfo = HiddenCallResult.Success(LegacyVpnFacts(false, null)),
        alwaysOnPackage = HiddenCallResult.Success(null),
        lockdownEnabled = HiddenCallResult.Success(false),
        lockdownAllowlistSize = HiddenCallResult.Success(0),
    )
}
