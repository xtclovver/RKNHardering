package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BetaChecksRolloutGateTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `socket oracles are included after rollout gate opens`() = runBlocking {
        val result = BetaChecksChecker.check(
            BetaChecksRequest(
                context = context,
                settings = BetaCheckSettings(
                    enabled = true,
                    hiddenAndroidApis = false,
                    kernelNetlink = false,
                    socketOracles = true,
                    profileIsolation = false,
                    sandboxIntegrity = false,
                    bpfNetfilter = false,
                    aggressive = false,
                ),
                resolverConfig = DnsResolverConfig.system(),
                networkRequestsEnabled = false,
                executionContext = ScanExecutionContext(),
            ),
        )

        assertTrue(BetaChecksChecker.SOCKET_ORACLES_ROLLOUT_READY)
        assertEquals(null, result.availabilitySummary[ProbeAvailability.SKIPPED])
        assertEquals(7, result.availabilitySummary.values.sum())
        assertFalse(result.category.detected)
    }
}
