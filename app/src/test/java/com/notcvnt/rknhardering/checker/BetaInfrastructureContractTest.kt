package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.NetworkEpoch
import com.notcvnt.rknhardering.model.NetworkEpochChangeReason
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.HiddenCallResult
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlinx.coroutines.runBlocking

@RunWith(RobolectricTestRunner::class)
class BetaInfrastructureContractTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `hidden profile lookup is not called when hidden APIs are disabled`() {
        var called = false
        val result = ExecutionContextChecker.check(
            context = context,
            networkEpochId = "epoch",
            observedAtElapsedMs = 1L,
            hiddenApiEnabled = false,
            hiddenProfileTypeLookup = {
                called = true
                HiddenCallResult.Success("android.os.usertype.profile.PRIVATE")
            },
        )

        assertFalse(called)
        assertTrue(result.hiddenAvailability == ProbeAvailability.SKIPPED)
    }

    @Test
    fun `network epoch comparison detects route relevant changes`() {
        val initial = epoch(activeInterface = "wlan0")

        assertTrue(initial.hasSameNetworkState(epoch(activeInterface = "wlan0")))
        assertFalse(initial.hasSameNetworkState(epoch(activeInterface = "tun0")))
        assertFalse(initial.hasSameNetworkState(epoch(activeInterface = "wlan0", routes = setOf("route-b"))))
        assertFalse(initial.hasSameNetworkState(epoch(activeInterface = "wlan0", dnsServers = setOf("1.1.1.1"))))
        assertTrue(initial.hasSameNetworkState(epoch(activeInterface = "wlan0", networkHandles = setOf(100L, 200L))))
    }

    @Test
    fun `initial default network callbacks establish baseline before probes without transition`() = runBlocking {
        val tracker = DefaultNetworkEpochTracker(epoch("wlan0"))

        tracker.onAvailable(100L)
        tracker.onCapabilities(100L, setOf(1), validated = true, captivePortal = false, vpnTransport = false)
        tracker.onLinkProperties(100L) { it.copy(activeInterface = "wlan0") }

        val baseline = tracker.awaitBaseline()

        assertEquals("wlan0", baseline.activeInterface)
        assertTrue(tracker.changeReasons.isEmpty())
    }

    @Test
    fun `subsequent capability change is retained as transition`() {
        val tracker = DefaultNetworkEpochTracker(epoch("wlan0"))
        tracker.onAvailable(100L)
        tracker.onCapabilities(100L, setOf(1), validated = true, captivePortal = false, vpnTransport = false)
        tracker.onLinkProperties(100L) { it.copy(activeInterface = "wlan0") }

        tracker.onCapabilities(100L, setOf(1), validated = false, captivePortal = false, vpnTransport = false)

        assertEquals(setOf(NetworkEpochChangeReason.VALIDATION_CHANGED), tracker.changeReasons)
    }

    @Test
    fun `unstable attempt retries once and returns stable result`() = runBlocking {
        var attempts = 0

        val result = retryOnceOnNetworkEpochChange {
            attempts += 1
            NetworkEpochAttempt(value = attempts, stable = attempts == 2)
        }

        assertEquals(2, attempts)
        assertEquals(2, result.value)
        assertEquals(1, result.retryCount)
    }

    @Test
    fun `two unstable attempts stop after second result`() = runBlocking {
        var attempts = 0

        val result = retryOnceOnNetworkEpochChange {
            attempts += 1
            NetworkEpochAttempt(value = attempts, stable = false)
        }

        assertEquals(2, attempts)
        assertEquals(2, result.value)
        assertEquals(1, result.retryCount)
    }

    @Test
    fun `stable attempt does not retry`() = runBlocking {
        var attempts = 0

        val result = retryOnceOnNetworkEpochChange {
            attempts += 1
            NetworkEpochAttempt(value = attempts, stable = true)
        }

        assertEquals(1, attempts)
        assertEquals(0, result.retryCount)
    }

    @Test
    fun `missing callback monitor makes epoch unstable`() = runBlocking {
        val tracker = DefaultNetworkEpochTracker(epoch("wlan0"))

        tracker.monitorUnavailable()
        tracker.awaitBaseline()

        assertEquals(
            setOf(NetworkEpochChangeReason.CALLBACK_MONITOR_UNAVAILABLE),
            tracker.stopAndSnapshot().changeReasons,
        )
    }

    @Test
    fun `callback bootstrap timeout makes epoch unstable`() {
        val tracker = DefaultNetworkEpochTracker(epoch("wlan0"))

        tracker.bootstrapTimedOut()

        assertEquals(
            setOf(NetworkEpochChangeReason.CALLBACK_BOOTSTRAP_TIMEOUT),
            tracker.stopAndSnapshot().changeReasons,
        )
    }

    @Test
    fun `transition latch preserves ABA changes`() {
        val latch = NetworkEpochTransitionLatch()
        latch.markChanged()

        assertTrue(latch.changed)
        assertTrue(epoch("wlan0").hasSameNetworkState(epoch("wlan0")))
    }

    @Test
    fun `registered resource is closed when cancellation throws immediately`() {
        var closeCount = 0
        val resource = AutoCloseable { closeCount += 1 }

        runCatching {
            withCloseableResource(resource) { error("cancelled") }
        }

        assertTrue(closeCount == 1)
    }

    private fun epoch(
        activeInterface: String,
        routes: Set<String> = setOf("route-a"),
        dnsServers: Set<String> = setOf("8.8.8.8"),
        networkHandles: Set<Long> = setOf(100L),
    ) = NetworkEpoch(
        id = "epoch",
        startedAtElapsedMs = 1L,
        activeNetworkHandle = 100L,
        networkHandles = networkHandles,
        activeTransports = setOf(1),
        activeInterface = activeInterface,
        validated = true,
        captivePortal = false,
        vpnTransport = false,
        vcnTransport = null,
        privateDnsActive = false,
        nat64Prefix = null,
        telephonyNetworkType = null,
        roaming = null,
        currentUserId = 0,
        routes = routes,
        dnsServers = dnsServers,
    )
}
