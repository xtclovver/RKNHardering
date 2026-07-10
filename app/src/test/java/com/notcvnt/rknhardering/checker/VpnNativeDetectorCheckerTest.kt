package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.probe.NativeSignsBridge
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class VpnNativeDetectorCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        NativeSignsBridge.resetForTests()
        NativeSignsBridge.isLibraryLoadedOverride = { true }
    }

    @After
    fun tearDown() {
        NativeSignsBridge.resetForTests()
    }

    @Test
    fun `neutral measurements are informational and do not create evidence`() {
        NativeSignsBridge.detectVpnDetectorOverride = {
            arrayOf(
                "vdet|route_count|routes=12",
                "vdet|pmtu_mss_combined|tcp_snd_mss=1440 tcp_rcv_mss=1440",
                "vdet|udp_pmtu_ok|sent=1500 bytes",
                "vdet|normal_pmtu|iface=wlan0 mtu=1500",
                "vdet|timing_oracle|min=1 max=2 avg=1",
                "vdet|backpressure|50000/50000 pkts sent",
                "vdet|gso_ok|supported",
                "vdet|hw_timestamp|unsupported",
            )
        }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.evidence.isEmpty())
        assertTrue(result.findings.all { it.isInformational })
    }

    @Test
    fun `gso failures are capability diagnostics instead of vpn evidence`() {
        NativeSignsBridge.detectVpnDetectorOverride = {
            arrayOf(
                "vdet|gso_failed|errno=92",
                "vdet|gso_send_failed|errno=90",
            )
        }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.evidence.isEmpty())
        assertTrue(result.findings.all { it.isInformational })
    }

    @Test
    fun `high confidence socket leak remains detected evidence`() {
        NativeSignsBridge.detectVpnDetectorOverride = {
            arrayOf("vdet|bindtodevice_leak|setsockopt(tun0) succeeded")
        }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }
        val evidence = result.evidence.single()

        assertTrue(result.detected)
        assertEquals(EvidenceSource.NATIVE_SOCKET, evidence.source)
        assertEquals(EvidenceConfidence.HIGH, evidence.confidence)
        assertTrue(evidence.detected)
    }

    @Test
    fun `native detector receives scan cancellation and aborts result`() {
        val cancellationSignal = ScanCancellationSignal()
        val executionContext = ScanExecutionContext(cancellationSignal = cancellationSignal)
        NativeSignsBridge.detectVpnDetectorOverride = { receivedSignal ->
            assertSame(cancellationSignal, receivedSignal)
            cancellationSignal.cancel()
            arrayOf("vdet|backpressure|partial")
        }

        assertThrows(CancellationException::class.java) {
            runBlocking(executionContext.asCoroutineContext()) {
                VpnNativeDetectorChecker.check(context)
            }
        }
    }
}
