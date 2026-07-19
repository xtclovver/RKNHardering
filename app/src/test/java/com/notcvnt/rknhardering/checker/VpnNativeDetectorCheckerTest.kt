package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.NativeSignalCatalog
import com.notcvnt.rknhardering.model.NativeSignalId
import com.notcvnt.rknhardering.model.ProbeAvailability
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
    fun `every deep detector kind receives its stable signal id`() {
        val kinds = listOf(
            "sysfs_vpn_leak", "getifaddrs_vpn", "sysclassnet_vpn", "rtm_getlink_vpn",
            "proc_if_inet6_vpn", "proc_ipv6_route_vpn", "proc_net_dev_vpn", "ifindexname_vpn",
            "vpn_policy_rules_netlink", "fib_trie_denied", "inet_diag_denied", "bindtodevice_leak",
            "getsockname_leak", "udp_port_conflict_physical", "vpn_qdisc", "bpf_map_accessible",
            "route_count", "trim_oracle", "pmtu_mss_combined", "udp_pmtu_ok", "udp_pmtu_fail",
            "normal_pmtu", "timing_oracle", "backpressure", "gso_failed", "gso_send_failed",
            "gso_ok", "hw_timestamp", "traceroute_denied", "vpnhide_ifindex_clean",
            "vpnhide_ifindex_unavailable", "vpnhide_ifconf_clean", "vpnhide_ifconf_unavailable",
            "vpnhide_ifindex_oracle", "vpnhide_ifconf_tail_vpn", "vpnhide_ifconf_tail_oracle",
        )
        NativeSignsBridge.detectVpnDetectorOverride = {
            kinds.map { kind -> "vdet|$kind|detail" }.toTypedArray()
        }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        kinds.forEach { kind ->
            assertTrue(
                kind,
                result.findings.any { it.nativeSignalId == NativeSignalCatalog.fromDeepVpnKind(kind) },
            )
        }
    }

    @Test
    fun `unknown deep kind remains visible in general category`() {
        NativeSignsBridge.detectVpnDetectorOverride = { arrayOf("vdet|future_kind|future detail") }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        assertEquals(NativeSignalId.UNKNOWN, result.findings.single().nativeSignalId)
        assertTrue(result.findings.single().description.contains("future_kind"))
    }

    @Test
    fun `clean vpnhide probes remain visible without affecting verdict`() {
        NativeSignsBridge.detectVpnDetectorOverride = {
            arrayOf(
                "vdet|vpnhide_ifindex_clean|completed",
                "vdet|vpnhide_ifconf_clean|returned_bytes=80",
            )
        }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertFalse(result.hasError)
        assertTrue(result.evidence.isEmpty())
        assertEquals(2, result.findings.size)
        assertTrue(result.findings.all { it.isInformational })
        assertTrue(result.findings.all { it.nativeSignalId == NativeSignalId.VPNHIDE })
        assertTrue(result.findings.all { it.availability == ProbeAvailability.AVAILABLE })
        assertEquals(
            setOf("native.vpnhide.ifindex_consistency", "native.vpnhide.ifconf_tail"),
            result.findings.mapNotNull { it.checkId }.toSet(),
        )
        assertTrue(result.findings.any {
            it.description.contains(context.getString(com.notcvnt.rknhardering.R.string.vpn_desc_vpnhide_ifindex_probe))
        })
        assertTrue(result.findings.any {
            it.description.contains(context.getString(com.notcvnt.rknhardering.R.string.vpn_desc_vpnhide_ifconf_probe))
        })
        assertTrue(result.findings.none { it.description.contains("vpnhide_if") })
    }

    @Test
    fun `unavailable vpnhide probes are errors instead of clean results`() {
        NativeSignsBridge.detectVpnDetectorOverride = {
            arrayOf(
                "vdet|vpnhide_ifindex_unavailable|stage=socket errno=13",
                "vdet|vpnhide_ifconf_unavailable|stage=ioctl errno=1",
            )
        }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.hasError)
        assertTrue(result.evidence.isEmpty())
        assertEquals(2, result.findings.size)
        assertTrue(result.findings.all { it.isError })
        assertTrue(result.findings.all { it.availability == ProbeAvailability.ERROR })
        assertTrue(result.findings.all { it.nativeSignalId == NativeSignalId.VPNHIDE })
    }

    @Test
    fun `native detector exception is visible as an error`() {
        NativeSignsBridge.detectVpnDetectorOverride = { error("native failure") }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        assertTrue(result.hasError)
        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.evidence.isEmpty())
        assertEquals(NativeSignalId.NATIVE_LIBRARY, result.findings.single().nativeSignalId)
        assertTrue(result.findings.single().description.contains("native failure"))
    }

    @Test
    fun `vpnhide concealment leaks are high confidence evidence`() {
        NativeSignsBridge.detectVpnDetectorOverride = {
            arrayOf(
                "vdet|vpnhide_ifindex_oracle|stable_asymmetries=1 samples=tun0:33(reverse_errno=19)",
                "vdet|vpnhide_ifconf_tail_vpn|returned_bytes=160 entry_size=40 stale_slots=1 vpn_like=1 names=tun0",
            )
        }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertEquals(2, result.evidence.size)
        assertTrue(result.evidence.all { it.source == EvidenceSource.NATIVE_INTERFACE })
        assertTrue(result.evidence.all { it.confidence == EvidenceConfidence.HIGH })
        assertTrue(result.findings.all { it.nativeSignalId == NativeSignalId.VPNHIDE })
        assertTrue(result.findings.all { it.availability == ProbeAvailability.AVAILABLE })
        assertTrue(result.findings.none { it.description.contains("vpnhide_if") })
    }

    @Test
    fun `generic vpnhide ifconf tail is review only`() {
        NativeSignsBridge.detectVpnDetectorOverride = {
            arrayOf(
                "vdet|vpnhide_ifconf_tail_oracle|returned_bytes=160 entry_size=40 stale_slots=1 vpn_like=0 names=rmnet_data0",
            )
        }

        val result = runBlocking { VpnNativeDetectorChecker.check(context) }

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertEquals(1, result.evidence.size)
        assertEquals(EvidenceSource.NATIVE_INTERFACE, result.evidence.single().source)
        assertEquals(EvidenceConfidence.MEDIUM, result.evidence.single().confidence)
        assertEquals(NativeSignalId.VPNHIDE, result.findings.single().nativeSignalId)
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
