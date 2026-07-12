package com.notcvnt.rknhardering.probe.privileged

import android.content.Context
import android.os.Process
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.model.PrivilegedProbeProvider
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PrivilegedProbeContractTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `aidl exposes fixed probes and no command or path surface`() {
        val methods = IPrivilegedProbeService::class.java.methods.map { it.name }.toSet()

        assertTrue("probeWireGuard" in methods)
        assertTrue("probeOvpn" in methods)
        assertTrue("probeXfrm" in methods)
        assertTrue("probeBpfNetfilter" in methods)
        assertFalse(methods.any { it.contains("command", ignoreCase = true) || it.contains("path", ignoreCase = true) })
    }

    @Test
    fun `sanitizer drops interface names keys endpoints and raw map details`() {
        val rows = PrivilegedProbeRows.sanitize(
            arrayOf(
                "beta_v1|check=wireguard_genl|status=available|devices=1|peers=2|" +
                    "rx_bytes=12|tx_bytes=14|interfaces=wg-secret|interface_indexes=42|" +
                    "private_key=secret|endpoint=198.51.100.1",
            ),
            listOf("wireguard_genl"),
        )

        assertTrue(PrivilegedProbeRows.validate(rows, setOf("wireguard_genl")))
        assertTrue(rows.single().contains("devices=1"))
        assertTrue(rows.single().contains("interface_indexes=42"))
        assertFalse(rows.single().contains("interfaces"))
        assertFalse(rows.single().contains("key"))
        assertFalse(rows.single().contains("endpoint"))
    }

    @Test
    fun `binder requires exact bounded session nonce`() {
        val binder = PrivilegedProbeBinder(engine = fixedEngine(), exitOnDestroy = false)
        val nonce = ByteArray(PRIVILEGED_NONCE_SIZE) { it.toByte() }
        val wrong = nonce.copyOf().also { it[0] = 99 }

        assertFalse(binder.openSession(ByteArray(3)))
        assertTrue(binder.openSession(nonce))
        assertEquals(PRIVILEGED_PROBE_PROTOCOL_VERSION, binder.getProtocolVersion(nonce))
        assertEquals(-1, binder.getProtocolVersion(wrong))
        assertTrue(binder.probeWireGuard(wrong).single().contains("permission_denied"))
        assertArrayEquals(fixedEngine().wireGuard(ScanCancellationSignal()), binder.probeWireGuard(nonce))
    }

    @Test
    fun `cancel session reaches privileged probe signal`() {
        var cancelled = false
        val engine = object : PrivilegedProbeEngine by fixedEngine() {
            override fun wireGuard(cancellationSignal: ScanCancellationSignal): Array<String> {
                cancelled = cancellationSignal.isCancelled()
                return fixedEngine().wireGuard(cancellationSignal)
            }
        }
        val binder = PrivilegedProbeBinder(engine = engine, exitOnDestroy = false)
        val nonce = ByteArray(PRIVILEGED_NONCE_SIZE) { it.toByte() }

        assertTrue(binder.openSession(nonce))
        binder.cancelSession(nonce)
        binder.probeWireGuard(nonce)

        assertTrue(cancelled)
    }

    @Test
    fun `dual master disables binding and selected provider never falls back`() = runBlocking {
        val calls = mutableListOf<PrivilegedProbeProvider>()
        val coordinator = PrivilegedProbeCoordinator(context) { provider, _ ->
            calls += provider
            PrivilegedProbeClient { PrivilegedConnectionResult.Unavailable }
        }

        val disabled = coordinator.run(
            PrivilegedProbeSettings(false, true, PrivilegedProbeProvider.ROOT),
            PrivilegedProbeKind.WIREGUARD,
        )
        val unavailable = coordinator.run(
            PrivilegedProbeSettings(true, true, PrivilegedProbeProvider.ROOT),
            PrivilegedProbeKind.WIREGUARD,
        )

        assertTrue(disabled is PrivilegedProbeResult.Disabled)
        assertTrue(unavailable is PrivilegedProbeResult.Unavailable)
        assertEquals(listOf(PrivilegedProbeProvider.ROOT), calls)
    }

    @Test
    fun `coordinator validates provider identity and bounded rows`() = runBlocking {
        var closed = false
        val binder = PrivilegedProbeBinder(engine = fixedEngine(), exitOnDestroy = false)
        val coordinator = PrivilegedProbeCoordinator(context) { _, _ ->
            PrivilegedProbeClient {
                PrivilegedConnectionResult.Connected(
                    PrivilegedProbeConnection(binder, Process.myUid(), 13) { closed = true },
                )
            }
        }

        val result = coordinator.run(
            PrivilegedProbeSettings(true, true, PrivilegedProbeProvider.SHIZUKU),
            PrivilegedProbeKind.WIREGUARD,
        )

        assertTrue(result is PrivilegedProbeResult.Available)
        assertTrue(closed)
    }

    @Test
    fun `batch uses one authenticated provider connection for all selected probes`() = runBlocking {
        var connections = 0
        val binder = PrivilegedProbeBinder(engine = fixedEngine(), exitOnDestroy = false)
        val coordinator = PrivilegedProbeCoordinator(context) { _, _ ->
            PrivilegedProbeClient {
                connections += 1
                PrivilegedConnectionResult.Connected(
                    PrivilegedProbeConnection(binder, Process.myUid(), 13) {},
                )
            }
        }

        val results = coordinator.runBatch(
            PrivilegedProbeSettings(true, true, PrivilegedProbeProvider.SHIZUKU),
            linkedSetOf(PrivilegedProbeKind.WIREGUARD, PrivilegedProbeKind.OVPN, PrivilegedProbeKind.XFRM),
        )

        assertEquals(1, connections)
        assertEquals(3, results.size)
        assertTrue(results.values.all { it is PrivilegedProbeResult.Available })
    }

    private fun fixedEngine() = object : PrivilegedProbeEngine {
        override fun wireGuard(cancellationSignal: ScanCancellationSignal) =
            arrayOf("beta_v1|check=wireguard_genl|status=available|devices=1")
        override fun ovpn(cancellationSignal: ScanCancellationSignal) =
            arrayOf("beta_v1|check=ovpn_genl|status=available|interfaces=1|peers=0")
        override fun xfrm(imsContext: Boolean, cancellationSignal: ScanCancellationSignal) =
            arrayOf("beta_v1|check=xfrm|status=available|states=0")
        override fun bpfNetfilter(cancellationSignal: ScanCancellationSignal) = arrayOf(
            "beta_v1|check=cgroup_bpf|status=available|programs=0",
            "beta_v1|check=bpf_netd|status=available|opened=0",
            "beta_v1|check=netfilter_path|status=available|table_messages=0",
        )
    }
}
