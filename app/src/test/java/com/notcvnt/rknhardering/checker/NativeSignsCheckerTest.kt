package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.probe.NativeInterface
import com.notcvnt.rknhardering.probe.NativeRouteEntry
import com.notcvnt.rknhardering.probe.NativeSignsBridge
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class NativeSignsCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        NativeSignsBridge.resetForTests()
        NativeSignsBridge.isLibraryLoadedOverride = { true }
        NativeSignsBridge.getIfAddrsOverride = { emptyArray() }
        NativeSignsBridge.ifNameToIndexOverride = { 0 }
        NativeSignsBridge.readProcFileOverride = { _, _ -> null }
        NativeSignsBridge.readSelfMapsSummaryOverride = { emptyArray() }
        NativeSignsBridge.probeFeatureFlagsOverride = { emptyArray() }
        NativeSignsBridge.libraryIntegrityOverride = { emptyArray() }
        NativeSignsBridge.detectRootOverride = { emptyArray() }
    }

    @After
    fun tearDown() {
        NativeSignsBridge.resetForTests()
    }

    @Test
    fun `library unavailable yields info-only result`() {
        NativeSignsBridge.isLibraryLoadedOverride = { false }

        val result = runBlocking { NativeSignsChecker.check(context) }

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.isNotEmpty())
    }

    @Test
    fun `vpn interface detected`() {
        NativeSignsBridge.getIfAddrsOverride = {
            arrayOf(
                "wlan0|3|65|AF_INET|192.168.1.10|255.255.255.0|1500",
                "tun0|42|69|AF_INET|10.8.0.2|255.255.255.0|1420",
            )
        }

        val result = runBlocking { NativeSignsChecker.check(context) }

        assertTrue(result.detected)
        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.NATIVE_INTERFACE && it.detected
            },
        )
    }

    @Test
    fun `hook marker flags review`() {
        NativeSignsBridge.readSelfMapsSummaryOverride = {
            arrayOf("marker|frida-gadget|/data/local/tmp/frida-gadget.so")
        }

        val result = runBlocking { NativeSignsChecker.check(context) }

        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.NATIVE_HOOK_MARKERS && it.detected
            },
        )
    }

    @Test
    fun `library integrity foreign library flags review`() {
        NativeSignsBridge.libraryIntegrityOverride = {
            arrayOf("getifaddrs|0xdeadbeef|/data/local/tmp/hook.so")
        }

        val result = runBlocking { NativeSignsChecker.check(context) }

        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.NATIVE_LIBRARY_INTEGRITY && it.detected
            },
        )
    }

    @Test
    fun `clean native state produces ok result`() {
        NativeSignsBridge.getIfAddrsOverride = {
            arrayOf("wlan0|3|65|AF_INET|192.168.1.10|255.255.255.0|1500")
        }
        NativeSignsBridge.libraryIntegrityOverride = {
            arrayOf(
                "getifaddrs|0x7abc123|/apex/com.android.runtime/lib64/bionic/libc.so",
                "socket|0x7abc456|/apex/com.android.runtime/lib64/bionic/libc.so",
            )
        }

        val result = runBlocking { NativeSignsChecker.check(context) }

        assertFalse(result.detected)
        val hookEvidence = result.evidence.filter {
            it.source == EvidenceSource.NATIVE_HOOK_MARKERS && it.detected
        }
        assertEquals(0, hookEvidence.size)
        val integrityEvidence = result.evidence.filter {
            it.source == EvidenceSource.NATIVE_LIBRARY_INTEGRITY && it.detected
        }
        assertEquals(0, integrityEvidence.size)
    }

    @Test
    fun `ipv6 default vpn route is detected`() {
        NativeSignsBridge.readProcFileOverride = { path, _ ->
            when (path) {
                "/proc/net/ipv6_route" -> """
                    00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 tun0
                """.trimIndent()
                else -> null
            }
        }

        val result = runBlocking { NativeSignsChecker.check(context) }

        assertTrue(
            result.evidence.any {
                it.source == EvidenceSource.NATIVE_ROUTE && it.detected
            },
        )
    }

    @Test
    fun `stock vendor overlay mounts are ignored`() {
        NativeSignsBridge.getIfAddrsOverride = {
            arrayOf("wlan0|3|65|AF_INET|192.168.1.10|255.255.255.0|1500")
        }
        NativeSignsBridge.detectRootOverride = {
            arrayOf(
                "overlay_mount|overlay /system_ext/etc/permissions overlay ro,seclabel,relatime,lowerdir=/mnt/vendor/mi_ext/system_ext/etc/permissions:/system_ext/etc/permissions 0 0",
                "overlay_mount|overlay /product/overlay overlay ro,seclabel,relatime,lowerdir=/mnt/vendor/mi_ext/product/overlay:/product/overlay 0 0",
            )
        }

        val result = runBlocking { NativeSignsChecker.check(context) }

        assertFalse(
            result.findings.any { it.source == EvidenceSource.NATIVE_ROOT_DETECTION },
        )
        assertFalse(
            result.evidence.any { it.source == EvidenceSource.NATIVE_ROOT_DETECTION && it.detected },
        )
    }

    @Test
    fun `root overlay mounts with explicit markers are kept`() {
        NativeSignsBridge.getIfAddrsOverride = {
            arrayOf("wlan0|3|65|AF_INET|192.168.1.10|255.255.255.0|1500")
        }
        NativeSignsBridge.detectRootOverride = {
            arrayOf(
                "overlay_mount|overlay /system overlay rw,seclabel,relatime,lowerdir=/system,upperdir=/data/adb/modules/lsposed/system,workdir=/data/adb/overlay 0 0",
            )
        }

        val result = runBlocking { NativeSignsChecker.check(context) }

        assertTrue(
            result.findings.any { it.source == EvidenceSource.NATIVE_ROOT_DETECTION && it.needsReview },
        )
        assertTrue(
            result.evidence.any { it.source == EvidenceSource.NATIVE_ROOT_DETECTION && it.detected },
        )
    }

    @Test
    fun `host route to public ip via physical interface requires review`() {
        val routes = listOf(
            NativeRouteEntry(
                interfaceName = "wlan0",
                destinationHex = "08080808",
                gatewayHex = "C0A80101",
                flags = 0,
                isDefault = false,
                source = NativeRouteEntry.RouteSource.NETLINK,
                family = 2,
                destination = "8.8.8.8",
                gateway = "192.168.1.1",
                prefSrc = "192.168.1.10",
                scope = "global",
                type = "unicast",
                table = 254,
                prefixLen = 32,
                protocol = 4,
            ),
        )
        val outcome = NativeSignsChecker.evaluateHostRoutes(context, routes)
        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertTrue(outcome.evidence.any { it.source == EvidenceSource.NATIVE_HOST_ROUTE && it.detected })
    }

    @Test
    fun `host route to private ip or via tun does not emit evidence`() {
        val privateViaWlan = NativeRouteEntry(
            interfaceName = "wlan0", destinationHex = "0A080001", gatewayHex = "00000000",
            flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
            family = 2, destination = "10.8.0.1", prefixLen = 32,
        )
        val publicViaTun = NativeRouteEntry(
            interfaceName = "tun0", destinationHex = "08080808", gatewayHex = "00000000",
            flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
            family = 2, destination = "8.8.8.8", prefixLen = 32,
        )
        val outcome = NativeSignsChecker.evaluateHostRoutes(context, listOf(privateViaWlan, publicViaTun))
        assertFalse(outcome.detected)
    }

    @Test
    fun `kernel local route for interface own address does not emit evidence`() {
        // Reproduces issue #78: ccmni1 cellular interface with a public-range address
        // (12.233.114.164/8) produces a kernel-managed /32 entry in the local table.
        // dst == prefsrc, type=local, scope=host — this is the interface's own address,
        // not a VPN server host-route leak.
        val localOwnAddress = NativeRouteEntry(
            interfaceName = "ccmni1", destinationHex = "0CE972A4", gatewayHex = "00000000",
            flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
            family = 2, destination = "12.233.114.164", prefSrc = "12.233.114.164",
            scope = "host", type = "local", table = 255, prefixLen = 32,
        )
        val broadcastEntry = NativeRouteEntry(
            interfaceName = "ccmni1", destinationHex = "0CFFFFFF", gatewayHex = "00000000",
            flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
            family = 2, destination = "12.255.255.255", scope = "link",
            type = "broadcast", table = 255, prefixLen = 32,
        )
        val outcome = NativeSignsChecker.evaluateHostRoutes(context, listOf(localOwnAddress, broadcastEntry))
        assertFalse(outcome.detected)
    }

    @Test
    fun `carrier service host routes do not emit VPN server leak evidence`() {
        val routes = listOf(
            NativeRouteEntry(
                interfaceName = "ccmni0", destinationHex = "1A1272F5", gatewayHex = "00000000",
                flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
                family = 2, destination = "26.18.114.245", scope = "link",
                type = "unicast", table = 1008, prefixLen = 32, protocol = 2,
            ),
            NativeRouteEntry(
                interfaceName = "rmnet_data0", destinationHex = "1A1272F5", gatewayHex = "00000000",
                flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
                family = 2, destination = "26.18.114.245", scope = "link",
                type = "unicast", table = 1009, prefixLen = 32, protocol = 2,
            ),
        )

        val outcome = NativeSignsChecker.evaluateHostRoutes(context, routes)

        assertFalse(outcome.detected)
        assertFalse(outcome.evidence.any { it.source == EvidenceSource.NATIVE_HOST_ROUTE })
    }

    @Test
    fun `malformed local table route does not emit VPN server leak evidence`() {
        val route = NativeRouteEntry(
            interfaceName = "ccmni0", destinationHex = "1A1272F5", gatewayHex = "00000000",
            flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
            family = 2, destination = "26.18.114.245", scope = "link",
            type = "unicast", table = 255, prefixLen = 32,
        )

        val outcome = NativeSignsChecker.evaluateHostRoutes(context, listOf(route))

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
    }

    @Test
    fun `static public host route via cellular interface requires review`() {
        val route = NativeRouteEntry(
            interfaceName = "ccmni2", destinationHex = "0D0058A1", gatewayHex = "00000000",
            flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
            family = 2, destination = "13.0.88.161", scope = "global",
            type = "unicast", table = 1008, prefixLen = 32, protocol = 4,
        )

        val outcome = NativeSignsChecker.evaluateHostRoutes(context, listOf(route))

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertTrue(outcome.evidence.any { it.source == EvidenceSource.NATIVE_HOST_ROUTE })
    }

    @Test
    fun `host route with incomplete metadata is not promoted to VPN evidence`() {
        val route = NativeRouteEntry(
            interfaceName = "wlan0", destinationHex = "08080808", gatewayHex = "C0A80101",
            flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
            family = 2, destination = "8.8.8.8", prefixLen = 32,
        )

        val outcome = NativeSignsChecker.evaluateHostRoutes(context, listOf(route))

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
    }

    @Test
    fun `non unicast host route is not promoted to VPN evidence`() {
        val route = NativeRouteEntry(
            interfaceName = "wlan0", destinationHex = "08080808", gatewayHex = "C0A80101",
            flags = 0, isDefault = false, source = NativeRouteEntry.RouteSource.NETLINK,
            family = 2, destination = "8.8.8.8", scope = "global",
            type = "blackhole", table = 254, prefixLen = 32, protocol = 4,
        )

        val outcome = NativeSignsChecker.evaluateHostRoutes(context, listOf(route))

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
    }

    @Test
    fun `interface with tuntap type and nonstandard name emits NATIVE_INTERFACE evidence`() {
        val ifaces = listOf(
            NativeInterface(
                name = "mynet0", canonicalName = "mynet0", index = 9,
                flags = NativeInterface.IFF_UP, family = "inet",
                address = "10.9.0.2", netmask = "255.255.255.0", mtu = 1400,
                ifaceType = 65534,
            ),
        )
        val outcome = NativeSignsChecker.evaluateInterfaces(context, ifaces)
        assertTrue(outcome.detected)
        assertTrue(outcome.evidence.any { it.source == EvidenceSource.NATIVE_INTERFACE && it.detected })
    }

    @Suppress("unused")
    private fun referencedConfidence(): EvidenceConfidence = EvidenceConfidence.HIGH
}
