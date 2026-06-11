package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
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
    fun `host route to public ip via physical interface emits NATIVE_ROUTE evidence`() {
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
                prefixLen = 32,
            ),
        )
        val outcome = NativeSignsChecker.evaluateHostRoutes(context, routes)
        assertTrue(outcome.detected)
        assertTrue(outcome.evidence.any { it.source == EvidenceSource.NATIVE_ROUTE && it.detected })
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

    @Suppress("unused")
    private fun referencedConfidence(): EvidenceConfidence = EvidenceConfidence.HIGH
}
