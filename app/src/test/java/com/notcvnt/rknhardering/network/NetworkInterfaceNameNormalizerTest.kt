package com.notcvnt.rknhardering.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkInterfaceNameNormalizerTest {

    @Test
    fun `canonicalizes stacked clat wifi and mobile interfaces`() {
        assertEquals("wlan0", NetworkInterfaceNameNormalizer.canonicalName("v4-wlan0"))
        assertEquals("rmnet_data0", NetworkInterfaceNameNormalizer.canonicalName("v4-rmnet_data0"))
        assertEquals("eth0", NetworkInterfaceNameNormalizer.canonicalName("v4-eth0"))
        assertEquals("ccmni0", NetworkInterfaceNameNormalizer.canonicalName("v4-ccmni0"))
    }

    @Test
    fun `keeps unrelated v4 prefixed interfaces unchanged`() {
        assertEquals("v4-tun0", NetworkInterfaceNameNormalizer.canonicalName("v4-tun0"))
        assertEquals("tun0", NetworkInterfaceNameNormalizer.canonicalName("tun0"))
    }

    @Test
    fun `passes through null and blank names`() {
        assertEquals(null, NetworkInterfaceNameNormalizer.canonicalName(null))
        assertEquals("", NetworkInterfaceNameNormalizer.canonicalName(""))
        assertEquals("  ", NetworkInterfaceNameNormalizer.canonicalName("  "))
    }

    @Test
    fun `seth and dummy are not de-stacked - pinned historical divergence`() {
        // seth/dummy are STANDARD_INTERFACES but deliberately absent from
        // STACKED_BASE_INTERFACES. Changing this is a detection-behavior
        // decision, not a refactoring; see NetworkInterfacePatterns.
        assertEquals("v4-seth0", NetworkInterfaceNameNormalizer.canonicalName("v4-seth0"))
        assertEquals("v4-dummy0", NetworkInterfaceNameNormalizer.canonicalName("v4-dummy0"))
        assertTrue(NetworkInterfacePatterns.isStandardInterface("seth0"))
        assertFalse(NetworkInterfacePatterns.isStandardInterface("v4-seth0"))
    }

    @Test
    fun `stacked base patterns are a strict subset of standard interfaces`() {
        val standard = NetworkInterfacePatterns.STANDARD_INTERFACES.map { it.pattern }.toSet()
        val stackedBases = NetworkInterfacePatterns.STACKED_BASE_INTERFACES.map { it.pattern }

        stackedBases.forEach { pattern ->
            assertTrue("stacked base $pattern missing from STANDARD_INTERFACES", pattern in standard)
        }
        assertTrue(stackedBases.size < standard.size)
    }

    @Test
    fun `vpn classification works on stacked names via canonicalization`() {
        // "v4-tun0" stays as-is (tun is not a stacked base), so the full-match
        // VPN pattern does not fire on it. Pinned current behavior.
        assertFalse(NetworkInterfacePatterns.isVpnInterface("v4-tun0"))
        assertTrue(NetworkInterfacePatterns.isVpnInterface("tun0"))
        assertFalse(NetworkInterfacePatterns.isVpnInterface("v4-wlan0"))
        assertTrue(NetworkInterfacePatterns.isStandardInterface("v4-wlan0"))
    }
}
