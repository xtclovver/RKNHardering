package com.notcvnt.rknhardering.network

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkInterfacePatternsTest {

    @Test
    fun `matches new tunnel interface prefixes`() {
        val tunnelNames = listOf(
            "utun0", "zt0", "ztabcd1234", "tailscale0",
            "svpn0", "gre0", "l2tp0", "he-ipv6",
        )
        for (name in tunnelNames) {
            assertTrue("expected $name to be VPN-like", NetworkInterfacePatterns.isVpnInterface(name))
        }
    }

    @Test
    fun `does not match ordinary interfaces resembling tunnel prefixes`() {
        val ordinary = listOf("grenade0", "wlan0", "rmnet_data0", "eth0", "lo", "l2tpeth0", "xfrm0")
        for (name in ordinary) {
            assertFalse("expected $name to NOT be VPN-like", NetworkInterfacePatterns.isVpnInterface(name))
        }
    }

    @Test
    fun `xfrm interfaces are classified as ipsec not vpn`() {
        assertTrue(NetworkInterfacePatterns.isIpsecInterface("xfrm0"))
        assertFalse(NetworkInterfacePatterns.isVpnInterface("xfrm0"))
    }

    @Test
    fun `classifies cellular modem interfaces`() {
        val modemNames = listOf("rmnet_data0", "ccmni0", "ccemni1", "pdp0", "seth_lte0", "v4-ccmni0")
        for (name in modemNames) {
            assertTrue("expected $name to be cellular", NetworkInterfacePatterns.isCellularModemInterface(name))
        }
        assertFalse(NetworkInterfacePatterns.isCellularModemInterface("wlan0"))
        assertFalse(NetworkInterfacePatterns.isCellularModemInterface("eth0"))
    }
}
