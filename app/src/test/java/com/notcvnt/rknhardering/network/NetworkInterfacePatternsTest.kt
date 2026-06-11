package com.notcvnt.rknhardering.network

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkInterfacePatternsTest {

    @Test
    fun `matches new tunnel interface prefixes`() {
        val tunnelNames = listOf(
            "utun0", "xfrm1", "zt0", "ztabcd1234", "tailscale0",
            "svpn0", "gre0", "l2tp0", "he-ipv6",
        )
        for (name in tunnelNames) {
            assertTrue("expected $name to be VPN-like", NetworkInterfacePatterns.isVpnInterface(name))
        }
    }

    @Test
    fun `does not match ordinary interfaces resembling tunnel prefixes`() {
        val ordinary = listOf("grenade0", "wlan0", "rmnet_data0", "eth0", "lo")
        for (name in ordinary) {
            assertFalse("expected $name to NOT be VPN-like", NetworkInterfacePatterns.isVpnInterface(name))
        }
    }
}
