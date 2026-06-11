package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeInterfaceProbeTest {

    @Test
    fun `parseIfAddrRow parses valid row`() {
        val row = "tun0|42|69|AF_INET|10.8.0.2|255.255.255.0|1420"
        val iface = NativeInterfaceProbe.parseIfAddrRow(row)

        assertNotNull(iface)
        iface!!
        assertEquals("tun0", iface.name)
        assertEquals(42, iface.index)
        assertEquals(69L, iface.flags)
        assertEquals("AF_INET", iface.family)
        assertEquals("10.8.0.2", iface.address)
        assertEquals("255.255.255.0", iface.netmask)
        assertEquals(1420, iface.mtu)
        assertTrue(iface.isUp)
        assertFalse(iface.isLoopback)
    }

    @Test
    fun `parseIfAddrRow reads interface type from eighth column`() {
        val row = "tun0|5|4163|inet|10.8.0.2|255.255.255.0|1500|65534"
        val iface = NativeInterfaceProbe.parseIfAddrRow(row)
        assertNotNull(iface)
        assertEquals(65534, iface!!.ifaceType)
    }

    @Test
    fun `parseIfAddrRow tolerates legacy seven-column rows`() {
        val row = "wlan0|3|4163|inet|192.168.1.5|255.255.255.0|1500"
        val iface = NativeInterfaceProbe.parseIfAddrRow(row)
        assertNotNull(iface)
        assertEquals(null, iface!!.ifaceType)
    }

    @Test
    fun `parseIfAddrRow handles empty address and mask`() {
        val row = "wlan0|3|65|AF_PACKET|||1500"
        val iface = NativeInterfaceProbe.parseIfAddrRow(row)

        assertNotNull(iface)
        iface!!
        assertEquals("wlan0", iface.name)
        assertEquals(3, iface.index)
        assertEquals("AF_PACKET", iface.family)
        assertNull(iface.address)
        assertNull(iface.netmask)
        assertEquals(1500, iface.mtu)
    }

    @Test
    fun `parseIfAddrRow rejects malformed rows`() {
        assertNull(NativeInterfaceProbe.parseIfAddrRow(""))
        assertNull(NativeInterfaceProbe.parseIfAddrRow("tun0|42|69"))
        assertNull(NativeInterfaceProbe.parseIfAddrRow("too|few|parts|only|five|six"))
    }

    @Test
    fun `parseProcRoute extracts default route`() {
        val content = """
            Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
            wlan0	00000000	0100A8C0	0003	0	0	0	00000000	0	0	0
            wlan0	0000A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
        """.trimIndent()

        val routes = NativeInterfaceProbe.parseProcRoute(content)
        assertEquals(2, routes.size)

        val defaultRoute = routes.first { it.isDefault }
        assertEquals("wlan0", defaultRoute.interfaceName)
        assertEquals("00000000", defaultRoute.destinationHex)

        val nonDefault = routes.first { !it.isDefault }
        assertEquals("0000A8C0", nonDefault.destinationHex)
    }

    @Test
    fun `parseProcRoute handles null and blank`() {
        assertTrue(NativeInterfaceProbe.parseProcRoute(null).isEmpty())
        assertTrue(NativeInterfaceProbe.parseProcRoute("").isEmpty())
        assertTrue(NativeInterfaceProbe.parseProcRoute("   ").isEmpty())
    }

    @Test
    fun `parseProcIpv6Route extracts default route`() {
        val content = """
            00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 tun0
            20010DB8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000001 wlan0
        """.trimIndent()

        val routes = NativeInterfaceProbe.parseProcIpv6Route(content)

        assertEquals(2, routes.size)
        val defaultRoute = routes.first { it.isDefault }
        assertEquals("tun0", defaultRoute.interfaceName)
        assertEquals("00000000000000000000000000000000", defaultRoute.destinationHex)
    }

    @Test
    fun `parseMapsSummary extracts markers and rwx`() {
        val rows = arrayOf(
            "marker|frida-gadget|/data/local/tmp/frida-gadget.so",
            "marker|XposedBridge|/system/framework/XposedBridge.jar",
            "rwx_large|512",
            "garbage|data",
        )
        val findings = NativeInterfaceProbe.parseMapsSummary(rows)
        assertEquals(3, findings.size)
        assertTrue(findings.any { it.kind == "marker" && it.marker == "frida-gadget" })
        assertTrue(findings.any { it.kind == "marker" && it.marker == "XposedBridge" })
        assertTrue(findings.any { it.kind == "rwx_large" && it.detail == "512" })
    }

    @Test
    fun `parseLibraryIntegrity detects missing and foreign libs`() {
        val rows = arrayOf(
            "getifaddrs|0x7abc123|/apex/com.android.runtime/lib64/bionic/libc.so",
            "if_nametoindex||missing",
            "socket|0xdeadbeef|/data/local/tmp/hook.so",
        )
        val syms = NativeInterfaceProbe.parseLibraryIntegrity(rows)
        assertEquals(3, syms.size)

        val ok = syms.first { it.symbol == "getifaddrs" }
        assertFalse(ok.missing)
        assertTrue(ok.library!!.contains("libc.so"))

        val missing = syms.first { it.symbol == "if_nametoindex" }
        assertTrue(missing.missing)
        assertNull(missing.library)

        val hooked = syms.first { it.symbol == "socket" }
        assertFalse(hooked.missing)
        assertEquals("/data/local/tmp/hook.so", hooked.library)
    }

    @Test
    fun `parseNetlinkRoutes preserves prefix length for host routes`() {
        val rows = arrayOf(
            "route|family=2|dst=203.0.113.7/32|via=192.168.1.1|dev=wlan0|oif=5",
            "route|family=2|dst=10.8.0.0/24|dev=tun0|oif=7",
        )
        val parsed = NativeInterfaceProbe.parseNetlinkRoutes(rows)
        val hostRoute = parsed.first { it.destination == "203.0.113.7" }
        assertEquals(32, hostRoute.prefixLen)
        val subnet = parsed.first { it.destination == "10.8.0.0" }
        assertEquals(24, subnet.prefixLen)
    }
}
