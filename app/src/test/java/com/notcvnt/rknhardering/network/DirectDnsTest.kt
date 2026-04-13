package com.notcvnt.rknhardering.network

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.UnknownHostException

class DirectDnsTest {
    @After
    fun tearDown() {
        ResolverNetworkStack.resetForTests()
    }

    @Test
    fun `direct dns resolves ipv4 and ipv6 from configured server`() {
        FakeDnsServer(
            records = mapOf(
                "resolver-test.local" to FakeDnsServer.Record(
                    ipv4 = "127.0.0.1",
                    ipv6 = "2001:db8::1",
                ),
            ),
        ).use { server ->
            val dns = DirectDns(listOf("127.0.0.1"), port = server.port, timeoutMs = 1_000)

            val resolved = dns.lookup("resolver-test.local")

            assertTrue(resolved.any { it.hostAddress == "127.0.0.1" })
            assertTrue(resolved.any { it.hostAddress == InetAddress.getByName("2001:db8::1").hostAddress })
        }
    }

    @Test(expected = UnknownHostException::class)
    fun `direct dns surfaces nxdomain from configured server`() {
        FakeDnsServer(
            records = mapOf(
                "missing.local" to FakeDnsServer.Record(nxdomain = true),
            ),
        ).use { server ->
            val dns = DirectDns(listOf("127.0.0.1"), port = server.port, timeoutMs = 1_000)
            dns.lookup("missing.local")
        }
    }

    @Test
    fun `literal ip lookup bypasses dns query`() {
        val dns = DirectDns(listOf("127.0.0.1"))

        val resolved = dns.lookup("203.0.113.5")

        assertEquals(listOf("203.0.113.5"), resolved.mapNotNull { it.hostAddress })
    }

    @Test
    fun `direct dns uses os device binding for udp sockets`() {
        val boundInterfaces = mutableListOf<String>()
        ResolverSocketBinder.bindDatagramToDeviceOverride = { _, interfaceName ->
            boundInterfaces += interfaceName
        }

        FakeDnsServer(
            records = mapOf(
                "resolver-test.local" to FakeDnsServer.Record(
                    ipv4 = "127.0.0.1",
                    ipv6 = "2001:db8::1",
                ),
            ),
        ).use { server ->
            val dns = DirectDns(
                servers = listOf("127.0.0.1"),
                port = server.port,
                timeoutMs = 1_000,
                binding = ResolverBinding.OsDeviceBinding("tun0"),
            )

            dns.lookup("resolver-test.local")
        }

        assertTrue(boundInterfaces.isNotEmpty())
        assertTrue(boundInterfaces.all { it == "tun0" })
    }
}
