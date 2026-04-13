package com.notcvnt.rknhardering.network

import okhttp3.Dns
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ResolverBindingTest {

    @After
    fun tearDown() {
        ResolverNetworkStack.resetForTests()
    }

    @Test
    fun `bind to device socket factory binds unconnected socket before connect`() {
        val boundInterfaces = mutableListOf<String>()
        ResolverSocketBinder.bindSocketToDeviceOverride = { socket, interfaceName ->
            assertFalse(socket.isConnected)
            boundInterfaces += interfaceName
        }

        BindToDeviceSocketFactory("tun0").createSocket().use { socket ->
            assertFalse(socket.isConnected)
        }

        assertEquals(listOf("tun0"), boundInterfaces)
    }

    @Test
    fun `build client uses bind to device socket factory for os device binding`() {
        val client = ResolverNetworkStack.buildClient(
            config = DnsResolverConfig.system(),
            dns = Dns.SYSTEM,
            binding = ResolverBinding.OsDeviceBinding("tun0"),
        )

        assertTrue(client.socketFactory is BindToDeviceSocketFactory)
    }

    @Test
    fun `os device binding can preserve system dns semantics for fallback path`() {
        val config = DnsResolverConfig(
            mode = DnsResolverMode.DOH,
            preset = DnsResolverPreset.CUSTOM,
            customDohUrl = "https://dns.example/dns-query",
        )

        val dns = ResolverNetworkStack.createDns(
            config = config,
            binding = ResolverBinding.OsDeviceBinding(
                interfaceName = "tun0",
                dnsMode = ResolverBinding.DnsMode.SYSTEM,
            ),
        )

        assertSame(Dns.SYSTEM, dns)
    }

    @Test
    fun `os device binding keeps doh bootstrap client on bind to device socket factory`() {
        val config = DnsResolverConfig(
            mode = DnsResolverMode.DOH,
            preset = DnsResolverPreset.CUSTOM,
            customDohUrl = "https://dns.example/dns-query",
            customDohBootstrapHosts = listOf("1.1.1.1"),
        )

        val dns = ResolverNetworkStack.createDns(
            config = config,
            binding = ResolverBinding.OsDeviceBinding("tun0"),
        )

        val clientField = dns.javaClass.getDeclaredField("client")
        clientField.isAccessible = true
        val client = clientField.get(dns) as OkHttpClient

        assertTrue(dns.javaClass.simpleName == "DnsOverHttps")
        assertTrue(client.socketFactory is BindToDeviceSocketFactory)
    }
}
