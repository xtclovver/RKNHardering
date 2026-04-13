package com.notcvnt.rknhardering.network

import com.notcvnt.rknhardering.probe.PublicIpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PublicIpClientResolverTest {
    @Before
    fun setUp() {
        ResolverNetworkStack.dnsFactoryOverride = null
        ResolverNetworkStack.resetForTests()
        PublicIpClient.resetForTests()
    }

    @After
    fun tearDown() {
        ResolverNetworkStack.dnsFactoryOverride = null
        ResolverNetworkStack.resetForTests()
        PublicIpClient.resetForTests()
    }

    @Test
    fun `public ip client uses direct resolver config for DNS lookup and fetch`() {
        MockWebServer().use { webServer ->
            webServer.enqueue(MockResponse().setResponseCode(200).setBody("203.0.113.10\n"))

            FakeDnsServer(
                records = mapOf(
                    "resolver-test.local" to FakeDnsServer.Record(ipv4 = "127.0.0.1"),
                ),
            ).use { dnsServer ->
                ResolverNetworkStack.dnsFactoryOverride = { _, _ ->
                    DirectDns(listOf("127.0.0.1"), port = dnsServer.port, timeoutMs = 1_000)
                }
                ResolverNetworkStack.resetForTests()

                val config = DnsResolverConfig(
                    mode = DnsResolverMode.DIRECT,
                    preset = DnsResolverPreset.CUSTOM,
                    customDirectServers = listOf("127.0.0.1"),
                )
                val endpoint = "http://resolver-test.local:${webServer.port}/ip"

                val dnsRecords = PublicIpClient.resolveDnsRecords(endpoint, config)
                val ipResult = PublicIpClient.fetchIp(endpoint, timeoutMs = 2_000, resolverConfig = config)

                assertEquals(listOf("127.0.0.1"), dnsRecords.ipv4Records)
                assertTrue(ipResult.isSuccess)
                assertEquals("203.0.113.10", ipResult.getOrNull())
            }
        }
    }

    @Test
    fun `public ip client shortens html 403 response to concise message`() {
        MockWebServer().use { webServer ->
            webServer.enqueue(
                MockResponse()
                    .setResponseCode(403)
                    .setBody(
                        """
                        <!DOCTYPE html>
                        <html>
                        <head><title>403</title></head>
                        <body>Access denied</body>
                        </html>
                        """.trimIndent(),
                    ),
            )

            val result = PublicIpClient.fetchIp(
                endpoint = webServer.url("/ip").toString(),
                timeoutMs = 2_000,
            )

            assertFalse(result.isSuccess)
            assertEquals("HTTP 403", result.exceptionOrNull()?.message)
        }
    }
}
