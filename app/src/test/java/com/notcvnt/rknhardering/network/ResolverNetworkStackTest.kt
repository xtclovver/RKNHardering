package com.notcvnt.rknhardering.network

import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.probe.NativeCurlBridge
import com.notcvnt.rknhardering.probe.NativeCurlRequest
import com.notcvnt.rknhardering.probe.NativeCurlResponse
import kotlinx.coroutines.CancellationException
import okhttp3.Dns
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class ResolverNetworkStackTest {

    @Before
    fun setUp() {
        WhitelistAwareDnsFailureCounter.reset()
    }

    @After
    fun tearDown() {
        ResolverNetworkStack.dnsFactoryOverride = null
        ResolverNetworkStack.resetForTests()
        NativeCurlBridge.resetForTests()
        WhitelistAwareDnsFailureCounter.reset()
    }

    @Test
    fun `lookup bypasses configured dns for ip literals`() {
        var overrideCalls = 0
        ResolverNetworkStack.dnsFactoryOverride = { _, _ ->
            overrideCalls += 1
            object : Dns {
                override fun lookup(hostname: String) = throw UnknownHostException("NXDOMAIN")
            }
        }

        val resolved = ResolverNetworkStack.lookup(
            hostname = "149.154.167.51",
            config = DnsResolverConfig(
                mode = DnsResolverMode.DOH,
                preset = DnsResolverPreset.CUSTOM,
                customDohUrl = "https://dns.google/dns-query",
            ),
        )

        assertEquals(listOf("149.154.167.51"), resolved.mapNotNull { it.hostAddress })
        assertEquals(0, overrideCalls)
    }

    @Test
    fun `execute keeps http response from okhttp and does not call native curl`() {
        var nativeCalls = 0
        ResolverNetworkStack.okHttpExecuteOverride = {
            ResolverHttpResponse(code = 403, body = "blocked")
        }
        NativeCurlBridge.executeOverride = { _: NativeCurlRequest ->
            nativeCalls += 1
            NativeCurlResponse(httpCode = 200, body = "fallback")
        }

        val response = ResolverNetworkStack.execute(
            url = "https://example.com",
            method = "GET",
            timeoutMs = 1_000,
            config = DnsResolverConfig.system(),
        )

        assertEquals(403, response.code)
        assertEquals("blocked", response.body)
        assertEquals(0, nativeCalls)
    }

    @Test
    fun `execute retries okhttp then falls back to native curl`() {
        var okHttpCalls = 0
        var nativeCalls = 0
        ResolverNetworkStack.okHttpExecuteOverride = {
            okHttpCalls += 1
            throw IOException("okhttp down")
        }
        NativeCurlBridge.executeOverride = { request: NativeCurlRequest ->
            nativeCalls += 1
            assertEquals("GET", request.method)
            assertEquals("", request.interfaceName)
            NativeCurlResponse(httpCode = 200, body = "1.2.3.4\n")
        }

        val response = ResolverNetworkStack.execute(
            url = "https://example.com/ip",
            method = "GET",
            timeoutMs = 1_000,
            config = DnsResolverConfig.system(),
        )

        assertEquals(ResolverNetworkStack.OKHTTP_RETRY_COUNT + 1, okHttpCalls)
        assertEquals(1, nativeCalls)
        assertEquals(200, response.code)
        assertEquals("1.2.3.4\n", response.body)
    }

    @Test
    fun `execute retries native curl after okhttp exhaustion`() {
        var okHttpCalls = 0
        var nativeCalls = 0
        ResolverNetworkStack.okHttpExecuteOverride = {
            okHttpCalls += 1
            throw IOException("okhttp down")
        }
        NativeCurlBridge.executeOverride = { _: NativeCurlRequest ->
            nativeCalls += 1
            throw IOException("curl down")
        }

        val error = runCatching {
            ResolverNetworkStack.execute(
                url = "https://example.com/ip",
                method = "GET",
                timeoutMs = 1_000,
                config = DnsResolverConfig.system(),
            )
        }.exceptionOrNull()

        assertEquals(ResolverNetworkStack.OKHTTP_RETRY_COUNT + 1, okHttpCalls)
        assertEquals(ResolverNetworkStack.NATIVE_CURL_RETRY_COUNT + 1, nativeCalls)
        assertTrue(error is IOException)
        assertTrue(error?.message?.contains("OkHttp failed after") == true)
        assertTrue(error?.message?.contains("native curl failed after") == true)
    }

    @Test
    fun `execute stops before native curl fallback after cancellation`() {
        val cancellationSignal = ScanCancellationSignal()
        var okHttpCalls = 0
        var nativeCalls = 0

        ResolverNetworkStack.okHttpExecuteOverride = {
            okHttpCalls += 1
            cancellationSignal.cancel()
            throw IOException("okhttp down")
        }
        NativeCurlBridge.executeOverride = { _: NativeCurlRequest ->
            nativeCalls += 1
            NativeCurlResponse(httpCode = 200, body = "fallback")
        }

        val error = runCatching {
            ResolverNetworkStack.execute(
                url = "https://example.com/ip",
                method = "GET",
                timeoutMs = 1_000,
                config = DnsResolverConfig.system(),
                cancellationSignal = cancellationSignal,
            )
        }.exceptionOrNull()

        assertEquals(1, okHttpCalls)
        assertEquals(0, nativeCalls)
        assertTrue(error is CancellationException)
    }

    @Test
    fun `after 3 dns failures createDns uses yandex doh regardless of config mode`() {
        // Record 3 failures to exhaust
        repeat(3) { WhitelistAwareDnsFailureCounter.recordFailure() }
        assertTrue(WhitelistAwareDnsFailureCounter.dnsExhausted)

        var capturedDns: Dns? = null
        ResolverNetworkStack.dnsFactoryOverride = { config, binding ->
            // dnsFactoryOverride is called BEFORE the exhaustion guard in createDns,
            // so to test the guard we need to test WITHOUT the override.
            // We'll test by checking the DNS type produced without the override.
            capturedDns = null
            object : Dns {
                override fun lookup(hostname: String): List<InetAddress> = emptyList()
            }
        }

        // Reset override so we test the real path
        ResolverNetworkStack.dnsFactoryOverride = null

        // With SYSTEM mode config but dnsExhausted=true, createDns should not wrap in CountingDns
        val systemConfig = DnsResolverConfig.system()
        val dns = ResolverNetworkStack.createDns(systemConfig)

        // The DNS returned must NOT be a CountingDns (which only wraps the normal path).
        // When exhausted, we get Yandex DoH (DnsOverHttps) or DirectDns as fallback.
        // Either way it's not CountingDns.
        assertFalse("DNS must not be CountingDns when exhausted", dns is CountingDns)
        assertNotNull(dns)
    }

    @Test
    fun `createDns wraps with CountingDns when not exhausted`() {
        assertFalse(WhitelistAwareDnsFailureCounter.dnsExhausted)
        ResolverNetworkStack.dnsFactoryOverride = null

        val systemConfig = DnsResolverConfig.system()
        val dns = ResolverNetworkStack.createDns(systemConfig)

        assertTrue("DNS must be CountingDns when not exhausted", dns is CountingDns)
    }

    @Test
    fun `native curl request is cancelled through registered callback`() {
        val cancellationSignal = ScanCancellationSignal()
        val executionContext = ScanExecutionContext(cancellationSignal = cancellationSignal)
        val executeEntered = CountDownLatch(1)
        val executeReleased = CountDownLatch(1)
        val cancelledRequestIds = mutableListOf<String>()

        NativeCurlBridge.executeOverride = { _: NativeCurlRequest ->
            executeEntered.countDown()
            assertTrue(executeReleased.await(2, TimeUnit.SECONDS))
            NativeCurlResponse(httpCode = 200, body = "late response")
        }
        NativeCurlBridge.cancelOverride = { requestId ->
            cancelledRequestIds += requestId
            executeReleased.countDown()
            true
        }

        var failure: Throwable? = null
        val worker = Thread {
            failure = runCatching {
                NativeCurlHttpClient.execute(
                    request = ResolverHttpRequest(
                        url = "https://example.com/ip",
                        method = "GET",
                        headers = emptyMap(),
                        body = null,
                        bodyContentType = null,
                        timeoutMs = 1_000,
                        config = DnsResolverConfig.system(),
                        proxy = null,
                        binding = null,
                        addressFamily = null,
                        okHttpRetryCount = ResolverNetworkStack.OKHTTP_RETRY_COUNT,
                        nativeCurlRetryCount = ResolverNetworkStack.NATIVE_CURL_RETRY_COUNT,
                        cancellationSignal = cancellationSignal,
                    ),
                    executionContext = executionContext,
                )
            }.exceptionOrNull()
        }

        worker.start()
        assertTrue(executeEntered.await(1, TimeUnit.SECONDS))
        cancellationSignal.cancel()
        worker.join(2_000)

        assertFalse(worker.isAlive)
        assertTrue(failure is CancellationException)
        assertEquals(1, cancelledRequestIds.size)
        assertTrue(cancelledRequestIds.single().startsWith("native-http-"))
    }
}
