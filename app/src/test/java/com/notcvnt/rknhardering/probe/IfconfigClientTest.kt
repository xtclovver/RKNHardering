package com.notcvnt.rknhardering.probe

import android.net.Network
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import com.notcvnt.rknhardering.network.ResolverBinding
import okhttp3.Dns
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import java.net.InetAddress

@RunWith(RobolectricTestRunner::class)
class IfconfigClientTest {

    @After
    fun tearDown() {
        PublicIpClient.resetForTests()
        NativeCurlBridge.resetForTests()
        ResolverNetworkStack.dnsFactoryOverride = null
        ResolverNetworkStack.resetForTests()
    }

    @Test
    fun `fetch ip via network keeps primary then fallback order`() {
        val events = mutableListOf<String>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            events += "strict:${binding?.javaClass?.simpleName}"
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                null -> Result.failure(IOException("unexpected unbound path"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }
        NativeCurlBridge.executeOverride = { request ->
            events += "native:${request.interfaceName}"
            NativeCurlResponse(
                curlCode = 0,
                httpCode = 200,
                body = "203.0.113.20",
            )
        }

        val result = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetwork(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(202)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertTrue(result.isSuccess)
        assertEquals("203.0.113.20", result.getOrNull())
        assertEquals("strict:AndroidNetworkBinding", events.first())
        assertTrue(events.any { it == "native:tun0" })
    }

    @Test
    fun `fetch ip via network combines primary and fallback errors when both bindings fail`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                null -> Result.failure(IOException("unexpected unbound path"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }
        NativeCurlBridge.executeOverride = {
            NativeCurlResponse(localError = "device path failed")
        }

        val result = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetwork(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(203)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertTrue(result.isFailure)
        assertEquals(
            "Android Network binding failed: primary path failed; SO_BINDTODEVICE(tun0) failed: device path failed",
            result.exceptionOrNull()?.message,
        )
    }

    @Test
    fun `network comparison marks dns path mismatch when curl compatible succeeds after strict failure`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("strict failed"))
                null -> Result.failure(IOException("unexpected unbound path"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }
        NativeCurlBridge.executeOverride = {
            NativeCurlResponse(
                curlCode = 0,
                httpCode = 200,
                body = "203.0.113.21",
            )
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(204)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                collectTrace = true,
            )
        }

        assertEquals(PublicIpProbeStatus.FAILED, comparison.strict.status)
        assertEquals(PublicIpProbeStatus.SUCCEEDED, comparison.curlCompatible.status)
        assertEquals(PublicIpProbeMode.CURL_COMPATIBLE, comparison.selectedMode)
        assertEquals("203.0.113.21", comparison.selectedIp)
        assertTrue(comparison.dnsPathMismatch)
        assertFalse(comparison.strict.endpointAttempts.isEmpty())
        assertFalse(comparison.curlCompatible.endpointAttempts.isEmpty())
        assertEquals(TunProbeEngine.NATIVE_LIBCURL, comparison.curlCompatible.transportDiagnostics.engine)
    }

    @Test
    fun `network comparison still runs curl compatible branch after strict success`() {
        var nativeCalls = 0
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.success("198.51.100.10")
                null -> Result.failure(IOException("unexpected unbound path"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }
        NativeCurlBridge.executeOverride = {
            nativeCalls++
            NativeCurlResponse(
                curlCode = 0,
                httpCode = 200,
                body = "203.0.113.22",
            )
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(205)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                collectTrace = true,
            )
        }

        assertEquals(PublicIpProbeMode.STRICT_SAME_PATH, comparison.selectedMode)
        assertEquals("198.51.100.10", comparison.selectedIp)
        assertEquals(PublicIpProbeStatus.SUCCEEDED, comparison.curlCompatible.status)
        assertEquals(1, nativeCalls)
    }

    @Test
    fun `fetch direct ip supports one okhttp and one native curl attempt`() {
        var okHttpCalls = 0
        var nativeCalls = 0
        ResolverNetworkStack.okHttpExecuteOverride = { request ->
            okHttpCalls += 1
            assertEquals(4_000, request.timeoutMs)
            assertEquals(0, request.okHttpRetryCount)
            assertEquals(0, request.nativeCurlRetryCount)
            throw IOException("okhttp down")
        }
        NativeCurlBridge.executeOverride = { request ->
            nativeCalls += 1
            assertEquals(4_000, request.timeoutMs)
            NativeCurlResponse(
                curlCode = 0,
                httpCode = 200,
                body = "203.0.113.55",
            )
        }

        val result = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchDirectIp(
                timeoutMs = 4_000,
                resolverConfig = DnsResolverConfig.system(),
                okHttpRetryCount = 0,
                nativeCurlRetryCount = 0,
            )
        }

        assertTrue(result.isSuccess)
        assertEquals("203.0.113.55", result.getOrNull())
        assertEquals(1, okHttpCalls)
        assertEquals(1, nativeCalls)
    }

    @Test
    fun `network comparison forwards custom timeout into strict and curl compatible probes`() {
        var okHttpCalls = 0
        var nativeCalls = 0
        ResolverNetworkStack.okHttpExecuteOverride = { request ->
            okHttpCalls += 1
            assertEquals(4_000, request.timeoutMs)
            assertEquals(0, request.okHttpRetryCount)
            assertEquals(0, request.nativeCurlRetryCount)
            throw IOException("strict failed")
        }
        NativeCurlBridge.executeOverride = { request ->
            nativeCalls += 1
            assertEquals(4_000, request.timeoutMs)
            NativeCurlResponse(
                curlCode = 0,
                httpCode = 200,
                body = "203.0.113.56",
            )
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(211)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                timeoutMs = 4_000,
                resolverConfig = DnsResolverConfig.system(),
                okHttpRetryCount = 0,
                nativeCurlRetryCount = 0,
            )
        }

        assertTrue(okHttpCalls >= 1)
        assertEquals(1, nativeCalls)
        assertEquals(PublicIpProbeMode.CURL_COMPATIBLE, comparison.selectedMode)
        assertEquals("203.0.113.56", comparison.selectedIp)
    }

    @Test
    fun `strict override skips curl compatible branch`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.success("198.51.100.11")
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.31")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(207)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                modeOverride = TunProbeModeOverride.STRICT_SAME_PATH,
            )
        }

        assertEquals(PublicIpProbeMode.STRICT_SAME_PATH, comparison.selectedMode)
        assertEquals(PublicIpProbeStatus.SKIPPED, comparison.curlCompatible.status)
        assertEquals("Disabled by override", comparison.curlCompatible.error)
        assertTrue(observedBindings.all { it is ResolverBinding.AndroidNetworkBinding })
    }

    @Test
    fun `curl compatible override skips strict branch`() {
        val strictCalls = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            strictCalls += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("strict should not run"))
                null -> Result.failure(IOException("unexpected unbound path"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }
        NativeCurlBridge.executeOverride = {
            NativeCurlResponse(
                curlCode = 0,
                httpCode = 200,
                body = "203.0.113.32",
            )
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(208)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                modeOverride = TunProbeModeOverride.CURL_COMPATIBLE,
            )
        }

        assertEquals(PublicIpProbeMode.CURL_COMPATIBLE, comparison.selectedMode)
        assertEquals(PublicIpProbeStatus.SKIPPED, comparison.strict.status)
        assertEquals("Disabled by override", comparison.strict.error)
        assertTrue(strictCalls.isEmpty())
    }

    @Test
    fun `forced curl compatible reports missing interface clearly`() {
        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(209)),
                fallbackBinding = null,
                resolverConfig = DnsResolverConfig.system(),
                modeOverride = TunProbeModeOverride.CURL_COMPATIBLE,
            )
        }

        assertEquals(PublicIpProbeStatus.SKIPPED, comparison.curlCompatible.status)
        assertEquals(null, comparison.selectedMode)
        assertEquals(
            "OS device bind fallback is unavailable because interfaceName is missing",
            comparison.selectedError,
        )
    }

    @Test
    fun `network comparison marks curl compatible branch as skipped when interface is missing`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("strict failed"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(206)),
                fallbackBinding = null,
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertEquals(PublicIpProbeStatus.SKIPPED, comparison.curlCompatible.status)
        assertEquals(
            "OS device bind fallback is unavailable because interfaceName is missing",
            comparison.curlCompatible.error,
        )
        assertEquals("strict failed; OS device bind fallback is unavailable because interfaceName is missing", comparison.selectedError)
        assertEquals(null, comparison.selectedMode)
        assertFalse(comparison.dnsPathMismatch)
    }

    @Test
    fun `network comparison uses exact target url for strict and curl compatible probes`() {
        val requestedEndpoints = mutableListOf<String>()
        PublicIpClient.fetchIpOverride = { endpoint, _, _, _, binding ->
            requestedEndpoints += "strict:$endpoint:${binding?.javaClass?.simpleName}"
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("strict failed"))
                null -> Result.failure(IOException("unexpected unbound path"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }
        NativeCurlBridge.executeOverride = { request ->
            requestedEndpoints += "curl:${request.url}"
            NativeCurlResponse(
                curlCode = 0,
                httpCode = 200,
                body = "203.0.113.57",
            )
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(212)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                targetUrls = listOf("https://ipv4-internet.yandex.net/api/v0/ip"),
            )
        }

        assertEquals(PublicIpProbeMode.CURL_COMPATIBLE, comparison.selectedMode)
        assertTrue(
            requestedEndpoints.contains(
                "strict:https://ipv4-internet.yandex.net/api/v0/ip:AndroidNetworkBinding",
            ),
        )
        assertTrue(requestedEndpoints.contains("curl:https://ipv4-internet.yandex.net/api/v0/ip"))
    }

    @Test
    fun `network comparison falls back to next custom target url`() {
        val strictEndpoints = mutableListOf<String>()
        PublicIpClient.fetchIpOverride = { endpoint, _, _, _, binding ->
            strictEndpoints += endpoint
            when {
                binding is ResolverBinding.AndroidNetworkBinding && endpoint.contains("checkip.amazonaws.com") ->
                    Result.failure(IOException("connection closed"))
                binding is ResolverBinding.AndroidNetworkBinding && endpoint.contains("api-ipv4.ip.sb") ->
                    Result.success("203.0.113.58")
                binding == null -> Result.failure(IOException("unexpected unbound path"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(213)),
                fallbackBinding = null,
                resolverConfig = DnsResolverConfig.system(),
                targetUrls = listOf(
                    "https://checkip.amazonaws.com",
                    "https://api-ipv4.ip.sb/ip",
                ),
            )
        }

        assertEquals(PublicIpProbeMode.STRICT_SAME_PATH, comparison.selectedMode)
        assertEquals("203.0.113.58", comparison.selectedIp)
        assertEquals(
            listOf("https://checkip.amazonaws.com", "https://api-ipv4.ip.sb/ip"),
            strictEndpoints,
        )
    }

    @Test
    fun `curl compatible uses injected resolve for direct resolver`() {
        var observedBinding: ResolverBinding? = null
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("strict failed"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }
        ResolverNetworkStack.dnsFactoryOverride = { _, binding ->
            observedBinding = binding
            object : Dns {
                override fun lookup(hostname: String): List<InetAddress> {
                    if (hostname == "ifconfig.me") {
                        return listOf(InetAddress.getByName("93.184.216.34"))
                    }
                    throw java.net.UnknownHostException(hostname)
                }
            }
        }
        NativeCurlBridge.executeOverride = { request ->
            assertEquals(1, request.resolveRules.size)
            assertEquals("ifconfig.me", request.resolveRules.single().host)
            assertTrue(request.resolveRules.single().addresses.isNotEmpty())
            NativeCurlResponse(
                curlCode = 0,
                httpCode = 200,
                body = "203.0.113.45",
                resolvedAddressesUsed = request.resolveRules.single().addresses,
            )
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(210)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig(
                    mode = com.notcvnt.rknhardering.network.DnsResolverMode.DIRECT,
                    customDirectServers = listOf("1.1.1.1"),
                ),
            )
        }

        assertEquals(PublicIpProbeMode.CURL_COMPATIBLE, comparison.selectedMode)
        assertEquals(TunProbeResolveStrategy.KOTLIN_INJECTED, comparison.curlCompatible.transportDiagnostics.resolveStrategy)
        assertTrue(observedBinding is ResolverBinding.OsDeviceBinding)
        assertEquals("tun0", (observedBinding as ResolverBinding.OsDeviceBinding).interfaceName)
    }

    @Test
    fun `fetch direct ip prefers generic or ipv4 error over trailing ipv6-only failure`() {
        PublicIpClient.fetchIpOverride = { endpoint, _, _, _, _ ->
            when {
                endpoint.contains("api6.ipify.org") ->
                    Result.failure(IOException("Unable to resolve host \"api6.ipify.org\""))
                else ->
                    Result.failure(IOException("generic timeout"))
            }
        }

        val result = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchDirectIp(
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertTrue(result.isFailure)
        assertEquals("generic timeout", result.exceptionOrNull()?.message)
    }

    @Test
    fun `ipv6 endpoints are tried after all ipv4 and generic endpoints`() {
        val calledEndpoints = mutableListOf<String>()
        PublicIpClient.fetchIpOverride = { endpoint, _, _, _, _ ->
            calledEndpoints += endpoint
            Result.failure(IOException("fail"))
        }

        kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchDirectIp(
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        val ipv6Index = calledEndpoints.indexOfFirst { it.contains("api6.ipify.org") }
        assertTrue("IPv6 endpoint should be present", ipv6Index >= 0)
        // All endpoints before IPv6 should be non-IPv6
        for (i in 0 until ipv6Index) {
            assertTrue(
                "Non-IPv6 endpoint should come before IPv6: ${calledEndpoints[i]}",
                !calledEndpoints[i].contains("api6.ipify.org"),
            )
        }
        // IPv6 endpoint should be last
        assertEquals(calledEndpoints.lastIndex, ipv6Index)
    }

    private fun newNetwork(netId: Int): Network {
        val constructor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(netId)
    }
}
