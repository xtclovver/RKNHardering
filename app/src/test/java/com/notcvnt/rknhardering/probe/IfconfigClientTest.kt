package com.notcvnt.rknhardering.probe

import android.net.Network
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class IfconfigClientTest {

    @After
    fun tearDown() {
        PublicIpClient.resetForTests()
    }

    @Test
    fun `fetch ip via network keeps primary then fallback order`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.20")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
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
        assertTrue(observedBindings.first() is ResolverBinding.AndroidNetworkBinding)
        val fallbackIndex = observedBindings.indexOfFirst { it is ResolverBinding.OsDeviceBinding }
        assertTrue(fallbackIndex > 0)
        assertTrue(observedBindings.take(fallbackIndex).all { it is ResolverBinding.AndroidNetworkBinding })
        val fallbackBinding = observedBindings[fallbackIndex] as ResolverBinding.OsDeviceBinding
        assertEquals("tun0", fallbackBinding.interfaceName)
        assertEquals(ResolverBinding.DnsMode.SYSTEM, fallbackBinding.dnsMode)
    }

    @Test
    fun `fetch direct ip prefers generic or ipv4 error over trailing ipv6-only failure`() {
        PublicIpClient.fetchIpOverride = { endpoint, _, _, _, _ ->
            when {
                endpoint.contains("ipv6-internet.yandex.net") ->
                    Result.failure(IOException("Unable to resolve host \"ipv6-internet.yandex.net\""))
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

    private fun newNetwork(netId: Int): Network {
        val constructor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(netId)
    }
}
