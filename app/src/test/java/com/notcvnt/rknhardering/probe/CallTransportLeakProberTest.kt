package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.Network
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class CallTransportLeakProberTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        CallTransportLeakProber.dependenciesOverride = null
        PublicIpClient.resetForTests()
    }

    @Test
    fun `probeDirect keeps active path as baseline signal`() {
        CallTransportLeakProber.dependenciesOverride = CallTransportLeakProber.Dependencies(
            loadCatalog = { _, _ ->
                CallTransportTargetCatalog.Catalog(
                    telegramTargets = listOf(
                        CallTransportTargetCatalog.CallTransportTarget(
                            service = CallTransportService.TELEGRAM,
                            host = "149.154.167.51",
                            port = 3478,
                            experimental = false,
                            enabled = true,
                        ),
                    ),
                    whatsappTargets = emptyList(),
                )
            },
            loadPaths = {
                listOf(
                    CallTransportLeakProber.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                    ),
                )
            },
            stunProbe = { _, _, _ ->
                Result.success(
                    StunBindingClient.BindingResult(
                        resolvedIps = listOf("149.154.167.51"),
                        remoteIp = "149.154.167.51",
                        remotePort = 3478,
                        mappedIp = "198.51.100.20",
                        mappedPort = 40000,
                    ),
                )
            },
            publicIpFetcher = { _, _ -> Result.success("203.0.113.10") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NO_SIGNAL, telegram.status)
        assertEquals(CallTransportProbeKind.DIRECT_UDP_STUN, telegram.probeKind)
        assertEquals(CallTransportNetworkPath.ACTIVE, telegram.networkPath)
        assertEquals("149.154.167.51", telegram.targetHost)
        assertEquals("198.51.100.20", telegram.mappedIp)
        assertEquals("203.0.113.10", telegram.observedPublicIp)
    }

    @Test
    fun `probeDirect flags active vpn path when stun ip diverges from public ip`() {
        CallTransportLeakProber.dependenciesOverride = CallTransportLeakProber.Dependencies(
            loadCatalog = { _, _ ->
                CallTransportTargetCatalog.Catalog(
                    telegramTargets = listOf(
                        CallTransportTargetCatalog.CallTransportTarget(
                            service = CallTransportService.TELEGRAM,
                            host = "149.154.167.51",
                            port = 3478,
                            experimental = false,
                            enabled = true,
                        ),
                    ),
                    whatsappTargets = emptyList(),
                )
            },
            loadPaths = {
                listOf(
                    CallTransportLeakProber.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                        vpnProtected = true,
                    ),
                )
            },
            stunProbe = { _, _, _ ->
                Result.success(
                    StunBindingClient.BindingResult(
                        resolvedIps = listOf("149.154.167.51"),
                        remoteIp = "149.154.167.51",
                        remotePort = 3478,
                        mappedIp = "198.51.100.20",
                        mappedPort = 40000,
                    ),
                )
            },
            publicIpFetcher = { _, _ -> Result.success("203.0.113.10") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, telegram.status)
    }

    @Test
    fun `probeDirect flags explicit underlying path for review`() {
        CallTransportLeakProber.dependenciesOverride = CallTransportLeakProber.Dependencies(
            loadCatalog = { _, _ ->
                CallTransportTargetCatalog.Catalog(
                    telegramTargets = listOf(
                        CallTransportTargetCatalog.CallTransportTarget(
                            service = CallTransportService.TELEGRAM,
                            host = "149.154.167.51",
                            port = 3478,
                            experimental = false,
                            enabled = true,
                        ),
                    ),
                    whatsappTargets = emptyList(),
                )
            },
            loadPaths = {
                listOf(
                    CallTransportLeakProber.PathDescriptor(
                        path = CallTransportNetworkPath.UNDERLYING,
                    ),
                )
            },
            stunProbe = { _, _, _ ->
                Result.success(
                    StunBindingClient.BindingResult(
                        resolvedIps = listOf("149.154.167.51"),
                        remoteIp = "149.154.167.51",
                        remotePort = 3478,
                        mappedIp = "198.51.100.20",
                        mappedPort = 40000,
                    ),
                )
            },
            publicIpFetcher = { _, _ -> Result.success("198.51.100.20") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, telegram.status)
        assertEquals(CallTransportNetworkPath.UNDERLYING, telegram.networkPath)
    }

    @Test
    fun `probeDirect does not convert no response into telegram error`() {
        CallTransportLeakProber.dependenciesOverride = CallTransportLeakProber.Dependencies(
            loadCatalog = { _, _ ->
                CallTransportTargetCatalog.Catalog(
                    telegramTargets = listOf(
                        CallTransportTargetCatalog.CallTransportTarget(
                            service = CallTransportService.TELEGRAM,
                            host = "149.154.167.51",
                            port = 3478,
                            experimental = false,
                            enabled = true,
                        ),
                    ),
                    whatsappTargets = emptyList(),
                )
            },
            loadPaths = {
                listOf(
                    CallTransportLeakProber.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                    ),
                )
            },
            stunProbe = { _, _, _ -> Result.failure(IllegalStateException("timeout")) },
            publicIpFetcher = { _, _ -> Result.success("203.0.113.10") },
        )

        val results = runBlockingProbeDirect(experimental = false)

        assertFalse(results.any { it.service == CallTransportService.TELEGRAM && it.status == CallTransportStatus.ERROR })
        assertTrue(results.any { it.service == CallTransportService.WHATSAPP && it.status == CallTransportStatus.UNSUPPORTED })
    }

    @Test
    fun `proxy assisted telegram stores remote dc as target not local proxy`() {
        CallTransportLeakProber.dependenciesOverride = CallTransportLeakProber.Dependencies(
            proxyProbe = {
                CallTransportLeakProber.ProxyProbeOutcome(
                    reachable = true,
                    targetHost = "149.154.167.51",
                    targetPort = 443,
                    observedPublicIp = "203.0.113.10",
                )
            },
        )

        val result = kotlinx.coroutines.runBlocking {
            CallTransportLeakProber.probeProxyAssistedTelegram(
                ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            )
        }

        requireNotNull(result)
        assertEquals(CallTransportStatus.NEEDS_REVIEW, result.status)
        assertEquals("149.154.167.51", result.targetHost)
        assertEquals(443, result.targetPort)
        assertNull(result.mappedIp)
        assertEquals("203.0.113.10", result.observedPublicIp)
    }

    @Test
    fun `underlying path uses interface name for public ip fallback`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.10")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }
        CallTransportLeakProber.dependenciesOverride = CallTransportLeakProber.Dependencies(
            loadCatalog = { _, _ ->
                CallTransportTargetCatalog.Catalog(
                    telegramTargets = listOf(
                        CallTransportTargetCatalog.CallTransportTarget(
                            service = CallTransportService.TELEGRAM,
                            host = "149.154.167.51",
                            port = 3478,
                            experimental = false,
                            enabled = true,
                        ),
                    ),
                    whatsappTargets = emptyList(),
                )
            },
            loadPaths = {
                listOf(
                    CallTransportLeakProber.PathDescriptor(
                        path = CallTransportNetworkPath.UNDERLYING,
                        network = newNetwork(101),
                        interfaceName = "tun0",
                    ),
                )
            },
            stunProbe = { _, _, _ ->
                Result.success(
                    StunBindingClient.BindingResult(
                        resolvedIps = listOf("149.154.167.51"),
                        remoteIp = "149.154.167.51",
                        remotePort = 3478,
                        mappedIp = "198.51.100.20",
                        mappedPort = 40000,
                    ),
                )
            },
        )

        val results = runBlockingProbeDirect(experimental = false)

        val telegram = results.first { it.service == CallTransportService.TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, telegram.status)
        assertTrue(observedBindings.any { it is ResolverBinding.AndroidNetworkBinding })
        val fallbackBinding = observedBindings.last { it is ResolverBinding.OsDeviceBinding } as ResolverBinding.OsDeviceBinding
        assertEquals("tun0", fallbackBinding.interfaceName)
        assertEquals(ResolverBinding.DnsMode.SYSTEM, fallbackBinding.dnsMode)
    }

    private fun runBlockingProbeDirect(
        experimental: Boolean,
    ): List<CallTransportLeakResult> = kotlinx.coroutines.runBlocking {
        CallTransportLeakProber.probeDirect(
            context = context,
            resolverConfig = DnsResolverConfig.system(),
            experimentalCallTransportEnabled = experimental,
        )
    }

    private fun newNetwork(netId: Int): Network {
        val constructor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(netId)
    }
}
