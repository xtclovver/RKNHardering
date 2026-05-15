package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.Network
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.system.measureTimeMillis

@RunWith(RobolectricTestRunner::class)
class UnderlyingNetworkProberTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        UnderlyingNetworkProber.resetForTests()
    }

    @Test
    fun `build diagnostics returns null when debug disabled`() {
        val diagnostics = UnderlyingNetworkProber.buildTunProbeDiagnostics(
            debugEnabled = false,
            modeOverride = TunProbeModeOverride.AUTO,
            activeNetworkIsVpn = true,
            vpnNetworkPresent = true,
            underlyingNetworkPresent = true,
            vpnInterfaceName = "tun0",
            vpnComparison = successfulComparison("198.51.100.10"),
            underlyingInterfaceName = "wlan0",
            underlyingComparison = successfulComparison("203.0.113.10"),
        )

        assertNull(diagnostics)
    }

    @Test
    fun `build diagnostics keeps override and both paths`() {
        val diagnostics = UnderlyingNetworkProber.buildTunProbeDiagnostics(
            debugEnabled = true,
            modeOverride = TunProbeModeOverride.CURL_COMPATIBLE,
            activeNetworkIsVpn = false,
            vpnNetworkPresent = true,
            underlyingNetworkPresent = true,
            vpnInterfaceName = "tun0",
            vpnComparison = successfulComparison("198.51.100.10"),
            underlyingInterfaceName = "wlan0",
            underlyingComparison = successfulComparison("203.0.113.10"),
        )

        assertNotNull(diagnostics)
        assertEquals(TunProbeModeOverride.CURL_COMPATIBLE, diagnostics?.modeOverride)
        assertEquals("tun0", diagnostics?.vpnPath?.interfaceName)
        assertEquals("wlan0", diagnostics?.underlyingPath?.interfaceName)
        assertFalse(diagnostics?.vpnPath?.dnsPathMismatch ?: true)
    }

    @Test
    fun `build diagnostics preserves auto mismatch on vpn path`() {
        val diagnostics = UnderlyingNetworkProber.buildTunProbeDiagnostics(
            debugEnabled = true,
            modeOverride = TunProbeModeOverride.AUTO,
            activeNetworkIsVpn = true,
            vpnNetworkPresent = true,
            underlyingNetworkPresent = false,
            vpnInterfaceName = "tun0",
            vpnComparison = PublicIpNetworkComparison(
                strict = PublicIpModeProbeResult(
                    mode = PublicIpProbeMode.STRICT_SAME_PATH,
                    status = PublicIpProbeStatus.FAILED,
                    error = "strict timeout",
                ),
                curlCompatible = PublicIpModeProbeResult(
                    mode = PublicIpProbeMode.CURL_COMPATIBLE,
                    status = PublicIpProbeStatus.SUCCEEDED,
                    ip = "198.51.100.10",
                ),
                selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                selectedIp = "198.51.100.10",
                dnsPathMismatch = true,
            ),
            underlyingInterfaceName = null,
            underlyingComparison = null,
        )

        assertTrue(diagnostics?.vpnPath?.dnsPathMismatch == true)
        assertNull(diagnostics?.underlyingPath)
    }

    @Test
    fun `probe returns both targets when both succeed`() = runBlocking {
        val vpnNetwork = newNetwork(301)
        val wifiNetwork = newNetwork(302)
        installDependencies(
            activeNetwork = vpnNetwork,
            snapshots = listOf(
                snapshot(vpnNetwork, "tun0", hasVpnTransport = true),
                snapshot(wifiNetwork, "wlan0", hasVpnTransport = false),
            ),
            comparisons = mapOf(
                vpnNetwork to mapOf(
                    listOf("https://ipv4-internet.yandex.net/api/v0/ip", "https://ip.mail.ru") to successfulComparison("198.51.100.10"),
                    listOf(
                        "https://api-ipv4.ip.sb/ip",
                        "https://checkip.amazonaws.com",
                        "https://ifconfig.me/ip",
                        "https://api4.ipify.org",
                    ) to successfulComparison("203.0.113.10"),
                ),
                wifiNetwork to mapOf(
                    listOf("https://ipv4-internet.yandex.net/api/v0/ip", "https://ip.mail.ru") to successfulComparison("203.0.113.1"),
                    listOf(
                        "https://api-ipv4.ip.sb/ip",
                        "https://checkip.amazonaws.com",
                        "https://ifconfig.me/ip",
                        "https://api4.ipify.org",
                    ) to successfulComparison("203.0.113.2"),
                ),
            ),
        )

        val result = UnderlyingNetworkProber.probe(
            context = context,
            resolverConfig = DnsResolverConfig.system(),
        )

        assertTrue(result.vpnActive)
        assertTrue(result.underlyingReachable)
        assertEquals("198.51.100.10", result.ruTarget.vpnIp)
        assertEquals("203.0.113.10", result.nonRuTarget.vpnIp)
        assertEquals("203.0.113.1", result.ruTarget.directIp)
        assertEquals("203.0.113.2", result.nonRuTarget.directIp)
        assertEquals("ipv4-internet.yandex.net", result.ruTarget.targetHost)
        assertEquals("api-ipv4.ip.sb", result.nonRuTarget.targetHost)
        assertEquals("203.0.113.10", result.vpnIp)
        assertEquals("203.0.113.2", result.underlyingIp)
    }

    @Test
    fun `probe survives ru target failure`() = runBlocking {
        val vpnNetwork = newNetwork(303)
        installDependencies(
            activeNetwork = vpnNetwork,
            snapshots = listOf(snapshot(vpnNetwork, "tun0", hasVpnTransport = true)),
            comparisons = mapOf(
                vpnNetwork to mapOf(
                    listOf("https://ipv4-internet.yandex.net/api/v0/ip", "https://ip.mail.ru") to failureComparison("RU endpoint timeout"),
                    listOf(
                        "https://api-ipv4.ip.sb/ip",
                        "https://checkip.amazonaws.com",
                        "https://ifconfig.me/ip",
                        "https://api4.ipify.org",
                    ) to successfulComparison("203.0.113.10"),
                ),
            ),
        )

        val result = UnderlyingNetworkProber.probe(
            context = context,
            resolverConfig = DnsResolverConfig.system(),
        )

        assertTrue(result.vpnActive)
        assertFalse(result.underlyingReachable)
        assertNull(result.ruTarget.vpnIp)
        assertEquals("RU endpoint timeout", result.ruTarget.error)
        assertEquals("203.0.113.10", result.nonRuTarget.vpnIp)
    }

    @Test
    fun `probe flags divergence when vpn ips differ across targets`() = runBlocking {
        val vpnNetwork = newNetwork(304)
        installDependencies(
            activeNetwork = vpnNetwork,
            snapshots = listOf(snapshot(vpnNetwork, "tun0", hasVpnTransport = true)),
            comparisons = mapOf(
                vpnNetwork to mapOf(
                    listOf("https://ipv4-internet.yandex.net/api/v0/ip", "https://ip.mail.ru") to successfulComparison("198.51.100.10"),
                    listOf(
                        "https://api-ipv4.ip.sb/ip",
                        "https://checkip.amazonaws.com",
                        "https://ifconfig.me/ip",
                        "https://api4.ipify.org",
                    ) to successfulComparison("203.0.113.10"),
                ),
            ),
        )

        val result = UnderlyingNetworkProber.probe(
            context = context,
            resolverConfig = DnsResolverConfig.system(),
        )

        assertNotNull(result.ruTarget.vpnIp)
        assertNotNull(result.nonRuTarget.vpnIp)
        assertTrue(result.ruTarget.vpnIp != result.nonRuTarget.vpnIp)
    }

    @Test
    fun `probe fetches ru and non ru targets in parallel`() {
        val vpnNetwork = newNetwork(307)
        val wifiNetwork = newNetwork(308)
        installDependencies(
            activeNetwork = vpnNetwork,
            snapshots = listOf(
                snapshot(vpnNetwork, "tun0", hasVpnTransport = true),
                snapshot(wifiNetwork, "wlan0", hasVpnTransport = false),
            ),
            comparisons = mapOf(
                vpnNetwork to mapOf(
                    listOf("https://ipv4-internet.yandex.net/api/v0/ip", "https://ip.mail.ru") to successfulComparison("198.51.100.10"),
                    listOf(
                        "https://api-ipv4.ip.sb/ip",
                        "https://checkip.amazonaws.com",
                        "https://ifconfig.me/ip",
                        "https://api4.ipify.org",
                    ) to successfulComparison("203.0.113.10"),
                ),
                wifiNetwork to mapOf(
                    listOf("https://ipv4-internet.yandex.net/api/v0/ip", "https://ip.mail.ru") to successfulComparison("203.0.113.1"),
                    listOf(
                        "https://api-ipv4.ip.sb/ip",
                        "https://checkip.amazonaws.com",
                        "https://ifconfig.me/ip",
                        "https://api4.ipify.org",
                    ) to successfulComparison("203.0.113.2"),
                ),
            ),
        )
        val baseDependencies = requireNotNull(UnderlyingNetworkProber.dependenciesOverride)
        UnderlyingNetworkProber.dependenciesOverride = baseDependencies.copy(
            comparisonFetcher = { snapshot, resolverConfig, debugEnabled, modeOverride, targetUrls ->
                delay(300)
                baseDependencies.comparisonFetcher(snapshot, resolverConfig, debugEnabled, modeOverride, targetUrls)
            },
        )

        val elapsedMs = measureTimeMillis {
            val result = runBlocking {
                UnderlyingNetworkProber.probe(
                    context = context,
                    resolverConfig = DnsResolverConfig.system(),
                )
            }

            assertTrue(result.vpnActive)
            assertTrue(result.underlyingReachable)
        }

        assertTrue("Expected RU/non-RU target probes to overlap, but took ${elapsedMs}ms", elapsedMs < 900)
    }

    private fun installDependencies(
        activeNetwork: Network?,
        snapshots: List<UnderlyingNetworkProber.NetworkSnapshot>,
        comparisons: Map<Network, Map<List<String>, PublicIpNetworkComparison>>,
    ) {
        UnderlyingNetworkProber.dependenciesOverride = UnderlyingNetworkProber.Dependencies(
            initNativeCurl = {},
            environmentProvider = {
                UnderlyingNetworkProber.ProbeEnvironment(
                    activeNetwork = activeNetwork,
                    networks = snapshots,
                )
            },
            comparisonFetcher = { snapshot, _, _, _, targetUrls ->
                val urls = requireNotNull(targetUrls)
                comparisons[snapshot.network]?.get(urls)
                    ?: failureComparison("Missing test comparison for ${snapshot.network} $urls")
            },
        )
    }

    @Test
    fun `probe keeps vpn error separate from underlying error`() = runBlocking {
        val vpnNetwork = newNetwork(305)
        val wifiNetwork = newNetwork(306)
        installDependencies(
            activeNetwork = vpnNetwork,
            snapshots = listOf(
                snapshot(vpnNetwork, "tun0", hasVpnTransport = true),
                snapshot(wifiNetwork, "wlan0", hasVpnTransport = false),
            ),
            comparisons = mapOf(
                vpnNetwork to mapOf(
                    listOf("https://ipv4-internet.yandex.net/api/v0/ip", "https://ip.mail.ru") to successfulComparison("198.51.100.10"),
                    listOf(
                        "https://api-ipv4.ip.sb/ip",
                        "https://checkip.amazonaws.com",
                        "https://ifconfig.me/ip",
                        "https://api4.ipify.org",
                    ) to failureComparison("vpn non-ru timeout"),
                ),
                wifiNetwork to mapOf(
                    listOf("https://ipv4-internet.yandex.net/api/v0/ip", "https://ip.mail.ru") to successfulComparison("203.0.113.1"),
                    listOf(
                        "https://api-ipv4.ip.sb/ip",
                        "https://checkip.amazonaws.com",
                        "https://ifconfig.me/ip",
                        "https://api4.ipify.org",
                    ) to failureComparison("underlying non-ru timeout"),
                ),
            ),
        )

        val result = UnderlyingNetworkProber.probe(
            context = context,
            resolverConfig = DnsResolverConfig.system(),
        )

        assertEquals(null, result.ruTarget.error)
        assertEquals("vpn non-ru timeout", result.nonRuTarget.error)
        assertEquals("underlying non-ru timeout", result.underlyingError)
    }

    private fun snapshot(
        network: Network,
        interfaceName: String,
        hasVpnTransport: Boolean,
        hasInternet: Boolean = true,
    ): UnderlyingNetworkProber.NetworkSnapshot {
        return UnderlyingNetworkProber.NetworkSnapshot(
            network = network,
            interfaceName = interfaceName,
            hasInternet = hasInternet,
            hasVpnTransport = hasVpnTransport,
        )
    }

    private fun successfulComparison(ip: String): PublicIpNetworkComparison {
        return PublicIpNetworkComparison(
            strict = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.STRICT_SAME_PATH,
                status = PublicIpProbeStatus.SUCCEEDED,
                ip = ip,
            ),
            curlCompatible = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                status = PublicIpProbeStatus.SKIPPED,
                error = "Disabled by override",
            ),
            selectedMode = PublicIpProbeMode.STRICT_SAME_PATH,
            selectedIp = ip,
        )
    }

    private fun failureComparison(error: String): PublicIpNetworkComparison {
        return PublicIpNetworkComparison(
            strict = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.STRICT_SAME_PATH,
                status = PublicIpProbeStatus.FAILED,
                error = error,
            ),
            curlCompatible = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                status = PublicIpProbeStatus.SKIPPED,
                error = "Disabled by override",
            ),
            selectedMode = null,
            selectedIp = null,
            selectedError = error,
        )
    }

    @Test
    fun `vpnNetwork null with tun0 present activates OsDeviceBinding fallback`() = runBlocking {
        // No Android VPN network (app excluded from per-app VPN), but tun0 is visible.
        var osDeviceFetcherCalled = false
        UnderlyingNetworkProber.dependenciesOverride = UnderlyingNetworkProber.Dependencies(
            initNativeCurl = {},
            environmentProvider = {
                // cm.allNetworks returns empty (no VPN network visible to excluded app)
                UnderlyingNetworkProber.ProbeEnvironment(
                    activeNetwork = null,
                    networks = emptyList(),
                )
            },
            comparisonFetcher = { _, _, _, _, _ ->
                failureComparison("should not be called")
            },
            osDeviceComparisonFetcher = { interfaceName, _, _, _, targetUrls ->
                osDeviceFetcherCalled = true
                when {
                    interfaceName == "tun0" && targetUrls?.contains("https://ipv4-internet.yandex.net/api/v0/ip") == true ->
                        successfulComparison("203.0.113.50")
                    interfaceName == "tun0" ->
                        successfulComparison("203.0.113.51")
                    else ->
                        failureComparison("unexpected interface: $interfaceName")
                }
            },
        )

        val result = UnderlyingNetworkProber.probe(
            context = context,
            resolverConfig = DnsResolverConfig.system(),
            tunInterfacePresent = true,
            tunInterfaceName = "tun0",
            underlyingInterfaceName = null,
        )

        assertTrue("osDeviceComparisonFetcher must be called", osDeviceFetcherCalled)
        assertTrue(result.vpnActive)
        assertFalse(result.underlyingReachable)
        assertNotNull(result.ruTarget.vpnIp)
    }

    @Test
    fun `vpnNetwork null tun0 and underlying differ produce dnsPathMismatch true`() = runBlocking {
        UnderlyingNetworkProber.dependenciesOverride = UnderlyingNetworkProber.Dependencies(
            initNativeCurl = {},
            environmentProvider = {
                UnderlyingNetworkProber.ProbeEnvironment(
                    activeNetwork = null,
                    networks = emptyList(),
                )
            },
            comparisonFetcher = { _, _, _, _, _ ->
                failureComparison("should not be called")
            },
            osDeviceComparisonFetcher = { interfaceName, _, _, _, targetUrls ->
                val isRu = targetUrls?.contains("https://ipv4-internet.yandex.net/api/v0/ip") == true
                when (interfaceName) {
                    // tun0 returns VPN exit IP
                    "tun0" -> if (isRu) successfulComparison("10.8.0.1") else successfulComparison("10.8.0.2")
                    // rmnet0 returns real carrier IP (different → mismatch)
                    "rmnet0" -> if (isRu) successfulComparison("203.0.113.1") else successfulComparison("203.0.113.2")
                    else -> failureComparison("unexpected: $interfaceName")
                }
            },
        )

        val result = UnderlyingNetworkProber.probe(
            context = context,
            resolverConfig = DnsResolverConfig.system(),
            tunInterfacePresent = true,
            tunInterfaceName = "tun0",
            underlyingInterfaceName = "rmnet0",
        )

        assertTrue(result.vpnActive)
        assertTrue(result.underlyingReachable)
        assertTrue("dnsPathMismatch must be true when tun and underlying IPs differ", result.dnsPathMismatch)
        // VPN IP comes from tun0, underlying from rmnet0
        assertNotNull(result.ruTarget.vpnIp)
        assertNotNull(result.ruTarget.directIp)
        assertTrue(result.ruTarget.vpnIp != result.ruTarget.directIp)
    }

    private fun newNetwork(netId: Int): Network {
        val constructor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(netId)
    }
}
