package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.Network
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.network.DnsResolverConfig
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
                    "ifconfig.yandex.ru" to successfulComparison("198.51.100.10"),
                    "api.ipify.org" to successfulComparison("203.0.113.10"),
                ),
                wifiNetwork to mapOf(
                    "ifconfig.yandex.ru" to successfulComparison("203.0.113.1"),
                    "api.ipify.org" to successfulComparison("203.0.113.2"),
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
        assertEquals("ifconfig.yandex.ru", result.ruTarget.targetHost)
        assertEquals("api.ipify.org", result.nonRuTarget.targetHost)
    }

    @Test
    fun `probe survives ru target failure`() = runBlocking {
        val vpnNetwork = newNetwork(303)
        installDependencies(
            activeNetwork = vpnNetwork,
            snapshots = listOf(snapshot(vpnNetwork, "tun0", hasVpnTransport = true)),
            comparisons = mapOf(
                vpnNetwork to mapOf(
                    "ifconfig.yandex.ru" to failureComparison("RU endpoint timeout"),
                    "api.ipify.org" to successfulComparison("203.0.113.10"),
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
                    "ifconfig.yandex.ru" to successfulComparison("198.51.100.10"),
                    "api.ipify.org" to successfulComparison("203.0.113.10"),
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

    private fun installDependencies(
        activeNetwork: Network?,
        snapshots: List<UnderlyingNetworkProber.NetworkSnapshot>,
        comparisons: Map<Network, Map<String, PublicIpNetworkComparison>>,
    ) {
        UnderlyingNetworkProber.dependenciesOverride = UnderlyingNetworkProber.Dependencies(
            initNativeCurl = {},
            environmentProvider = {
                UnderlyingNetworkProber.ProbeEnvironment(
                    activeNetwork = activeNetwork,
                    networks = snapshots,
                )
            },
            comparisonFetcher = { snapshot, _, _, _, targetHost ->
                val host = requireNotNull(targetHost)
                comparisons[snapshot.network]?.get(host)
                    ?: failureComparison("Missing test comparison for ${snapshot.network} $host")
            },
        )
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

    private fun newNetwork(netId: Int): Network {
        val constructor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(netId)
    }
}
