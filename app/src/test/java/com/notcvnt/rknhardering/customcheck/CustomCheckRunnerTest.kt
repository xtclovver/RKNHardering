package com.notcvnt.rknhardering.customcheck

import com.notcvnt.rknhardering.checker.CheckSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CustomCheckRunnerTest {

    private val baseSettings = CheckSettings()

    private fun defaultProfile(name: String = "Test"): CustomCheckProfile =
        CustomCheckProfile(name = name)

    // ── default profile maps to expected defaults ──────────────────────────────

    @Test
    fun `default profile produces split tunnel enabled`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertTrue(settings.splitTunnelEnabled)
    }

    @Test
    fun `default profile produces proxyScan enabled`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertTrue(settings.proxyScanEnabled)
    }

    @Test
    fun `default profile produces xrayApiScan enabled`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertTrue(settings.xrayApiScanEnabled)
    }

    @Test
    fun `default profile produces networkRequests enabled`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertTrue(settings.networkRequestsEnabled)
    }

    @Test
    fun `default profile produces callTransport disabled`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertFalse(settings.callTransportProbeEnabled)
    }

    @Test
    fun `default profile produces cdnPulling disabled`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertFalse(settings.cdnPullingEnabled)
    }

    @Test
    fun `default profile produces icmpSpoofing disabled`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertFalse(settings.icmpSpoofingEnabled)
    }

    @Test
    fun `default profile produces rttTriangulation disabled`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertFalse(settings.rttTriangulationEnabled)
    }

    @Test
    fun `default profile produces popular portRange`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertEquals("popular", settings.portRange)
    }

    @Test
    fun `default profile produces portRangeStart 1024`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertEquals(1024, settings.portRangeStart)
    }

    @Test
    fun `default profile produces portRangeEnd 65535`() {
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), baseSettings)
        assertEquals(65535, settings.portRangeEnd)
    }

    // ── disabled checks produce false flags ───────────────────────────────────

    @Test
    fun `disabled splitTunnel sets splitTunnelEnabled false`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(splitTunnel = SplitTunnelConfig(enabled = false))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.splitTunnelEnabled)
    }

    @Test
    fun `disabled proxyScan sets proxyScanEnabled false`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(splitTunnel = SplitTunnelConfig(proxyScan = false))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.proxyScanEnabled)
    }

    @Test
    fun `disabled xrayApiScan sets xrayApiScanEnabled false`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(splitTunnel = SplitTunnelConfig(xrayApiScan = false))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.xrayApiScanEnabled)
    }

    @Test
    fun `disabled networkRequests sets networkRequestsEnabled false`() {
        val profile = defaultProfile().copy(
            networkConfig = NetworkConfig(networkRequestsEnabled = false)
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.networkRequestsEnabled)
    }

    @Test
    fun `enabled callTransport sets callTransportProbeEnabled true`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(callTransport = CallTransportConfig(enabled = true))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertTrue(settings.callTransportProbeEnabled)
    }

    @Test
    fun `enabled cdnPulling sets cdnPullingEnabled true`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(cdnPulling = CdnPullingConfig(enabled = true))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertTrue(settings.cdnPullingEnabled)
    }

    @Test
    fun `cdnPulling meduza flag propagates`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(cdnPulling = CdnPullingConfig(enabled = true, meduzaEnabled = false))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.cdnPullingMeduzaEnabled)
    }

    @Test
    fun `enabled icmpSpoofing sets icmpSpoofingEnabled true`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(icmpSpoofing = IcmpSpoofingConfig(enabled = true))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertTrue(settings.icmpSpoofingEnabled)
    }

    @Test
    fun `enabled rttTriangulation sets rttTriangulationEnabled true`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(rttTriangulation = RttTriangulationConfig(enabled = true))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertTrue(settings.rttTriangulationEnabled)
    }

    // ── portRange copies correctly ────────────────────────────────────────────

    @Test
    fun `custom portRange copies to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(splitTunnel = SplitTunnelConfig(
                portRange = "custom",
                portRangeStart = 8080,
                portRangeEnd = 8090,
            ))
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertEquals("custom", settings.portRange)
        assertEquals(8080, settings.portRangeStart)
        assertEquals(8090, settings.portRangeEnd)
    }

    // ── unrelated baseSettings fields are preserved ───────────────────────────

    @Test
    fun `tunProbeDebugEnabled from baseSettings is preserved`() {
        val base = baseSettings.copy(tunProbeDebugEnabled = true)
        val settings = CustomCheckRunner.toCheckSettings(defaultProfile(), base)
        assertTrue(settings.tunProbeDebugEnabled)
    }

    // ── per-checker deep customization propagates to CheckSettings ────────────

    @Test
    fun `directSigns sub-toggles propagate to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                directSigns = DirectSignsConfig(
                    enabled = true,
                    checkTransportVpn = false,
                    checkHttpProxy = false,
                    checkSocksProxy = true,
                    checkProxyInfo = false,
                    checkVpnService = true,
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.directSigns.checkTransportVpn)
        assertFalse(settings.directSigns.checkHttpProxy)
        assertTrue(settings.directSigns.checkSocksProxy)
        assertFalse(settings.directSigns.checkProxyInfo)
        assertTrue(settings.directSigns.checkVpnService)
    }

    @Test
    fun `indirectSigns sub-toggles and threshold propagate to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                indirectSigns = IndirectSignsConfig(
                    enabled = true,
                    checkNotVpnCap = false,
                    checkVpnInterfaces = false,
                    checkMtuAnomaly = true,
                    checkIpsec = false,
                    checkRouting = true,
                    checkDns = false,
                    checkProxyTools = true,
                    checkLocalListeners = false,
                    checkDumpsys = true,
                    listenerPortThreshold = 9,
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.indirectSigns.checkNotVpnCap)
        assertTrue(settings.indirectSigns.checkMtuAnomaly)
        assertFalse(settings.indirectSigns.checkLocalListeners)
        assertEquals(9, settings.indirectSigns.listenerPortThreshold)
    }

    @Test
    fun `locationSignals sub-toggles propagate to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                locationSignals = LocationSignalsConfig(
                    enabled = true,
                    checkBeacondb = false,
                    checkCellTowers = true,
                    checkWifiSignals = false,
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.locationSignals.checkBeacondb)
        assertTrue(settings.locationSignals.checkCellTowers)
        assertFalse(settings.locationSignals.checkWifiSignals)
    }

    @Test
    fun `callTransport sub-toggles and custom STUN propagate to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                callTransport = CallTransportConfig(
                    enabled = true,
                    builtinGlobalStunEnabled = false,
                    builtinRuStunEnabled = true,
                    checkMtproto = false,
                    customStunServers = listOf(
                        StunServer(host = "stun.example.com", port = 5349, label = "My STUN"),
                    ),
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.callTransport.builtinGlobalStunEnabled)
        assertTrue(settings.callTransport.builtinRuStunEnabled)
        assertFalse(settings.callTransport.checkMtproto)
        assertEquals(1, settings.callTransport.customStunServers.size)
        assertEquals("stun.example.com", settings.callTransport.customStunServers[0].host)
        assertEquals(5349, settings.callTransport.customStunServers[0].port)
    }

    @Test
    fun `geoIp custom providers propagate to settings`() {
        val mapping = ResponseMapping(responseType = ResponseType.JSON, ipPath = "$.ip")
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                geoIp = GeoIpConfig(
                    enabled = true,
                    timeoutMs = 12_345,
                    customProviders = listOf(
                        CustomGeoIpProvider(name = "MyIP", url = "https://example.com/ip", responseMapping = mapping),
                    ),
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertEquals(12_345, settings.geoIp.timeoutMs)
        assertEquals(1, settings.geoIp.customProviders.size)
        assertEquals("https://example.com/ip", settings.geoIp.customProviders[0].url)
    }

    @Test
    fun `ipComparison builtin toggles and custom endpoints propagate to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                ipComparison = IpComparisonConfig(
                    enabled = true,
                    builtinRuCheckersEnabled = false,
                    builtinNonRuCheckersEnabled = true,
                    customEndpoints = listOf(
                        CustomIpEndpoint(label = "My IP", url = "https://example.com/ip", scope = EndpointScope.NON_RU),
                    ),
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.ipComparison.builtinRuCheckersEnabled)
        assertTrue(settings.ipComparison.builtinNonRuCheckersEnabled)
        assertEquals(1, settings.ipComparison.customEndpoints.size)
        assertEquals(EndpointScope.NON_RU, settings.ipComparison.customEndpoints[0].scope)
    }

    @Test
    fun `icmpSpoofing custom targets and ping count propagate to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                icmpSpoofing = IcmpSpoofingConfig(
                    enabled = true,
                    pingCount = 7,
                    timeoutMs = 6_000,
                    builtinTargetsEnabled = false,
                    customTargets = listOf(
                        IcmpTarget(host = "blocked.example.com", label = "blocked"),
                        IcmpTarget(host = "control.example.com", label = "control", isControl = true),
                    ),
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertEquals(7, settings.icmpSpoofing.pingCount)
        assertEquals(6_000, settings.icmpSpoofing.timeoutMs)
        assertFalse(settings.icmpSpoofing.builtinTargetsEnabled)
        assertEquals(2, settings.icmpSpoofing.customTargets.size)
        assertTrue(settings.icmpSpoofing.customTargets.any { it.isControl })
    }

    @Test
    fun `rttTriangulation custom targets propagate to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                rttTriangulation = RttTriangulationConfig(
                    enabled = true,
                    pingCount = 9,
                    builtinTargetsEnabled = false,
                    customTargets = listOf(
                        RttTarget(host = "yandex.ru", label = "Yandex", expectedLocation = "RU"),
                    ),
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertEquals(9, settings.rttTriangulation.pingCount)
        assertFalse(settings.rttTriangulation.builtinTargetsEnabled)
        assertEquals(1, settings.rttTriangulation.customTargets.size)
        assertEquals("RU", settings.rttTriangulation.customTargets[0].expectedLocation)
    }

    // ── Domain reachability ──────────────────────────────────────────────────

    @Test
    fun `reachability domains enable check when toggle is on`() {
        val profile = defaultProfile().copy(
            customDomains = listOf(
                CustomDomain(domain = "example.com", checkType = "reachability"),
                CustomDomain(domain = "blocked.example.com", checkType = "dpi", description = "Blocked"),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertTrue(settings.domainReachabilityEnabled)
        assertEquals(2, settings.reachabilityDomains.size)
    }

    @Test
    fun `reachability domains are dropped when toggle is off`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(domainReachabilityEnabled = false),
            customDomains = listOf(
                CustomDomain(domain = "example.com", checkType = "reachability"),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.domainReachabilityEnabled)
        assertTrue(settings.reachabilityDomains.isEmpty())
    }

    @Test
    fun `reachability disabled when no domains regardless of toggle`() {
        val profile = defaultProfile() // toggle defaults to true, no domains
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.domainReachabilityEnabled)
        assertTrue(settings.reachabilityDomains.isEmpty())
    }

    @Test
    fun `cdnPulling custom targets and toggles propagate to settings`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                cdnPulling = CdnPullingConfig(
                    enabled = true,
                    rutrackerEnabled = false,
                    meduzaEnabled = false,
                    builtinTargetsEnabled = false,
                    customTargets = listOf(
                        CustomCdnTarget(label = "My CDN", url = "https://cdn.example.com/trace"),
                    ),
                ),
            ),
        )
        val settings = CustomCheckRunner.toCheckSettings(profile, baseSettings)
        assertFalse(settings.cdnPulling.rutrackerEnabled)
        assertFalse(settings.cdnPulling.meduzaEnabled)
        assertFalse(settings.cdnPulling.builtinTargetsEnabled)
        assertEquals(1, settings.cdnPulling.customTargets.size)
    }
}
