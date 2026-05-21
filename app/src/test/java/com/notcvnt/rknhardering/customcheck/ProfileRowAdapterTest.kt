package com.notcvnt.rknhardering.customcheck

import org.junit.Assert.assertEquals
import org.junit.Test

class ProfileRowAdapterTest {

    @Test
    fun `countEnabledCheckers returns 12 for default profile`() {
        val profile = CustomCheckProfile(name = "Test").copy(
            checksConfig = ChecksConfig(
                geoIp = GeoIpConfig(enabled = true),
                ipComparison = IpComparisonConfig(enabled = true),
                cdnPulling = CdnPullingConfig(enabled = true),
                directSigns = DirectSignsConfig(enabled = true),
                indirectSigns = IndirectSignsConfig(enabled = true),
                nativeSigns = CheckToggle(enabled = true),
                locationSignals = LocationSignalsConfig(enabled = true),
                icmpSpoofing = IcmpSpoofingConfig(enabled = true),
                rttTriangulation = RttTriangulationConfig(enabled = true),
                callTransport = CallTransportConfig(enabled = true),
                splitTunnel = SplitTunnelConfig(enabled = true),
                domainReachabilityEnabled = true,
            ),
        )
        assertEquals(12, ProfileRowAdapter.countEnabledCheckers(profile))
    }

    @Test
    fun `countEnabledCheckers excludes disabled sections`() {
        val profile = CustomCheckProfile(name = "Test").copy(
            checksConfig = ChecksConfig(
                geoIp = GeoIpConfig(enabled = false),
                ipComparison = IpComparisonConfig(enabled = false),
                cdnPulling = CdnPullingConfig(enabled = false),
                directSigns = DirectSignsConfig(enabled = true),
                indirectSigns = IndirectSignsConfig(enabled = true),
                nativeSigns = CheckToggle(enabled = true),
                locationSignals = LocationSignalsConfig(enabled = true),
                icmpSpoofing = IcmpSpoofingConfig(enabled = false),
                rttTriangulation = RttTriangulationConfig(enabled = false),
                callTransport = CallTransportConfig(enabled = false),
                splitTunnel = SplitTunnelConfig(enabled = true),
                domainReachabilityEnabled = false,
            ),
        )
        assertEquals(5, ProfileRowAdapter.countEnabledCheckers(profile))
    }

    @Test
    fun `TOTAL_CHECKERS constant is 12`() {
        assertEquals(12, ProfileRowAdapter.TOTAL_CHECKERS)
    }
}
