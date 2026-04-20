package com.notcvnt.rknhardering.checker.ipconsensus

import com.notcvnt.rknhardering.model.AsnInfo
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.GeoIpFacts
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpFamily
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.probe.PerTargetProbe
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IpConsensusBuilderTest {

    private fun geoIp(
        ip: String? = null,
        countryCode: String? = null,
        asn: String? = null,
    ): CategoryResult = CategoryResult(
        name = "GeoIP",
        detected = false,
        findings = emptyList(),
        geoFacts = GeoIpFacts(ip = ip, countryCode = countryCode, asn = asn),
    )

    private fun ipComparison(
        ruIps: List<String> = emptyList(),
        nonRuIps: List<String> = emptyList(),
    ): IpComparisonResult = IpComparisonResult(
        detected = false,
        summary = "",
        ruGroup = IpCheckerGroupResult(
            title = "ru",
            detected = false,
            statusLabel = "",
            summary = "",
            responses = ruIps.map {
                IpCheckerResponse(label = "r", url = "u", scope = IpCheckerScope.RU, ip = it)
            },
        ),
        nonRuGroup = IpCheckerGroupResult(
            title = "non-ru",
            detected = false,
            statusLabel = "",
            summary = "",
            responses = nonRuIps.map {
                IpCheckerResponse(label = "r", url = "u", scope = IpCheckerScope.NON_RU, ip = it)
            },
        ),
    )

    private fun cdn(ips: List<String> = emptyList()): CdnPullingResult = CdnPullingResult(
        detected = false,
        summary = "",
        responses = ips.map {
            CdnPullingResponse(targetLabel = "t", url = "u", ip = it, ipv4 = it)
        },
    )

    private fun probe(
        ruDirect: String? = null,
        ruVpn: String? = null,
        nonRuDirect: String? = null,
        nonRuVpn: String? = null,
        vpnActive: Boolean = true,
    ): UnderlyingNetworkProber.ProbeResult = UnderlyingNetworkProber.ProbeResult(
        vpnActive = vpnActive,
        ruTarget = PerTargetProbe(
            targetHost = "ru.example",
            targetGroup = TargetGroup.RU,
            directIp = ruDirect,
            vpnIp = ruVpn,
            comparison = null,
            error = null,
        ),
        nonRuTarget = PerTargetProbe(
            targetHost = "non-ru.example",
            targetGroup = TargetGroup.NON_RU,
            directIp = nonRuDirect,
            vpnIp = nonRuVpn,
            comparison = null,
            error = null,
        ),
    )

    private fun bypass(
        directIp: String? = null,
        vpnNetworkIp: String? = null,
        underlyingIp: String? = null,
        proxyIp: String? = null,
    ): BypassResult = BypassResult(
        proxyEndpoint = null,
        directIp = directIp,
        proxyIp = proxyIp,
        vpnNetworkIp = vpnNetworkIp,
        underlyingIp = underlyingIp,
        xrayApiScanResult = null,
        findings = emptyList(),
        detected = false,
    )

    private fun callTransportLeak(
        mappedIp: String,
        networkPath: CallTransportNetworkPath = CallTransportNetworkPath.ACTIVE,
        probeKind: CallTransportProbeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
    ): CallTransportLeakResult = CallTransportLeakResult(
        service = CallTransportService.TELEGRAM,
        probeKind = probeKind,
        networkPath = networkPath,
        status = CallTransportStatus.NEEDS_REVIEW,
        targetHost = "stun.example.com",
        targetPort = 3478,
        mappedIp = mappedIp,
        observedPublicIp = null,
        summary = "STUN mapped IP $mappedIp",
    )

    private suspend fun build(
        geoIpResult: CategoryResult = geoIp(),
        ipComparisonResult: IpComparisonResult = ipComparison(),
        cdnResult: CdnPullingResult = cdn(),
        probeResult: UnderlyingNetworkProber.ProbeResult? = null,
        bypassResult: BypassResult = bypass(),
        callTransportLeaks: List<CallTransportLeakResult> = emptyList(),
        asnLookup: suspend (String) -> AsnInfo? = { null },
    ) = IpConsensusBuilder.build(
        geoIp = geoIpResult,
        ipComparison = ipComparisonResult,
        cdnPulling = cdnResult,
        tunProbe = probeResult,
        bypass = bypassResult,
        callTransportLeaks = callTransportLeaks,
        asnResolver = AsnResolver(maxIps = 6, lookup = asnLookup),
    )

    @Test
    fun `empty input produces empty consensus`() = runBlocking {
        val result = build()
        assertTrue(result.observedIps.isEmpty())
        assertFalse(result.crossChannelMismatch)
        assertFalse(result.needsReview)
    }

    @Test
    fun `direct ip from geo and underlying merges to one observed entry`() = runBlocking {
        val result = build(
            geoIpResult = geoIp(ip = "1.2.3.4", countryCode = "RU"),
            probeResult = probe(ruDirect = "1.2.3.4"),
        )
        val direct = result.observedIps.filter { it.channel == Channel.DIRECT }
        assertEquals(1, direct.size)
        assertEquals("1.2.3.4", direct.first().value)
        assertTrue(direct.first().sources.any { it.contains("geoip") })
        assertTrue(direct.first().sources.any { it.contains("underlying-prober") })
    }

    @Test
    fun `different direct and vpn ips in same family trigger crossChannelMismatch`() = runBlocking {
        val result = build(
            geoIpResult = geoIp(ip = "1.2.3.4", countryCode = "RU"),
            probeResult = probe(ruDirect = "1.2.3.4", ruVpn = "9.9.9.9"),
        )
        assertTrue(result.crossChannelMismatch)
    }

    @Test
    fun `dual stack across channels is not a mismatch`() = runBlocking {
        val result = build(
            probeResult = probe(ruDirect = "1.2.3.4", ruVpn = "2001:db8::1"),
        )
        assertTrue(result.dualStackObserved)
        assertFalse(result.crossChannelMismatch)
    }

    @Test
    fun `conflicting ips inside direct channel raise channelConflict`() = runBlocking {
        val result = build(
            ipComparisonResult = ipComparison(
                ruIps = listOf("1.1.1.1"),
                nonRuIps = listOf("2.2.2.2"),
            ),
        )
        assertTrue(Channel.DIRECT in result.channelConflict)
    }

    @Test
    fun `proxy-only ip is warp-like`() = runBlocking {
        val result = build(
            probeResult = probe(ruDirect = "1.2.3.4", ruVpn = "1.2.3.4"),
            bypassResult = bypass(proxyIp = "5.6.7.8"),
        )
        assertTrue(result.warpLikeIndicator)
    }

    @Test
    fun `call transport mapped ip contributes direct channel`() = runBlocking {
        val result = build(
            callTransportLeaks = listOf(callTransportLeak(mappedIp = "203.0.113.55")),
        )
        val direct = result.observedIps.first { it.value == "203.0.113.55" }
        assertEquals(Channel.DIRECT, direct.channel)
        assertTrue(direct.sources.any { it.contains("call-transport:active") })
    }

    @Test
    fun `proxy assisted udp stun contributes proxy channel`() = runBlocking {
        val result = build(
            callTransportLeaks = listOf(
                callTransportLeak(
                    mappedIp = "198.51.100.20",
                    networkPath = CallTransportNetworkPath.LOCAL_PROXY,
                    probeKind = CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN,
                ),
            ),
        )
        val proxy = result.observedIps.first { it.value == "198.51.100.20" }
        assertEquals(Channel.PROXY, proxy.channel)
        assertTrue(proxy.sources.any { it.contains("call-transport:local_proxy") })
    }

    @Test
    fun `foreign ip from geoFacts populates foreignIps`() = runBlocking {
        val result = build(geoIpResult = geoIp(ip = "8.8.8.8", countryCode = "US"))
        assertTrue("8.8.8.8" in result.foreignIps)
    }

    @Test
    fun `geoCountryMismatch flags when two ips have different known countries`() = runBlocking {
        val result = build(
            geoIpResult = geoIp(ip = "1.2.3.4", countryCode = "RU"),
            probeResult = probe(ruVpn = "8.8.8.8"),
            asnLookup = { ip -> if (ip == "8.8.8.8") AsnInfo(asn = "AS1", countryCode = "US") else null },
        )
        assertTrue(result.geoCountryMismatch)
    }

    @Test
    fun `sameAsnAcrossChannels true when mismatched ips share asn`() = runBlocking {
        val result = build(
            geoIpResult = geoIp(ip = "1.2.3.4", countryCode = "RU", asn = "AS42 Example"),
            probeResult = probe(ruVpn = "5.6.7.8"),
            asnLookup = { ip ->
                if (ip == "5.6.7.8") AsnInfo(asn = "AS42 Example", countryCode = "RU") else null
            },
        )
        assertTrue(result.crossChannelMismatch)
        assertTrue(result.sameAsnAcrossChannels)
    }

    @Test
    fun `probeTargetDivergence flagged when vpn ips differ across targets`() = runBlocking {
        val result = build(
            probeResult = probe(ruVpn = "1.1.1.1", nonRuVpn = "2.2.2.2"),
        )
        assertTrue(result.probeTargetDivergence)
    }

    @Test
    fun `probeTargetDirectDivergence is independent of vpn`() = runBlocking {
        val result = build(
            probeResult = probe(ruDirect = "1.1.1.1", nonRuDirect = "2.2.2.2"),
        )
        assertTrue(result.probeTargetDirectDivergence)
        assertFalse(result.probeTargetDivergence)
    }

    @Test
    fun `ipv4-mapped ipv6 is normalized to ipv4`() = runBlocking {
        val result = build(
            geoIpResult = geoIp(ip = "1.2.3.4"),
            probeResult = probe(ruDirect = "::ffff:1.2.3.4"),
        )
        val direct = result.observedIps.first { it.channel == Channel.DIRECT }
        assertEquals("1.2.3.4", direct.value)
        assertEquals(IpFamily.V4, direct.family)
    }

    @Test
    fun `invalid ip from source goes to unparsedIps and sets needsReview`() = runBlocking {
        val result = build(
            ipComparisonResult = ipComparison(ruIps = listOf("not-an-ip")),
        )
        assertEquals(1, result.unparsedIps.size)
        assertTrue(result.needsReview)
    }

    @Test
    fun `targetGroup preserved in observed entries from probe`() = runBlocking {
        val result = build(
            probeResult = probe(ruDirect = "1.1.1.1", nonRuDirect = "2.2.2.2"),
        )
        val ru = result.observedIps.first { it.value == "1.1.1.1" }
        val nonRu = result.observedIps.first { it.value == "2.2.2.2" }
        assertEquals(TargetGroup.RU, ru.targetGroup)
        assertEquals(TargetGroup.NON_RU, nonRu.targetGroup)
    }
}
