package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.GeoIpFacts
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

class VerdictEngineTest {

    @Test
    fun `R1 split tunnel evidence yields detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(evidence = listOf(evidence(EvidenceSource.SPLIT_TUNNEL_BYPASS, EvidenceConfidence.HIGH))),
            ipConsensus = IpConsensusResult.empty(),
        )
        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `R5 transport_vpn evidence alone yields not detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = directCategory(true),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )
        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `metadata-only installed app evidence does not affect verdict`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = CategoryResult(
                name = "direct",
                detected = false,
                findings = emptyList(),
                evidence = listOf(
                    EvidenceItem(
                        source = EvidenceSource.INSTALLED_APP,
                        detected = false,
                        confidence = EvidenceConfidence.LOW,
                        description = "Installed app with VPN in name",
                    ),
                ),
            ),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `R3a probeTargetDivergence with geoCountryMismatch yields detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult(
                probeTargetDivergence = true,
                geoCountryMismatch = true,
            ),
        )
        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `R3a probeTargetDivergence alone yields detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult(probeTargetDivergence = true),
        )
        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `R3b probeTargetDirectDivergence with foreign ip yields detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult(
                probeTargetDirectDivergence = true,
                foreignIps = setOf("1.2.3.4"),
            ),
        )
        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `R3c crossChannelMismatch with foreignIps yields detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult(
                crossChannelMismatch = true,
                foreignIps = setOf("8.8.8.8"),
            ),
        )
        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `R3c crossChannelMismatch alone falls through`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult(crossChannelMismatch = true),
        )
        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `R4 locationConfirmsRussia with geo outsideRu yields detected`() {
        val geo = category(
            geoFacts = GeoIpFacts(outsideRu = true, countryCode = "DE"),
        )
        val location = CategoryResult(
            name = "loc",
            detected = false,
            findings = listOf(Finding("network_mcc_ru:true")),
        )
        val verdict = VerdictEngine.evaluate(
            geoIp = geo,
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = location,
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )
        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `R4 regression issue 15 hosting only yields needs review`() {
        val geo = category(
            geoFacts = GeoIpFacts(hosting = true, countryCode = "RU"),
        )
        val location = CategoryResult(
            name = "loc",
            detected = false,
            findings = listOf(Finding("network_mcc_ru:true")),
        )
        val verdict = VerdictEngine.evaluate(
            geoIp = geo,
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = location,
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )
        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `R5 geo outsideRu alone yields needs review`() {
        val geo = category(geoFacts = GeoIpFacts(outsideRu = true, countryCode = "DE"))
        val verdict = VerdictEngine.evaluate(
            geoIp = geo,
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )
        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `R5 geo outsideRu plus indirect yields detected`() {
        val geo = category(geoFacts = GeoIpFacts(outsideRu = true, countryCode = "DE"))
        val verdict = VerdictEngine.evaluate(
            geoIp = geo,
            directSigns = category(),
            indirectSigns = indirectCategory(true),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )
        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `R6 channelConflict alone promotes to needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult(channelConflict = setOf(Channel.DIRECT)),
        )
        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `R6 icmp spoofing review alone promotes to needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
            icmpSpoofing = category(needsReview = true),
        )
        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `R7 empty input yields not detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )
        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `xray api override returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(
                evidence = listOf(evidence(EvidenceSource.XRAY_API, EvidenceConfidence.HIGH)),
            ),
            ipConsensus = IpConsensusResult.empty(),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `vpn gateway leak override returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(
                evidence = listOf(evidence(EvidenceSource.VPN_GATEWAY_LEAK, EvidenceConfidence.HIGH)),
            ),
            ipConsensus = IpConsensusResult.empty(),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `vpn network binding override returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(
                evidence = listOf(evidence(EvidenceSource.VPN_NETWORK_BINDING, EvidenceConfidence.HIGH)),
            ),
            ipConsensus = IpConsensusResult.empty(),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `TUN_ACTIVE_PROBE evidence source exists`() {
        val source = EvidenceSource.TUN_ACTIVE_PROBE
        assertEquals(EvidenceSource.TUN_ACTIVE_PROBE, source)
    }

    @Test
    fun `tun active probe alone does not change verdict`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(
                evidence = listOf(evidence(EvidenceSource.TUN_ACTIVE_PROBE, EvidenceConfidence.LOW)),
            ),
            ipConsensus = IpConsensusResult.empty(),
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `bypass needs review elevates clean verdict to needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(needsReview = true),
            ipConsensus = IpConsensusResult.empty(),
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `direct call transport leak elevates clean verdict to needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(
                callTransportLeaks = listOf(
                    CallTransportLeakResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        networkPath = CallTransportNetworkPath.ACTIVE,
                        status = CallTransportStatus.NEEDS_REVIEW,
                        targetHost = "149.154.167.51",
                        targetPort = 3478,
                        mappedIp = "198.51.100.20",
                        observedPublicIp = "203.0.113.10",
                        summary = "Telegram call transport responded",
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                ),
            ),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `proxy assisted udp leak does not affect verdict`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(
                callTransportLeaks = listOf(
                    CallTransportLeakResult(
                        service = CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN,
                        networkPath = CallTransportNetworkPath.LOCAL_PROXY,
                        status = CallTransportStatus.NEEDS_REVIEW,
                        targetHost = "149.154.167.51",
                        targetPort = 3478,
                        mappedIp = "198.51.100.20",
                        observedPublicIp = "203.0.113.10",
                        summary = "Telegram call transport via local proxy responded",
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                ),
            ),
            locationSignals = category(),
            bypassResult = bypass(),
            ipConsensus = IpConsensusResult.empty(),
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    private fun geoCategory(present: Boolean): CategoryResult {
        if (!present) return category()
        return category(
            needsReview = true,
            evidence = listOf(evidence(EvidenceSource.GEO_IP, EvidenceConfidence.MEDIUM)),
        )
    }

    private fun directCategory(present: Boolean): CategoryResult {
        if (!present) return category()
        return category(
            evidence = listOf(evidence(EvidenceSource.DIRECT_NETWORK_CAPABILITIES, EvidenceConfidence.HIGH)),
        )
    }

    private fun indirectCategory(present: Boolean): CategoryResult {
        if (!present) return category()
        return category(
            evidence = listOf(evidence(EvidenceSource.ROUTING, EvidenceConfidence.MEDIUM)),
        )
    }

    private fun category(
        evidence: List<EvidenceItem> = emptyList(),
        needsReview: Boolean = false,
        callTransportLeaks: List<CallTransportLeakResult> = emptyList(),
        geoFacts: GeoIpFacts? = null,
    ): CategoryResult = CategoryResult(
        name = "test",
        detected = evidence.any { it.detected },
        findings = emptyList(),
        needsReview = needsReview,
        evidence = evidence,
        callTransportLeaks = callTransportLeaks,
        geoFacts = geoFacts,
    )

    private fun bypass(
        evidence: List<EvidenceItem> = emptyList(),
        needsReview: Boolean = false,
    ): BypassResult = BypassResult(
        proxyEndpoint = null,
        proxyOwner = null,
        directIp = null,
        proxyIp = null,
        vpnNetworkIp = null,
        underlyingIp = null,
        xrayApiScanResult = null,
        findings = emptyList(),
        detected = evidence.any { it.detected },
        needsReview = needsReview,
        evidence = evidence,
    )

    private fun evidence(
        source: EvidenceSource,
        confidence: EvidenceConfidence,
    ): EvidenceItem = EvidenceItem(
        source = source,
        detected = true,
        confidence = confidence,
        description = source.name,
    )
}
