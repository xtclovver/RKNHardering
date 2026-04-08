package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VpnAppKind
import org.junit.Assert.assertEquals
import org.junit.Test

class VerdictEngineTest {

    @Test
    fun `xray api evidence returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(
                evidence = listOf(
                    evidence(
                        source = EvidenceSource.XRAY_API,
                        confidence = EvidenceConfidence.HIGH,
                        kind = VpnAppKind.TARGETED_BYPASS,
                    ),
                ),
            ),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `targeted active vpn with corroboration returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(
                evidence = listOf(
                    evidence(
                        source = EvidenceSource.NETWORK_CAPABILITIES,
                        confidence = EvidenceConfidence.HIGH,
                    ),
                ),
            ),
            indirectSigns = category(
                evidence = listOf(
                    evidence(
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = EvidenceConfidence.HIGH,
                        kind = VpnAppKind.TARGETED_BYPASS,
                    ),
                ),
            ),
            locationSignals = category(),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `generic active vpn returns needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(
                evidence = listOf(
                    evidence(
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = EvidenceConfidence.MEDIUM,
                        kind = VpnAppKind.GENERIC_VPN,
                    ),
                ),
            ),
            locationSignals = category(),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `localhost proxy alone returns needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(
                evidence = listOf(
                    evidence(
                        source = EvidenceSource.LOCAL_PROXY,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                ),
            ),
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `foreign geo alone returns not detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(needsReview = true),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `vpn gateway leak returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(
                evidence = listOf(
                    evidence(
                        source = EvidenceSource.VPN_GATEWAY_LEAK,
                        confidence = EvidenceConfidence.HIGH,
                    ),
                ),
            ),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `no evidence returns not detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `network mcc RU plus foreign geoip returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(needsReview = true),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = locationCategory(networkMccRu = true),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `network mcc RU foreign sim roaming plus foreign geoip returns detected`() {
        val geoEvidence = evidence(
            source = EvidenceSource.GEO_IP,
            confidence = EvidenceConfidence.MEDIUM,
        )

        val verdict = VerdictEngine.evaluate(
            geoIp = category(evidence = listOf(geoEvidence)),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = locationCategory(networkMccRu = true),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `foreign network mcc plus foreign geoip returns needs review`() {
        val locationEvidence = evidence(
            source = EvidenceSource.LOCATION_SIGNALS,
            confidence = EvidenceConfidence.MEDIUM,
        )
        val geoEvidence = evidence(
            source = EvidenceSource.GEO_IP,
            confidence = EvidenceConfidence.MEDIUM,
        )

        val verdict = VerdictEngine.evaluate(
            geoIp = category(evidence = listOf(geoEvidence), needsReview = true),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(evidence = listOf(locationEvidence), needsReview = true),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `empty location signals does not affect verdict`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `network mcc RU without foreign geoip returns not detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = locationCategory(networkMccRu = true),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    private fun category(
        evidence: List<EvidenceItem> = emptyList(),
        needsReview: Boolean = false,
    ): CategoryResult = CategoryResult(
        name = "test",
        detected = evidence.any { it.detected && it.confidence == EvidenceConfidence.HIGH },
        findings = emptyList(),
        needsReview = needsReview,
        evidence = evidence,
    )

    private fun locationCategory(
        networkMccRu: Boolean,
        evidence: List<EvidenceItem> = emptyList(),
    ): CategoryResult {
        val findings = if (networkMccRu) {
            listOf(Finding("Network MCC: 250"), Finding("network_mcc_ru:true"))
        } else {
            listOf(Finding("Network MCC: 244"))
        }
        return CategoryResult(
            name = "Сигналы местоположения",
            detected = false,
            findings = findings,
            needsReview = !networkMccRu,
            evidence = evidence,
        )
    }

    private fun bypass(
        evidence: List<EvidenceItem> = emptyList(),
    ): BypassResult = BypassResult(
        proxyEndpoint = null,
        directIp = null,
        proxyIp = null,
        xrayApiScanResult = null,
        findings = emptyList(),
        detected = evidence.any { it.source == EvidenceSource.XRAY_API || it.source == EvidenceSource.SPLIT_TUNNEL_BYPASS || it.source == EvidenceSource.VPN_GATEWAY_LEAK },
        evidence = evidence,
    )

    private fun evidence(
        source: EvidenceSource,
        confidence: EvidenceConfidence,
        kind: VpnAppKind? = null,
    ): EvidenceItem = EvidenceItem(
        source = source,
        detected = true,
        confidence = confidence,
        description = source.name,
        kind = kind,
    )
}
