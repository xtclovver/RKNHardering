package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

class VerdictEngineTest {

    @Test
    fun `table 2 matrix is implemented literally`() {
        val cases = listOf(
            MatrixCase("000", geo = false, direct = false, indirect = false, expected = Verdict.NOT_DETECTED),
            MatrixCase("010", geo = false, direct = true, indirect = false, expected = Verdict.NOT_DETECTED),
            MatrixCase("001", geo = false, direct = false, indirect = true, expected = Verdict.NOT_DETECTED),
            MatrixCase("100", geo = true, direct = false, indirect = false, expected = Verdict.NEEDS_REVIEW),
            MatrixCase("011", geo = false, direct = true, indirect = true, expected = Verdict.NEEDS_REVIEW),
            MatrixCase("110", geo = true, direct = true, indirect = false, expected = Verdict.DETECTED),
            MatrixCase("101", geo = true, direct = false, indirect = true, expected = Verdict.DETECTED),
            MatrixCase("111", geo = true, direct = true, indirect = true, expected = Verdict.DETECTED),
        )

        for (case in cases) {
            val verdict = VerdictEngine.evaluate(
                geoIp = geoCategory(case.geo),
                directSigns = directCategory(case.direct),
                indirectSigns = indirectCategory(case.indirect),
                locationSignals = category(),
                bypassResult = bypass(),
            )

            assertEquals("matrix case ${case.label}", case.expected, verdict)
        }
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
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `split tunnel bypass override returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = category(),
            bypassResult = bypass(
                evidence = listOf(evidence(EvidenceSource.SPLIT_TUNNEL_BYPASS, EvidenceConfidence.HIGH)),
            ),
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
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `russian location marker plus foreign geoip returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = geoCategory(true),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = locationCategory("cell_country_ru:true"),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `russian location marker without foreign geoip does not override verdict`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = category(),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = locationCategory("network_mcc_ru:true"),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    @Test
    fun `coarse BeaconDB fallback does not override foreign geoip on its own`() {
        val verdict = VerdictEngine.evaluate(
            geoIp = geoCategory(true),
            directSigns = category(),
            indirectSigns = category(),
            locationSignals = CategoryResult(
                name = "location",
                detected = false,
                findings = listOf(Finding("BeaconDB: coarse cell area fallback")),
                needsReview = false,
                evidence = emptyList(),
            ),
            bypassResult = bypass(),
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
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
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }

    private data class MatrixCase(
        val label: String,
        val geo: Boolean,
        val direct: Boolean,
        val indirect: Boolean,
        val expected: Verdict,
    )

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

    private fun locationCategory(marker: String): CategoryResult = CategoryResult(
        name = "location",
        detected = false,
        findings = listOf(Finding(marker)),
        needsReview = false,
        evidence = emptyList(),
    )

    private fun category(
        evidence: List<EvidenceItem> = emptyList(),
        needsReview: Boolean = false,
    ): CategoryResult = CategoryResult(
        name = "test",
        detected = evidence.any { it.detected },
        findings = emptyList(),
        needsReview = needsReview,
        evidence = evidence,
    )

    private fun bypass(
        evidence: List<EvidenceItem> = emptyList(),
    ): BypassResult = BypassResult(
        proxyEndpoint = null,
        directIp = null,
        proxyIp = null,
        xrayApiScanResult = null,
        findings = emptyList(),
        detected = evidence.any { it.detected },
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
