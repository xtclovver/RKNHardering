package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceMaturity
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VerdictRuleCode
import org.junit.Assert.assertEquals
import org.junit.Test

class VerdictEngineBetaTest {
    @Test
    fun `beta disabled preserves legacy verdict`() {
        val decision = evaluate(betaEnabled = false, beta = category(beta("kernel_route")))

        assertEquals(Verdict.NOT_DETECTED, decision.verdict)
        assertEquals(VerdictRuleCode.R5_MATRIX, decision.rule)
    }

    @Test
    fun `two independent beta network groups detect through R2`() {
        val decision = evaluate(
            beta = category(
                beta("kernel_route"),
                beta("kernel_socket", source = EvidenceSource.BETA_SOCKET_MARK),
            ),
        )

        assertEquals(Verdict.DETECTED, decision.verdict)
        assertEquals(VerdictRuleCode.R2_BETA_EVIDENCE, decision.rule)
    }

    @Test
    fun `same beta group does not form quorum`() {
        val decision = evaluate(
            beta = category(
                beta("kernel_route"),
                beta("kernel_route", source = EvidenceSource.BETA_POLICY_RULE),
            ),
        )

        assertEquals(Verdict.NEEDS_REVIEW, decision.verdict)
        assertEquals(VerdictRuleCode.R6_FALLBACK, decision.rule)
    }

    @Test
    fun `stable source from same group does not double vote`() {
        val decision = evaluate(
            beta = category(beta("kernel_route")),
            indirect = category(stable(EvidenceSource.ROUTING)),
        )

        assertEquals(Verdict.NEEDS_REVIEW, decision.verdict)
    }

    @Test
    fun `independent stable source corroborates beta network group`() {
        val decision = evaluate(
            beta = category(beta("kernel_route")),
            direct = category(stable(EvidenceSource.SYSTEM_PROXY)),
        )

        assertEquals(Verdict.DETECTED, decision.verdict)
        assertEquals(VerdictRuleCode.R2_BETA_EVIDENCE, decision.rule)
    }

    @Test
    fun `hard medium is review while hard high detects`() {
        val medium = evaluate(beta = category(beta("kernel_vpn", hard = true)))
        val high = evaluate(beta = category(beta("kernel_vpn", hard = true, confidence = EvidenceConfidence.HIGH)))

        assertEquals(Verdict.NEEDS_REVIEW, medium.verdict)
        assertEquals(Verdict.DETECTED, high.verdict)
    }

    @Test
    fun `isolation alone is review and does not claim vpn domain`() {
        val decision = evaluate(
            beta = category(
                beta(
                    group = "android_user_manager",
                    source = EvidenceSource.BETA_USER_PROFILE,
                    domain = DetectionDomain.ISOLATED_PROFILE,
                ),
            ),
        )

        assertEquals(Verdict.NEEDS_REVIEW, decision.verdict)
        assertEquals(setOf(DetectionDomain.ISOLATED_PROFILE), decision.detectionDomains)
    }

    @Test
    fun `low and system context beta evidence are neutral`() {
        val low = evaluate(beta = category(beta("kernel_route", confidence = EvidenceConfidence.LOW)))
        val context = evaluate(
            beta = category(
                beta(
                    "path_observation",
                    source = EvidenceSource.BETA_SERVER_FINGERPRINT,
                    domain = DetectionDomain.SYSTEM_NETWORK_CONTEXT,
                ),
            ),
        )

        assertEquals(Verdict.NOT_DETECTED, low.verdict)
        assertEquals(Verdict.NOT_DETECTED, context.verdict)
    }

    private fun evaluate(
        betaEnabled: Boolean = true,
        beta: CategoryResult = category(),
        direct: CategoryResult = category(),
        indirect: CategoryResult = category(),
    ) = VerdictEngine.evaluateDetailed(
        geoIp = category(),
        directSigns = direct,
        indirectSigns = indirect,
        locationSignals = category(),
        bypassResult = BypassResult(null, null, null, null, xrayApiScanResult = null, findings = emptyList(), detected = false),
        ipConsensus = IpConsensusResult.empty(),
        betaSigns = beta,
        betaEnabled = betaEnabled,
    )

    private fun category(vararg evidence: EvidenceItem): CategoryResult = CategoryResult(
        name = "test",
        detected = evidence.any { it.detected },
        findings = emptyList(),
        evidence = evidence.toList(),
    )

    private fun beta(
        group: String,
        source: EvidenceSource = EvidenceSource.BETA_ROUTE_LOOKUP,
        domain: DetectionDomain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
        confidence: EvidenceConfidence = EvidenceConfidence.MEDIUM,
        hard: Boolean = false,
    ) = EvidenceItem(
        source = source,
        detected = true,
        confidence = confidence,
        description = source.name,
        maturity = EvidenceMaturity.BETA,
        checkId = "beta.test.${source.name.lowercase()}",
        independenceGroup = group,
        detectionDomain = domain,
        hardSignal = hard,
    )

    private fun stable(source: EvidenceSource) = EvidenceItem(
        source = source,
        detected = true,
        confidence = EvidenceConfidence.MEDIUM,
        description = source.name,
    )
}
