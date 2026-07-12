package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BetaEvidencePolicyTest {
    @Test
    fun `unavailable and permission denied never create positive evidence`() {
        for (availability in listOf(ProbeAvailability.UNAVAILABLE, ProbeAvailability.PERMISSION_DENIED)) {
            val evaluated = BetaEvidencePolicy.evaluate(observation(availability = availability), context())
            assertNull(evaluated.evidence)
            assertFalse(evaluated.finding.detected)
        }
    }

    @Test
    fun `single profile observation is review not detected`() {
        val evaluated = BetaEvidencePolicy.evaluate(
            observation(
                checkId = "beta.user_profile",
                authority = ObservationAuthority.PUBLIC_ANDROID_API,
                source = EvidenceSource.BETA_USER_PROFILE,
                domain = DetectionDomain.ISOLATED_PROFILE,
                group = "android_user_manager",
            ),
            context(),
        )

        assertFalse(evaluated.finding.detected)
        assertTrue(evaluated.finding.needsReview)
        assertTrue(evaluated.evidence?.detected == true)
    }

    @Test
    fun `suppression and epoch mismatch neutralize a positive observation`() {
        val evaluated = BetaEvidencePolicy.evaluate(
            observation(
                suppressions = listOf(BetaSuppressionRuleId.VCN_CONTEXT),
                networkEpochId = "old",
            ),
            context(),
        )

        assertNull(evaluated.evidence)
        assertTrue(BetaSuppressionRuleId.VCN_CONTEXT in evaluated.suppressionRuleIds)
        assertTrue(BetaSuppressionRuleId.NETWORK_EPOCH_CHANGED in evaluated.suppressionRuleIds)
        assertTrue(BetaSuppressionRuleId.NETWORK_EPOCH_CHANGED in evaluated.finding.suppressionRuleIds)
        assertEquals(EvidenceConfidence.MEDIUM, evaluated.finding.rawConfidence)
    }

    @Test
    fun `metadata that contradicts registry is neutralized`() {
        val evaluated = BetaEvidencePolicy.evaluate(
            observation(
                checkId = "beta.user_profile",
                source = EvidenceSource.BETA_SOCKET_DIAG,
                domain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
                group = "socket_diag",
            ),
            context(),
        )

        assertFalse(evaluated.finding.needsReview)
        assertTrue(BetaSuppressionRuleId.ABI_OR_PARSER_MISMATCH in evaluated.suppressionRuleIds)
    }

    @Test
    fun `only central policy can make repeated allowlisted high evidence hard`() {
        val checkId = "beta.vpn_binder"
        val high = BetaEvidencePolicy.evaluate(
            observation(checkId = checkId, confidence = EvidenceConfidence.HIGH),
            context(repeated = setOf(checkId)),
        )
        val medium = BetaEvidencePolicy.evaluate(
            observation(checkId = checkId),
            context(repeated = setOf(checkId)),
        )

        assertTrue(high.evidence?.hardSignal == true)
        assertFalse(medium.evidence?.hardSignal == true)
    }

    @Test
    fun `hard signal rejects mismatched authority and inconsistent repeats`() {
        val checkId = "beta.vpn_binder"
        val wrongAuthority = BetaEvidencePolicy.evaluate(
            observation(checkId = checkId, confidence = EvidenceConfidence.HIGH, authority = ObservationAuthority.HEURISTIC),
            context(repeated = setOf(checkId)),
        )
        val inconsistent = BetaEvidencePolicy.evaluate(
            observation(checkId = checkId, confidence = EvidenceConfidence.HIGH),
            BetaEvaluationContext(
                networkEpochId = "epoch",
                repeatValidations = mapOf(checkId to BetaRepeatValidation(2, classificationsMatch = false, epochStable = true)),
            ),
        )

        assertFalse(wrongAuthority.evidence?.hardSignal == true)
        assertFalse(inconsistent.evidence?.hardSignal == true)
    }

    private fun observation(
        checkId: String = "beta.vpn_binder",
        availability: ProbeAvailability = ProbeAvailability.AVAILABLE,
        confidence: EvidenceConfidence = EvidenceConfidence.MEDIUM,
        suppressions: List<BetaSuppressionRuleId> = emptyList(),
        networkEpochId: String = "epoch",
        authority: ObservationAuthority = ObservationAuthority.BINDER_SERVICE,
        source: EvidenceSource = EvidenceSource.BETA_VPN_BINDER,
        domain: DetectionDomain = DetectionDomain.VPN_OR_PROXY,
        group: String = "android_vpn_service",
    ) = BetaObservation(
        checkId = checkId,
        source = source,
        availability = availability,
        polarity = ObservationPolarity.POSITIVE,
        authority = authority,
        confidence = confidence,
        independenceGroup = group,
        detectionDomain = domain,
        facts = mapOf("summary" to "active VPN"),
        suppressions = suppressions,
        observedAtElapsedMs = 1L,
        networkEpochId = networkEpochId,
    )

    private fun context(repeated: Set<String> = emptySet()) = BetaEvaluationContext(
        networkEpochId = "epoch",
        repeatValidations = repeated.associateWith {
            BetaRepeatValidation(2, classificationsMatch = true, epochStable = true)
        },
    )
}
