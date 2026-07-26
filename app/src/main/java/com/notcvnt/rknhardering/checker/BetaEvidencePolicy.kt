package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceMaturity
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability

data class BetaEvaluationContext(
    val networkEpochId: String?,
    val repeatValidations: Map<String, BetaRepeatValidation> = emptyMap(),
)

data class BetaRepeatValidation(
    val successfulSamples: Int,
    val classificationsMatch: Boolean,
    val epochStable: Boolean,
)

data class EvaluatedBetaEvidence(
    val finding: Finding,
    val evidence: EvidenceItem? = null,
    val originalConfidence: EvidenceConfidence,
    val finalConfidence: EvidenceConfidence,
    val suppressionRuleIds: List<BetaSuppressionRuleId>,
)

object BetaEvidencePolicy {
    fun evaluate(
        observation: BetaObservation,
        context: BetaEvaluationContext,
    ): EvaluatedBetaEvidence {
        val suppressions = buildList {
            addAll(observation.suppressions)
            val definition = BetaCheckRegistry.get(observation.checkId)
            if (definition == null ||
                definition.source != observation.source ||
                definition.detectionDomain != observation.detectionDomain ||
                definition.independenceGroup != observation.independenceGroup ||
                (definition.expectedAuthority != null && definition.expectedAuthority != observation.authority)
            ) {
                add(BetaSuppressionRuleId.ABI_OR_PARSER_MISMATCH)
            }
            if (observation.networkEpochId != null &&
                context.networkEpochId != null &&
                observation.networkEpochId != context.networkEpochId
            ) {
                add(BetaSuppressionRuleId.NETWORK_EPOCH_CHANGED)
            }
        }.distinct()
        val positive = observation.availability == ProbeAvailability.AVAILABLE &&
            observation.polarity == ObservationPolarity.POSITIVE &&
            suppressions.isEmpty()
        val finalConfidence = if (positive) observation.confidence else EvidenceConfidence.LOW
        val description = observation.facts["summary"] ?: observation.checkId
        val repeatValidation = context.repeatValidations[observation.checkId]
        val hardPolicy = BetaCheckRegistry.get(observation.checkId)
        val hardSignal = positive &&
            finalConfidence == EvidenceConfidence.HIGH &&
            hardPolicy?.source == observation.source &&
            hardPolicy.detectionDomain == observation.detectionDomain &&
            hardPolicy.independenceGroup == observation.independenceGroup &&
            observation.authority in hardPolicy.hardAuthorities &&
            repeatValidation != null &&
            repeatValidation.successfulSamples >= 2 &&
            repeatValidation.classificationsMatch &&
            repeatValidation.epochStable
        val finding = Finding(
            description = description,
            detected = hardSignal,
            needsReview = positive && finalConfidence != EvidenceConfidence.LOW && !hardSignal,
            isInformational = !positive,
            isError = observation.availability in setOf(
                ProbeAvailability.ERROR,
                ProbeAvailability.MALFORMED_RESPONSE,
                ProbeAvailability.TRUNCATED,
            ),
            source = observation.source,
            confidence = finalConfidence,
            maturity = EvidenceMaturity.BETA,
            checkId = observation.checkId,
            availability = observation.availability,
            rawConfidence = observation.confidence,
            suppressionRuleIds = suppressions,
            facts = observation.facts - "summary",
            independenceGroup = observation.independenceGroup,
            detectionDomain = observation.detectionDomain,
        )
        val evidence = if (positive) {
            EvidenceItem(
                source = observation.source,
                detected = true,
                confidence = finalConfidence,
                description = description,
                maturity = EvidenceMaturity.BETA,
                checkId = observation.checkId,
                independenceGroup = observation.independenceGroup,
                detectionDomain = observation.detectionDomain,
                hardSignal = hardSignal,
            )
        } else {
            null
        }
        return EvaluatedBetaEvidence(
            finding = finding,
            evidence = evidence,
            originalConfidence = observation.confidence,
            finalConfidence = finalConfidence,
            suppressionRuleIds = suppressions,
        )
    }
}
