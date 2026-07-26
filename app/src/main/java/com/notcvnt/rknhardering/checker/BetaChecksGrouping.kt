package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.ProbeAvailability

enum class BetaGroupStatus {
    CLEAN,
    INCONCLUSIVE,
    SKIPPED,
    NEEDS_REVIEW,
    DETECTED,
    ERROR,
}

data class BetaDisplaySection(
    val group: BetaDisplayGroup,
    val status: BetaGroupStatus,
    val findings: List<Finding>,
    val checkIds: List<String>,
) {
    val initiallyExpanded: Boolean
        get() = group == BetaDisplayGroup.OVERVIEW || status in ATTENTION_STATUSES

    private companion object {
        val ATTENTION_STATUSES = setOf(
            BetaGroupStatus.NEEDS_REVIEW,
            BetaGroupStatus.DETECTED,
            BetaGroupStatus.ERROR,
        )
    }
}

object BetaChecksGrouping {
    fun sections(findings: List<Finding>): List<BetaDisplaySection> {
        val byGroup = findings.groupBy { BetaCheckRegistry.displayGroup(it.checkId) }
        return BetaDisplayGroup.entries.mapNotNull { group ->
            val groupedFindings = byGroup[group].orEmpty()
            if (groupedFindings.isEmpty()) return@mapNotNull null
            BetaDisplaySection(
                group = group,
                status = status(group, groupedFindings),
                findings = groupedFindings,
                checkIds = groupedFindings.mapNotNull(Finding::checkId).distinct(),
            )
        }
    }

    fun status(group: BetaDisplayGroup, findings: List<Finding>): BetaGroupStatus = when {
        findings.any(Finding::isError) -> BetaGroupStatus.ERROR
        findings.any(Finding::detected) -> BetaGroupStatus.DETECTED
        findings.any(Finding::needsReview) -> BetaGroupStatus.NEEDS_REVIEW
        findings.isNotEmpty() && findings.all { it.availability == ProbeAvailability.SKIPPED } ->
            BetaGroupStatus.SKIPPED
        group == BetaDisplayGroup.HOOK_TIMING -> BetaGroupStatus.INCONCLUSIVE
        findings.any { it.availability in INCONCLUSIVE_AVAILABILITIES } -> BetaGroupStatus.INCONCLUSIVE
        else -> BetaGroupStatus.CLEAN
    }

    private val INCONCLUSIVE_AVAILABILITIES = setOf(
        ProbeAvailability.UNSUPPORTED,
        ProbeAvailability.PERMISSION_DENIED,
        ProbeAvailability.UNAVAILABLE,
        ProbeAvailability.ERROR,
        ProbeAvailability.SKIPPED,
        ProbeAvailability.RACE,
        ProbeAvailability.MALFORMED_RESPONSE,
        ProbeAvailability.TRUNCATED,
    )
}
