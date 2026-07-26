package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.ProbeAvailability
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BetaChecksGroupingTest {
    @Test
    fun `groups use fixed order and preserve finding order`() {
        val sections = BetaChecksGrouping.sections(
            listOf(
                finding("kernel second", "beta.vpnhide_hook_timing.kernel"),
                finding("unknown", "beta.future"),
                finding("libc first", "beta.vpnhide_hook_timing.libc"),
                finding("android", "beta.vpn_binder"),
            ),
        )

        assertEquals(
            listOf(
                BetaDisplayGroup.OVERVIEW,
                BetaDisplayGroup.ANDROID_PROFILE,
                BetaDisplayGroup.HOOK_TIMING,
            ),
            sections.map(BetaDisplaySection::group),
        )
        assertEquals(
            listOf("kernel second", "libc first"),
            sections.last().findings.map(Finding::description),
        )
    }

    @Test
    fun `overview expands by default and attention or errors expand automatically`() {
        val sections = BetaChecksGrouping.sections(
            listOf(
                finding("coverage", "beta.coverage"),
                finding("clean", "beta.vpn_binder"),
                finding("review", "beta.route_lookup", needsReview = true),
                finding("error", "beta.transport_matrix", isError = true),
                finding("detected", "beta.direct_syscall_consistency", detected = true),
            ),
        ).associateBy(BetaDisplaySection::group)

        assertTrue(sections.getValue(BetaDisplayGroup.OVERVIEW).initiallyExpanded)
        assertFalse(sections.getValue(BetaDisplayGroup.ANDROID_PROFILE).initiallyExpanded)
        assertTrue(sections.getValue(BetaDisplayGroup.SOCKETS_ROUTING).initiallyExpanded)
        assertTrue(sections.getValue(BetaDisplayGroup.ACTIVE_NETWORK).initiallyExpanded)
        assertTrue(sections.getValue(BetaDisplayGroup.INTEGRITY_ISOLATION).initiallyExpanded)
        assertEquals(BetaGroupStatus.NEEDS_REVIEW, sections.getValue(BetaDisplayGroup.SOCKETS_ROUTING).status)
        assertEquals(BetaGroupStatus.ERROR, sections.getValue(BetaDisplayGroup.ACTIVE_NETWORK).status)
        assertEquals(BetaGroupStatus.DETECTED, sections.getValue(BetaDisplayGroup.INTEGRITY_ISOLATION).status)
    }

    @Test
    fun `skipped unavailable and unconfirmed hook groups stay neutral and collapsed`() {
        val sections = BetaChecksGrouping.sections(
            listOf(
                finding("skipped", "beta.vpn_binder", availability = ProbeAvailability.SKIPPED),
                finding("unsupported", "beta.route_lookup", availability = ProbeAvailability.UNSUPPORTED),
                finding("unconfirmed", "beta.vpnhide_hook_timing.libc", availability = ProbeAvailability.AVAILABLE),
            ),
        ).associateBy(BetaDisplaySection::group)

        assertEquals(BetaGroupStatus.SKIPPED, sections.getValue(BetaDisplayGroup.ANDROID_PROFILE).status)
        assertEquals(BetaGroupStatus.INCONCLUSIVE, sections.getValue(BetaDisplayGroup.SOCKETS_ROUTING).status)
        assertEquals(BetaGroupStatus.INCONCLUSIVE, sections.getValue(BetaDisplayGroup.HOOK_TIMING).status)
        assertFalse(sections.getValue(BetaDisplayGroup.ANDROID_PROFILE).initiallyExpanded)
        assertFalse(sections.getValue(BetaDisplayGroup.SOCKETS_ROUTING).initiallyExpanded)
        assertFalse(sections.getValue(BetaDisplayGroup.HOOK_TIMING).initiallyExpanded)
    }

    private fun finding(
        description: String,
        checkId: String,
        detected: Boolean = false,
        needsReview: Boolean = false,
        isError: Boolean = false,
        availability: ProbeAvailability? = null,
    ) = Finding(
        description = description,
        checkId = checkId,
        detected = detected,
        needsReview = needsReview,
        isError = isError,
        availability = availability,
    )
}
