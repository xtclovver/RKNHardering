package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.model.ProbeAvailability
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class BetaLocalProbeRowTest {
    @Test
    fun `local probe rows keep typed bounded fields`() {
        val unix = parse(
            "beta_v1|check=unix_diag|status=available|matched=2|own_uid_matches=1|markers=xray,tor",
            "unix_diag",
        )
        val route = parse(
            "beta_v1|check=extended_rtnetlink|status=available|multipath_hops=2|encap=true|nh_query=available",
            "extended_rtnetlink",
        )
        val timeline = parse(
            "beta_v1|check=netlink_transitions|status=available|duration_ms=500|link=1|route=2",
            "netlink_transitions",
        )
        val peer = parse(
            "beta_v1|check=unix_peer_identity|status=available|peer_uid_is_self=false|peer_domain_class=app",
            "unix_peer_identity",
        )

        assertEquals(ProbeAvailability.AVAILABLE, unix.availability)
        assertEquals("2", unix.fields["matched"])
        assertEquals("true", route.fields["encap"])
        assertEquals("2", timeline.fields["route"])
        assertEquals("app", peer.fields["peer_domain_class"])
        assertFalse(unix.fields.keys.any { it in setOf("name", "uid", "cookie", "inode") })
    }

    @Test
    fun `denial unsupported and duplicate status stay neutral or malformed`() {
        assertEquals(
            ProbeAvailability.PERMISSION_DENIED,
            parse("beta_v1|check=unix_diag|status=permission_denied|errno=13", "unix_diag").availability,
        )
        assertEquals(
            ProbeAvailability.UNSUPPORTED,
            parse("beta_v1|check=original_destination|status=unsupported|errno=92", "original_destination").availability,
        )
        assertEquals(
            ProbeAvailability.MALFORMED_RESPONSE,
            parse("beta_v1|check=pktinfo|status=available|status=error", "pktinfo").availability,
        )
    }

    private fun parse(row: String, checkId: String) =
        BetaProbeRowParser.parse(arrayOf(row), checkId)
}
