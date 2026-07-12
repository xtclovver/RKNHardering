package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.checker.BetaEvaluationContext
import com.notcvnt.rknhardering.checker.BetaEvidencePolicy
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramSocket
import java.net.InetAddress

class AdvancedNetlinkProbeTest {
    @Test
    fun `parser accepts bounded versioned row`() {
        val row = BetaProbeRowParser.parse(
            arrayOf("beta_v1|check=inet_diag_cookie|status=available|matched=true|cookie_match=true"),
            "inet_diag_cookie",
        )

        assertEquals(ProbeAvailability.AVAILABLE, row.availability)
        assertEquals("true", row.fields["matched"])
    }

    @Test
    fun `parser distinguishes denied unsupported malformed and truncated`() {
        assertEquals(
            ProbeAvailability.PERMISSION_DENIED,
            parse("beta_v1|check=socket_identity|status=permission_denied").availability,
        )
        assertEquals(
            ProbeAvailability.UNSUPPORTED,
            parse("beta_v1|check=socket_identity|status=unsupported").availability,
        )
        assertEquals(
            ProbeAvailability.MALFORMED_RESPONSE,
            parse("beta_v1|check=socket_identity|status=available|status=error").availability,
        )
        assertEquals(
            ProbeAvailability.TRUNCATED,
            BetaProbeRowParser.parse(Array(33) { "x" }, "socket_identity").availability,
        )
    }

    @Test
    fun `matching exact cookie is benign and unavailable is neutral`() {
        val benign = AdvancedNetlinkProbe.diagObservation(
            ParsedBetaProbeRow(
                "inet_diag_cookie",
                ProbeAvailability.AVAILABLE,
                mapOf("matched" to "true", "cookie_match" to "true"),
            ),
            "epoch",
            1L,
        )
        val denied = AdvancedNetlinkProbe.diagObservation(
            ParsedBetaProbeRow("inet_diag_cookie", ProbeAvailability.PERMISSION_DENIED, emptyMap()),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, benign.polarity)
        assertEquals(ObservationPolarity.INCONCLUSIVE, denied.polarity)
        assertNull(BetaEvidencePolicy.evaluate(denied, BetaEvaluationContext("epoch")).evidence)
    }

    @Test
    fun `stable critical mismatch becomes review but never hard`() {
        val observation = AdvancedNetlinkProbe.diagObservation(
            ParsedBetaProbeRow(
                "inet_diag_cookie",
                ProbeAvailability.AVAILABLE,
                mapOf("critical_mismatch" to "true", "cookie" to "sensitive", "inode" to "42"),
            ),
            "epoch",
            1L,
        )
        val evaluated = BetaEvidencePolicy.evaluate(observation, BetaEvaluationContext("epoch"))

        assertTrue(evaluated.finding.needsReview)
        assertFalse(evaluated.finding.detected)
        assertFalse(evaluated.evidence?.hardSignal == true)
        assertFalse(observation.facts.values.any { it.contains("sensitive") || it.contains("42") })
    }

    @Test
    fun `route table rule count and narrow addresses alone stay informational`() {
        val route = AdvancedNetlinkProbe.routeObservation(
            ParsedBetaProbeRow(
                "route_lookup",
                ProbeAvailability.AVAILABLE,
                mapOf("table" to "101", "oif" to "7"),
            ),
            "epoch",
            1L,
        )
        val rules = AdvancedNetlinkProbe.rulesObservation(
            ParsedBetaProbeRow(
                "policy_rules",
                ProbeAvailability.AVAILABLE,
                mapOf("matching_uid_rules" to "12"),
            ),
            "epoch",
            1L,
        )
        val address = AdvancedNetlinkProbe.addressObservation(
            ParsedBetaProbeRow(
                "rtnl_address",
                ProbeAvailability.AVAILABLE,
                mapOf("address_count" to "1", "prefix" to "32"),
            ),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, route.polarity)
        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, rules.polarity)
        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, address.polarity)
    }

    @Test
    fun `java and native socket contradiction drives positive fixture`() {
        DatagramSocket().use { socket ->
            socket.connect(InetAddress.getByName("127.0.0.1"), 53)
            val matching = ParsedBetaProbeRow(
                "socket_identity",
                ProbeAvailability.AVAILABLE,
                mapOf(
                    "cookie" to "1",
                    "local_address" to socket.localAddress.hostAddress.orEmpty(),
                    "local_port" to socket.localPort.toString(),
                    "remote_address" to socket.inetAddress.hostAddress.orEmpty(),
                    "remote_port" to socket.port.toString(),
                ),
            )
            val benign = AdvancedNetlinkProbe.compareSocketViews(matching, socket)
            val contradiction = AdvancedNetlinkProbe.compareSocketViews(
                matching.copy(fields = matching.fields + ("remote_port" to "443")),
                socket,
            )

            assertEquals("false", benign.fields["critical_mismatch"])
            assertEquals("true", contradiction.fields["critical_mismatch"])
            val evaluated = BetaEvidencePolicy.evaluate(
                AdvancedNetlinkProbe.socketObservation(contradiction, "epoch", 1L),
                BetaEvaluationContext("epoch"),
            )
            assertTrue(evaluated.finding.needsReview)
            assertFalse(evaluated.finding.detected)
        }
    }

    @Test
    fun `ipv4 mapped and canonical address forms normalize equally`() {
        assertEquals(
            AdvancedNetlinkProbe.normalizeAddress("8.8.8.8"),
            AdvancedNetlinkProbe.normalizeAddress("::ffff:8.8.8.8"),
        )
        assertEquals(
            AdvancedNetlinkProbe.normalizeAddress("2001:db8::1"),
            AdvancedNetlinkProbe.normalizeAddress("2001:0db8:0:0:0:0:0:1"),
        )
    }

    @Test
    fun `incomplete socket identity remains inconclusive`() {
        val observation = AdvancedNetlinkProbe.socketObservation(
            ParsedBetaProbeRow(
                "socket_identity",
                ProbeAvailability.AVAILABLE,
                mapOf("cookie" to "1", "critical_mismatch" to "false"),
            ),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.INCONCLUSIVE, observation.polarity)
    }

    @Test
    fun `original destination redirect needs concrete loopback mismatch`() {
        val redirected = AdvancedNetlinkProbe.originalDestinationObservation(
            ParsedBetaProbeRow(
                "original_destination",
                ProbeAvailability.AVAILABLE,
                mapOf("matches_peer" to "false", "original_loopback" to "true"),
            ),
            "epoch",
            1L,
        )
        val matching = AdvancedNetlinkProbe.originalDestinationObservation(
            ParsedBetaProbeRow(
                "original_destination",
                ProbeAvailability.AVAILABLE,
                mapOf("matches_peer" to "true", "original_loopback" to "false"),
            ),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.POSITIVE, redirected.polarity)
        assertTrue(BetaSuppressionRuleId.NO_CAUSAL_COUNTER_DELTA in redirected.suppressions)
        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, matching.polarity)
    }

    private fun parse(value: String) =
        BetaProbeRowParser.parse(arrayOf(value), "socket_identity")
}
