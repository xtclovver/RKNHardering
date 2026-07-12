package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class BetaCheckRegistryTest {
    @Test
    fun `registry contains every normative check id`() {
        val expected = setOf(
            "beta.vpn_binder", "beta.user_profile", "beta.foreground_user",
            "beta.connectivity_binder", "beta.netd_netid", "beta.socket_identity",
            "beta.inet_diag_cookie", "beta.route_lookup", "beta.policy_rules",
            "beta.rtnl_address", "beta.extended_rtnetlink", "beta.interface_driver", "beta.interface_traffic",
            "beta.wireguard_genl", "beta.ovpn_genl", "beta.xfrm", "beta.unix_diag",
            "beta.unix_peer_identity", "beta.tun_fd", "beta.bpf_netd", "beta.cgroup_bpf",
            "beta.netfilter_path", "beta.original_destination", "beta.direct_syscall_consistency",
            "beta.io_uring_consistency", "beta.fd_identity", "beta.sandbox_identity.process",
            "beta.sandbox_identity.filesystem", "beta.sandbox_identity.namespace",
            "beta.fscrypt_identity", "beta.linker_integrity", "beta.dns_netid",
            "beta.native_dns_resolver", "beta.proxy_selector", "beta.transport_matrix",
            "beta.tls_interception", "beta.pktinfo", "beta.netlink_transitions",
            "beta.traceroute", "beta.server_fingerprint", "beta.root_emulator",
        )

        assertEquals(expected, BetaCheckRegistry.definitions.keys)
    }

    @Test
    fun `repeated active canary is not hard without typed causal validation`() {
        val observation = BetaObservation(
            checkId = "beta.interface_traffic",
            source = EvidenceSource.BETA_INTERFACE_TRAFFIC,
            availability = ProbeAvailability.AVAILABLE,
            polarity = ObservationPolarity.POSITIVE,
            authority = ObservationAuthority.ACTIVE_CANARY,
            confidence = EvidenceConfidence.HIGH,
            independenceGroup = "active_egress",
            detectionDomain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
            facts = mapOf("summary" to "counter delta"),
            observedAtElapsedMs = 1L,
            networkEpochId = "epoch",
        )
        val evaluated = BetaEvidencePolicy.evaluate(
            observation,
            BetaEvaluationContext(
                networkEpochId = "epoch",
                repeatValidations = mapOf(
                    observation.checkId to BetaRepeatValidation(2, classificationsMatch = true, epochStable = true),
                ),
            ),
        )

        assertFalse(evaluated.finding.detected)
        assertFalse(evaluated.evidence?.hardSignal == true)
    }
}
