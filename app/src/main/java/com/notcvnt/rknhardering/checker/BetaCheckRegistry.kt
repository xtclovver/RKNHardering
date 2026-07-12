package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority

data class BetaCheckDefinition(
    val checkId: String,
    val source: EvidenceSource,
    val detectionDomain: DetectionDomain,
    val independenceGroup: String,
    val hardAuthorities: Set<ObservationAuthority> = emptySet(),
)

object BetaCheckRegistry {
    private fun definition(
        checkId: String,
        source: EvidenceSource,
        domain: DetectionDomain,
        group: String,
        vararg hardAuthorities: ObservationAuthority,
    ) = BetaCheckDefinition(checkId, source, domain, group, hardAuthorities.toSet())

    val definitions: Map<String, BetaCheckDefinition> = listOf(
        definition("beta.vpn_binder", EvidenceSource.BETA_VPN_BINDER, DetectionDomain.VPN_OR_PROXY, "android_vpn_service", ObservationAuthority.BINDER_SERVICE),
        definition("beta.user_profile", EvidenceSource.BETA_USER_PROFILE, DetectionDomain.ISOLATED_PROFILE, "android_user_manager"),
        definition("beta.foreground_user", EvidenceSource.BETA_USER_PROFILE, DetectionDomain.ISOLATED_PROFILE, "android_user_manager"),
        definition("beta.connectivity_binder", EvidenceSource.BETA_CONNECTIVITY_BINDER, DetectionDomain.NETWORK_PATH_DIVERGENCE, "android_connectivity"),
        definition("beta.netd_netid", EvidenceSource.BETA_NETD_NETID, DetectionDomain.NETWORK_PATH_DIVERGENCE, "netd"),
        definition("beta.socket_identity", EvidenceSource.BETA_SOCKET_MARK, DetectionDomain.NETWORK_PATH_DIVERGENCE, "kernel_socket"),
        definition("beta.inet_diag_cookie", EvidenceSource.BETA_SOCKET_DIAG, DetectionDomain.NETWORK_PATH_DIVERGENCE, "socket_diag"),
        definition("beta.route_lookup", EvidenceSource.BETA_ROUTE_LOOKUP, DetectionDomain.NETWORK_PATH_DIVERGENCE, "kernel_route"),
        definition("beta.policy_rules", EvidenceSource.BETA_POLICY_RULE, DetectionDomain.NETWORK_PATH_DIVERGENCE, "kernel_route"),
        definition("beta.rtnl_address", EvidenceSource.BETA_RTNL_ADDRESS, DetectionDomain.NETWORK_PATH_DIVERGENCE, "kernel_link"),
        definition("beta.extended_rtnetlink", EvidenceSource.BETA_NETD_NETID, DetectionDomain.NETWORK_PATH_DIVERGENCE, "kernel_routing"),
        definition("beta.interface_driver", EvidenceSource.BETA_LINK_DRIVER, DetectionDomain.VPN_OR_PROXY, "kernel_link"),
        definition("beta.interface_traffic", EvidenceSource.BETA_INTERFACE_TRAFFIC, DetectionDomain.NETWORK_PATH_DIVERGENCE, "active_egress"),
        definition("beta.wireguard_genl", EvidenceSource.BETA_WIREGUARD_GENL, DetectionDomain.VPN_OR_PROXY, "kernel_vpn"),
        definition("beta.ovpn_genl", EvidenceSource.BETA_OVPN_GENL, DetectionDomain.VPN_OR_PROXY, "kernel_vpn"),
        definition("beta.xfrm", EvidenceSource.BETA_XFRM, DetectionDomain.VPN_OR_PROXY, "kernel_ipsec"),
        definition("beta.unix_diag", EvidenceSource.BETA_UNIX_DIAG, DetectionDomain.VPN_OR_PROXY, "local_control_plane"),
        definition("beta.unix_peer_identity", EvidenceSource.BETA_UNIX_DIAG, DetectionDomain.VPN_OR_PROXY, "local_control_plane"),
        definition("beta.tun_fd", EvidenceSource.BETA_TUN_FD, DetectionDomain.VPN_OR_PROXY, "process_fd", ObservationAuthority.KERNEL_QUERY),
        definition("beta.bpf_netd", EvidenceSource.BETA_BPF_NETFILTER, DetectionDomain.NETWORK_PATH_DIVERGENCE, "packet_policy"),
        definition("beta.cgroup_bpf", EvidenceSource.BETA_BPF_NETFILTER, DetectionDomain.NETWORK_PATH_DIVERGENCE, "packet_policy"),
        definition("beta.netfilter_path", EvidenceSource.BETA_BPF_NETFILTER, DetectionDomain.NETWORK_PATH_DIVERGENCE, "packet_policy"),
        definition("beta.original_destination", EvidenceSource.BETA_BPF_NETFILTER, DetectionDomain.NETWORK_PATH_DIVERGENCE, "packet_policy"),
        definition("beta.direct_syscall_consistency", EvidenceSource.BETA_HOOK_CONSISTENCY, DetectionDomain.HOOK_OR_TAMPERING, "hook_consistency"),
        definition("beta.io_uring_consistency", EvidenceSource.BETA_HOOK_CONSISTENCY, DetectionDomain.HOOK_OR_TAMPERING, "alternate_syscall_path"),
        definition("beta.fd_identity", EvidenceSource.BETA_HOOK_CONSISTENCY, DetectionDomain.HOOK_OR_TAMPERING, "process_fd"),
        definition("beta.sandbox_identity.process", EvidenceSource.BETA_SANDBOX_IDENTITY, DetectionDomain.APP_VIRTUALIZATION, "process_identity"),
        definition("beta.sandbox_identity.filesystem", EvidenceSource.BETA_SANDBOX_IDENTITY, DetectionDomain.APP_VIRTUALIZATION, "filesystem_identity"),
        definition("beta.sandbox_identity.namespace", EvidenceSource.BETA_NAMESPACE, DetectionDomain.APP_VIRTUALIZATION, "namespace_identity"),
        definition("beta.fscrypt_identity", EvidenceSource.BETA_SANDBOX_IDENTITY, DetectionDomain.APP_VIRTUALIZATION, "filesystem_identity"),
        definition("beta.linker_integrity", EvidenceSource.BETA_HOOK_CONSISTENCY, DetectionDomain.HOOK_OR_TAMPERING, "loader_integrity"),
        definition("beta.dns_netid", EvidenceSource.BETA_DNS_NETID, DetectionDomain.NETWORK_PATH_DIVERGENCE, "dns_path"),
        definition("beta.native_dns_resolver", EvidenceSource.BETA_DNS_NETID, DetectionDomain.NETWORK_PATH_DIVERGENCE, "dns_path"),
        definition("beta.proxy_selector", EvidenceSource.BETA_PROXY_SELECTOR, DetectionDomain.VPN_OR_PROXY, "android_proxy"),
        definition("beta.transport_matrix", EvidenceSource.BETA_TRANSPORT_MATRIX, DetectionDomain.NETWORK_PATH_DIVERGENCE, "active_egress"),
        definition("beta.tls_interception", EvidenceSource.BETA_TLS_INTERCEPTION, DetectionDomain.VPN_OR_PROXY, "tls_path"),
        definition("beta.pktinfo", EvidenceSource.BETA_PKTINFO, DetectionDomain.NETWORK_PATH_DIVERGENCE, "kernel_socket"),
        definition("beta.netlink_transitions", EvidenceSource.BETA_NETWORK_TRANSITION, DetectionDomain.NETWORK_PATH_DIVERGENCE, "network_timeline"),
        definition("beta.traceroute", EvidenceSource.BETA_TRACEROUTE, DetectionDomain.SYSTEM_NETWORK_CONTEXT, "path_observation"),
        definition("beta.server_fingerprint", EvidenceSource.BETA_SERVER_FINGERPRINT, DetectionDomain.SYSTEM_NETWORK_CONTEXT, "server_observation"),
        definition("beta.root_emulator", EvidenceSource.NATIVE_ROOT_DETECTION, DetectionDomain.DEVICE_INTEGRITY, "device_integrity"),
    ).associateBy(BetaCheckDefinition::checkId)

    fun get(checkId: String): BetaCheckDefinition? = definitions[checkId]
}
