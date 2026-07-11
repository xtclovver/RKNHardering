package com.notcvnt.rknhardering

import android.content.Context
import androidx.annotation.StringRes
import com.notcvnt.rknhardering.model.NativeSignalId
import java.util.Locale

enum class NativeSignalCategory(@StringRes val titleRes: Int) {
    INTERFACES(R.string.native_category_interfaces),
    ROUTES(R.string.native_category_routes),
    VPN_ARTIFACTS(R.string.native_category_vpn_artifacts),
    HOOKS(R.string.native_category_hooks),
    ROOT(R.string.native_category_root),
    EMULATION(R.string.native_category_emulation),
    GENERAL(R.string.native_category_general),
}

data class NativeSignalInfo(
    val id: NativeSignalId,
    val category: NativeSignalCategory,
    val slug: String,
    @param:StringRes val titleRes: Int,
)

object NativeSignalCatalog {
    const val BASE_URL = "https://xtclovver.github.io/RKNHardering/help"

    val entries: List<NativeSignalInfo> = NativeSignalId.entries.map(::info)

    fun info(id: NativeSignalId?): NativeSignalInfo = when (id ?: NativeSignalId.UNKNOWN) {
        NativeSignalId.NATIVE_LIBRARY -> item(id, NativeSignalCategory.GENERAL, "native-library", R.string.native_signal_title_native_library)
        NativeSignalId.INTERFACE_ENUMERATION -> item(id, NativeSignalCategory.INTERFACES, "interface-enumeration", R.string.native_signal_title_interface_enumeration)
        NativeSignalId.TUNTAP_TYPE -> item(id, NativeSignalCategory.INTERFACES, "tuntap-type", R.string.native_signal_title_tuntap_type)
        NativeSignalId.IPSEC_INTERFACE -> item(id, NativeSignalCategory.INTERFACES, "ipsec-interface", R.string.native_signal_title_ipsec_interface)
        NativeSignalId.JVM_NATIVE_MISMATCH -> item(id, NativeSignalCategory.INTERFACES, "jvm-native-mismatch", R.string.native_signal_title_jvm_native_mismatch)
        NativeSignalId.ROUTE_TABLE -> item(id, NativeSignalCategory.ROUTES, "route-table", R.string.native_signal_title_route_table)
        NativeSignalId.HOST_ROUTE -> item(id, NativeSignalCategory.ROUTES, "host-route", R.string.native_signal_title_host_route)
        NativeSignalId.HOOK_MARKERS -> item(id, NativeSignalCategory.HOOKS, "hook-markers", R.string.native_signal_title_hook_markers)
        NativeSignalId.RWX_MEMORY_REGIONS -> item(id, NativeSignalCategory.HOOKS, "rwx-memory-regions", R.string.native_signal_title_rwx_memory)
        NativeSignalId.LIBRARY_INTEGRITY -> item(id, NativeSignalCategory.HOOKS, "library-integrity", R.string.native_signal_title_library_integrity)
        NativeSignalId.ROOT_INDICATORS -> item(id, NativeSignalCategory.ROOT, "root-indicators", R.string.native_signal_title_root)
        NativeSignalId.ROOT_SU_BINARY -> item(id, NativeSignalCategory.ROOT, "root-su-binary", R.string.native_signal_title_root)
        NativeSignalId.ROOT_PROPERTY -> item(id, NativeSignalCategory.ROOT, "root-property", R.string.native_signal_title_root)
        NativeSignalId.ROOT_MANAGEMENT -> item(id, NativeSignalCategory.ROOT, "root-management", R.string.native_signal_title_root)
        NativeSignalId.ROOT_SYSTEM_RW -> item(id, NativeSignalCategory.ROOT, "root-system-rw", R.string.native_signal_title_root)
        NativeSignalId.ROOT_SUSPICIOUS_MOUNT -> item(id, NativeSignalCategory.ROOT, "root-suspicious-mount", R.string.native_signal_title_root)
        NativeSignalId.ROOT_OVERLAY_MOUNT -> item(id, NativeSignalCategory.ROOT, "root-overlay-mount", R.string.native_signal_title_root)
        NativeSignalId.ROOT_SELINUX -> item(id, NativeSignalCategory.ROOT, "root-selinux", R.string.native_signal_title_root)
        NativeSignalId.ROOT_UID -> item(id, NativeSignalCategory.ROOT, "root-uid", R.string.native_signal_title_root)
        NativeSignalId.ROOT_MAGISK_PROPERTY -> item(id, NativeSignalCategory.ROOT, "root-magisk-property", R.string.native_signal_title_root)
        NativeSignalId.EMULATOR_INDICATORS -> item(id, NativeSignalCategory.EMULATION, "emulator-indicators", R.string.native_signal_title_emulator)
        NativeSignalId.EMULATOR_QEMU_PROPERTY -> item(id, NativeSignalCategory.EMULATION, "emulator-qemu-property", R.string.native_signal_title_emulator)
        NativeSignalId.EMULATOR_QEMU_PIPE -> item(id, NativeSignalCategory.EMULATION, "emulator-qemu-pipe", R.string.native_signal_title_emulator)
        NativeSignalId.EMULATOR_GOLDFISH -> item(id, NativeSignalCategory.EMULATION, "emulator-goldfish", R.string.native_signal_title_emulator)
        NativeSignalId.EMULATOR_QEMU_DRIVER -> item(id, NativeSignalCategory.EMULATION, "emulator-qemu-driver", R.string.native_signal_title_emulator)
        NativeSignalId.EMULATOR_BLUESTACKS -> item(id, NativeSignalCategory.EMULATION, "emulator-bluestacks", R.string.native_signal_title_emulator)
        NativeSignalId.EMULATOR_BUILD -> item(id, NativeSignalCategory.EMULATION, "emulator-build-profile", R.string.native_signal_title_emulator)
        NativeSignalId.ISOLATION_PROFILE -> item(id, NativeSignalCategory.EMULATION, "isolation-profile", R.string.native_signal_title_isolation)
        NativeSignalId.ISOLATION_CLONE -> item(id, NativeSignalCategory.EMULATION, "isolation-clone", R.string.native_signal_title_isolation)
        NativeSignalId.ISOLATION_SECONDARY_USER -> item(id, NativeSignalCategory.EMULATION, "isolation-secondary-user", R.string.native_signal_title_isolation)
        NativeSignalId.ISOLATION_WORK_PROFILE -> item(id, NativeSignalCategory.EMULATION, "isolation-work-profile", R.string.native_signal_title_isolation)
        NativeSignalId.VPN_PROPERTY -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "vpn-property", R.string.vpn_desc_prop)
        NativeSignalId.DNS_PROPERTY -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "dns-property", R.string.vpn_desc_dns)
        NativeSignalId.VPN_FILE -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "vpn-file", R.string.vpn_desc_file)
        NativeSignalId.VPNHIDE -> legacy(id, NativeSignalCategory.HOOKS, "vpnhide", R.string.vpn_desc_vpnhide)
        NativeSignalId.LSPOSED -> legacy(id, NativeSignalCategory.HOOKS, "lsposed", R.string.vpn_desc_lsposed)
        NativeSignalId.HOOK_PROPERTY -> legacy(id, NativeSignalCategory.HOOKS, "hook-property", R.string.vpn_desc_hook)
        NativeSignalId.TCP_VPN_PORT -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "tcp-vpn-port", R.string.vpn_desc_tcp_port)
        NativeSignalId.UDP_VPN_PORT -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "udp-vpn-port", R.string.vpn_desc_udp_port)
        NativeSignalId.INET6_VPN_INTERFACE -> legacy(id, NativeSignalCategory.INTERFACES, "inet6-vpn-interface", R.string.vpn_desc_inet6)
        NativeSignalId.ROUTE_VPN_INTERFACE -> legacy(id, NativeSignalCategory.ROUTES, "route-vpn-interface", R.string.vpn_desc_route)
        NativeSignalId.ARP_VPN_INTERFACE -> legacy(id, NativeSignalCategory.INTERFACES, "arp-vpn-interface", R.string.vpn_desc_arp)
        NativeSignalId.SYSCTL_FORWARDING -> legacy(id, NativeSignalCategory.ROUTES, "sysctl-forwarding", R.string.vpn_desc_forwarding)
        NativeSignalId.SYSCTL_RP_FILTER -> legacy(id, NativeSignalCategory.ROUTES, "sysctl-rp-filter", R.string.vpn_desc_rpfilter)
        NativeSignalId.ESTABLISHED_VPN_SOCKET -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "established-vpn-socket", R.string.vpn_desc_established)
        NativeSignalId.VPN_POLICY_RULES -> legacy(id, NativeSignalCategory.ROUTES, "vpn-policy-rules", R.string.vpn_desc_policy_rules)
        NativeSignalId.VPN_QDISC -> legacy(id, NativeSignalCategory.ROUTES, "vpn-qdisc", R.string.vpn_desc_qdisc)
        NativeSignalId.HIDDEN_MAC_NEIGHBORS -> legacy(id, NativeSignalCategory.INTERFACES, "hidden-mac-neighbors", R.string.vpn_desc_hidden_mac)
        NativeSignalId.TCP_MSS_LOW -> legacy(id, NativeSignalCategory.ROUTES, "tcp-mss-low", R.string.vpn_desc_mss)
        NativeSignalId.SO_BINDTODEVICE -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "so-bindtodevice", R.string.vpn_desc_bindtodevice)
        NativeSignalId.LOOPBACK_PORT_CONFLICT -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "loopback-port-conflict", R.string.vpn_desc_port_conflict)
        NativeSignalId.BPF_MAP_ACCESSIBLE -> legacy(id, NativeSignalCategory.ROUTES, "bpf-map-accessible", R.string.vpn_desc_bpf)
        NativeSignalId.IP_RECVERR -> legacy(id, NativeSignalCategory.VPN_ARTIFACTS, "ip-recverr", R.string.vpn_desc_recverr)
        NativeSignalId.SYSCALL_UNAVAILABLE -> item(id, NativeSignalCategory.GENERAL, "syscall-unavailable", R.string.native_signal_title_unavailable)
        NativeSignalId.SYSFS_VPN_LEAK -> deep(id, NativeSignalCategory.INTERFACES, "sysfs-vpn-leak", R.string.vpn_desc_sysfs_leak)
        NativeSignalId.GETIFADDRS_VPN -> deep(id, NativeSignalCategory.INTERFACES, "getifaddrs-vpn", R.string.vpn_desc_getifaddrs)
        NativeSignalId.SYSCLASSNET_VPN -> deep(id, NativeSignalCategory.INTERFACES, "sysclassnet-vpn", R.string.vpn_desc_sysclassnet)
        NativeSignalId.RTM_GETLINK_VPN -> deep(id, NativeSignalCategory.INTERFACES, "rtm-getlink-vpn", R.string.vpn_desc_rtm_getlink)
        NativeSignalId.PROC_IF_INET6_VPN -> deep(id, NativeSignalCategory.INTERFACES, "proc-if-inet6-vpn", R.string.vpn_desc_proc_if_inet6)
        NativeSignalId.PROC_IPV6_ROUTE_VPN -> deep(id, NativeSignalCategory.ROUTES, "proc-ipv6-route-vpn", R.string.vpn_desc_proc_ipv6_route)
        NativeSignalId.PROC_NET_DEV_VPN -> deep(id, NativeSignalCategory.INTERFACES, "proc-net-dev-vpn", R.string.vpn_desc_proc_net_dev)
        NativeSignalId.IFINDEXNAME_VPN -> deep(id, NativeSignalCategory.INTERFACES, "ifindexname-vpn", R.string.vpn_desc_ifindexname)
        NativeSignalId.VPN_POLICY_RULES_NETLINK -> deep(id, NativeSignalCategory.ROUTES, "vpn-policy-rules-netlink", R.string.vpn_desc_policy_rules_netlink)
        NativeSignalId.FIB_TRIE_DENIED -> deep(id, NativeSignalCategory.ROUTES, "fib-trie-denied", R.string.vpn_desc_fib_trie)
        NativeSignalId.INET_DIAG_DENIED -> deep(id, NativeSignalCategory.VPN_ARTIFACTS, "inet-diag-denied", R.string.vpn_desc_inet_diag)
        NativeSignalId.BINDTODEVICE_LEAK -> deep(id, NativeSignalCategory.VPN_ARTIFACTS, "bindtodevice-leak", R.string.vpn_desc_bindtodevice_leak)
        NativeSignalId.GETSOCKNAME_LEAK -> deep(id, NativeSignalCategory.VPN_ARTIFACTS, "getsockname-leak", R.string.vpn_desc_getsockname)
        NativeSignalId.UDP_PORT_CONFLICT_PHYSICAL -> deep(id, NativeSignalCategory.VPN_ARTIFACTS, "udp-port-conflict-physical", R.string.vpn_desc_udp_port_physical)
        NativeSignalId.DEEP_VPN_QDISC -> deep(id, NativeSignalCategory.ROUTES, "deep-vpn-qdisc", R.string.vpn_desc_qdisc)
        NativeSignalId.DEEP_BPF_MAP_ACCESSIBLE -> deep(id, NativeSignalCategory.ROUTES, "deep-bpf-map-accessible", R.string.vpn_desc_bpf)
        NativeSignalId.ROUTE_COUNT -> deep(id, NativeSignalCategory.ROUTES, "route-count", R.string.vpn_desc_route_count)
        NativeSignalId.TRIM_ORACLE -> deep(id, NativeSignalCategory.ROUTES, "trim-oracle", R.string.vpn_desc_trim_oracle)
        NativeSignalId.PMTU_MSS_COMBINED -> deep(id, NativeSignalCategory.ROUTES, "pmtu-mss-combined", R.string.vpn_desc_pmtu_mss)
        NativeSignalId.UDP_PMTU_OK -> deep(id, NativeSignalCategory.ROUTES, "udp-pmtu-ok", R.string.vpn_desc_udp_pmtu_ok)
        NativeSignalId.UDP_PMTU_FAIL -> deep(id, NativeSignalCategory.ROUTES, "udp-pmtu-fail", R.string.vpn_desc_udp_pmtu_fail)
        NativeSignalId.NORMAL_PMTU -> deep(id, NativeSignalCategory.ROUTES, "normal-pmtu", R.string.vpn_desc_normal_pmtu)
        NativeSignalId.TIMING_ORACLE -> deep(id, NativeSignalCategory.ROUTES, "timing-oracle", R.string.vpn_desc_timing_oracle)
        NativeSignalId.BACKPRESSURE -> deep(id, NativeSignalCategory.ROUTES, "backpressure", R.string.vpn_desc_backpressure)
        NativeSignalId.GSO_FAILED -> deep(id, NativeSignalCategory.ROUTES, "gso-failed", R.string.vpn_desc_gso_failed)
        NativeSignalId.GSO_SEND_FAILED -> deep(id, NativeSignalCategory.ROUTES, "gso-send-failed", R.string.vpn_desc_gso_send_failed)
        NativeSignalId.GSO_OK -> deep(id, NativeSignalCategory.ROUTES, "gso-ok", R.string.vpn_desc_gso_ok)
        NativeSignalId.HW_TIMESTAMP -> deep(id, NativeSignalCategory.ROUTES, "hardware-timestamp", R.string.vpn_desc_hw_timestamp)
        NativeSignalId.TRACEROUTE_DENIED -> deep(id, NativeSignalCategory.ROUTES, "traceroute-denied", R.string.vpn_desc_traceroute)
        NativeSignalId.GENERAL_DIAGNOSTICS -> item(id, NativeSignalCategory.GENERAL, "general-diagnostics", R.string.native_signal_title_general)
        NativeSignalId.UNKNOWN -> item(NativeSignalId.UNKNOWN, NativeSignalCategory.GENERAL, "unknown-signals", R.string.native_signal_title_unknown)
    }

    fun title(context: Context, id: NativeSignalId?): String = context.getString(info(id).titleRes)

    fun articleUrl(context: Context, id: NativeSignalId?): String =
        "$BASE_URL/${localePath(context)}/native/${info(id).slug}/"

    fun nativeIndexUrl(context: Context): String = "$BASE_URL/${localePath(context)}/native/"

    fun ipComparisonUrl(context: Context): String = "$BASE_URL/${localePath(context)}/ip-comparison/"

    fun localePath(context: Context): String {
        val locale = context.resources.configuration.locales[0] ?: Locale.ENGLISH
        return when (locale.language.lowercase(Locale.ROOT)) {
            "ru" -> "ru"
            "fa" -> "fa"
            "zh" -> "zh-CN"
            else -> "en"
        }
    }

    fun fromLegacyVpnKind(kind: String): NativeSignalId = LEGACY_IDS[kind] ?: NativeSignalId.UNKNOWN

    fun fromDeepVpnKind(kind: String): NativeSignalId = DEEP_IDS[kind] ?: NativeSignalId.UNKNOWN

    fun fromRootKind(kind: String): NativeSignalId = ROOT_IDS[kind] ?: NativeSignalId.UNKNOWN

    fun fromEmulatorKind(kind: String): NativeSignalId = EMULATOR_IDS[kind] ?: NativeSignalId.UNKNOWN

    private fun item(id: NativeSignalId?, category: NativeSignalCategory, slug: String, @StringRes titleRes: Int) =
        NativeSignalInfo(id ?: NativeSignalId.UNKNOWN, category, slug, titleRes)

    private fun legacy(id: NativeSignalId?, category: NativeSignalCategory, slug: String, @StringRes titleRes: Int) = item(id, category, slug, titleRes)
    private fun deep(id: NativeSignalId?, category: NativeSignalCategory, slug: String, @StringRes titleRes: Int) = item(id, category, slug, titleRes)

    private val LEGACY_IDS = mapOf(
        "vpn_prop" to NativeSignalId.VPN_PROPERTY,
        "dns_prop" to NativeSignalId.DNS_PROPERTY,
        "vpn_file" to NativeSignalId.VPN_FILE,
        "vpnhide" to NativeSignalId.VPNHIDE,
        "lsposed" to NativeSignalId.LSPOSED,
        "hook_prop" to NativeSignalId.HOOK_PROPERTY,
        "tcp_vpn_port" to NativeSignalId.TCP_VPN_PORT,
        "udp_vpn_port" to NativeSignalId.UDP_VPN_PORT,
        "inet6_vpn_iface" to NativeSignalId.INET6_VPN_INTERFACE,
        "route_vpn_iface" to NativeSignalId.ROUTE_VPN_INTERFACE,
        "arp_vpn_iface" to NativeSignalId.ARP_VPN_INTERFACE,
        "sysctl_forwarding" to NativeSignalId.SYSCTL_FORWARDING,
        "sysctl_rp_filter" to NativeSignalId.SYSCTL_RP_FILTER,
        "established_vpn" to NativeSignalId.ESTABLISHED_VPN_SOCKET,
        "vpn_policy_rules" to NativeSignalId.VPN_POLICY_RULES,
        "vpn_qdisc" to NativeSignalId.VPN_QDISC,
        "hidden_mac_neighbors" to NativeSignalId.HIDDEN_MAC_NEIGHBORS,
        "tcp_mss_low" to NativeSignalId.TCP_MSS_LOW,
        "so_bindtodevice" to NativeSignalId.SO_BINDTODEVICE,
        "loopback_port_conflict" to NativeSignalId.LOOPBACK_PORT_CONFLICT,
        "bpf_map_accessible" to NativeSignalId.BPF_MAP_ACCESSIBLE,
        "ip_recverr" to NativeSignalId.IP_RECVERR,
    )

    private val ROOT_IDS = mapOf(
        "su_binary" to NativeSignalId.ROOT_SU_BINARY,
        "root_prop" to NativeSignalId.ROOT_PROPERTY,
        "root_mgmt" to NativeSignalId.ROOT_MANAGEMENT,
        "system_rw" to NativeSignalId.ROOT_SYSTEM_RW,
        "suspicious_mount" to NativeSignalId.ROOT_SUSPICIOUS_MOUNT,
        "overlay_mount" to NativeSignalId.ROOT_OVERLAY_MOUNT,
        "selinux" to NativeSignalId.ROOT_SELINUX,
        "root_uid" to NativeSignalId.ROOT_UID,
        "magisk_prop" to NativeSignalId.ROOT_MAGISK_PROPERTY,
    )

    private val EMULATOR_IDS = mapOf(
        "qemu_prop" to NativeSignalId.EMULATOR_QEMU_PROPERTY,
        "qemu_pipe" to NativeSignalId.EMULATOR_QEMU_PIPE,
        "goldfish" to NativeSignalId.EMULATOR_GOLDFISH,
        "qemu_driver" to NativeSignalId.EMULATOR_QEMU_DRIVER,
        "bluestacks" to NativeSignalId.EMULATOR_BLUESTACKS,
    )

    private val DEEP_IDS = mapOf(
        "sysfs_vpn_leak" to NativeSignalId.SYSFS_VPN_LEAK,
        "getifaddrs_vpn" to NativeSignalId.GETIFADDRS_VPN,
        "sysclassnet_vpn" to NativeSignalId.SYSCLASSNET_VPN,
        "rtm_getlink_vpn" to NativeSignalId.RTM_GETLINK_VPN,
        "proc_if_inet6_vpn" to NativeSignalId.PROC_IF_INET6_VPN,
        "proc_ipv6_route_vpn" to NativeSignalId.PROC_IPV6_ROUTE_VPN,
        "proc_net_dev_vpn" to NativeSignalId.PROC_NET_DEV_VPN,
        "ifindexname_vpn" to NativeSignalId.IFINDEXNAME_VPN,
        "vpn_policy_rules_netlink" to NativeSignalId.VPN_POLICY_RULES_NETLINK,
        "fib_trie_denied" to NativeSignalId.FIB_TRIE_DENIED,
        "inet_diag_denied" to NativeSignalId.INET_DIAG_DENIED,
        "bindtodevice_leak" to NativeSignalId.BINDTODEVICE_LEAK,
        "getsockname_leak" to NativeSignalId.GETSOCKNAME_LEAK,
        "udp_port_conflict_physical" to NativeSignalId.UDP_PORT_CONFLICT_PHYSICAL,
        "vpn_qdisc" to NativeSignalId.DEEP_VPN_QDISC,
        "bpf_map_accessible" to NativeSignalId.DEEP_BPF_MAP_ACCESSIBLE,
        "route_count" to NativeSignalId.ROUTE_COUNT,
        "trim_oracle" to NativeSignalId.TRIM_ORACLE,
        "pmtu_mss_combined" to NativeSignalId.PMTU_MSS_COMBINED,
        "udp_pmtu_ok" to NativeSignalId.UDP_PMTU_OK,
        "udp_pmtu_fail" to NativeSignalId.UDP_PMTU_FAIL,
        "normal_pmtu" to NativeSignalId.NORMAL_PMTU,
        "timing_oracle" to NativeSignalId.TIMING_ORACLE,
        "backpressure" to NativeSignalId.BACKPRESSURE,
        "gso_failed" to NativeSignalId.GSO_FAILED,
        "gso_send_failed" to NativeSignalId.GSO_SEND_FAILED,
        "gso_ok" to NativeSignalId.GSO_OK,
        "hw_timestamp" to NativeSignalId.HW_TIMESTAMP,
        "traceroute_denied" to NativeSignalId.TRACEROUTE_DENIED,
    )
}
