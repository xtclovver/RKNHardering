package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.probe.NativeSignsBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Deep VPN detector ported from the reference [dev.soranerai.vpndetector] APK.
 * Lives in its own UI category, separate from the legacy [NativeSignsChecker].
 * Every native line is prefixed with "vdet|" and has the shape "vdet|<kind>|<detail>".
 *
 * Checks are grouped into sub-categories so the UI shows them as:
 *  - Direct signs      (interface / route / sysfs leaks)
 *  - Network signs     (sockets / policy rules / BPF)
 *  - Indirect signs    (MTU / MSS / GSO / timing / backpressure)
 *  - Environment       (traceroute / hw timestamp probes)
 */
object VpnNativeDetectorChecker {

    private val DIRECT_KINDS = setOf(
        "sysfs_vpn_leak", "getifaddrs_vpn", "sysclassnet_vpn", "rtm_getlink_vpn",
        "proc_if_inet6_vpn", "proc_ipv6_route_vpn", "proc_net_dev_vpn",
        "ifindexname_vpn", "vpn_policy_rules_netlink", "split_tunnel_uid",
    )

    private val NETWORK_KINDS = setOf(
        "fib_trie_denied", "inet_diag_denied", "bindtodevice_leak",
        "getsockname_leak", "udp_port_conflict_physical", "vpn_qdisc",
        "bpf_map_accessible", "route_count", "trim_oracle",
    )

    private val INDIRECT_KINDS = setOf(
        "pmtu_mss_combined", "udp_pmtu_ok", "udp_pmtu_fail", "normal_pmtu",
        "timing_oracle", "backpressure", "gso_failed", "gso_send_failed",
        "gso_ok", "hw_timestamp",
    )

    private val ENV_KINDS = setOf(
        "traceroute_denied",
    )

    private val HIGH_CONFIDENCE = setOf(
        "sysfs_vpn_leak", "getifaddrs_vpn", "sysclassnet_vpn", "rtm_getlink_vpn",
        "proc_if_inet6_vpn", "proc_ipv6_route_vpn", "proc_net_dev_vpn",
        "ifindexname_vpn", "vpn_policy_rules_netlink", "split_tunnel_uid",
        "bindtodevice_leak", "getsockname_leak", "udp_port_conflict_physical",
        "gso_failed", "gso_send_failed",
    )

    suspend fun check(context: Context): CategoryResult = withContext(Dispatchers.IO) {
        NativeSignsBridge.initIfNeeded()
        if (!NativeSignsBridge.isLibraryLoaded()) {
            val loadError = NativeSignsBridge.lastLoadErrorMessage()
            val description = if (loadError != null) {
                context.getString(R.string.checker_vpn_detector_unavailable_with_reason, loadError)
            } else {
                context.getString(R.string.checker_vpn_detector_unavailable)
            }
            return@withContext CategoryResult(
                name = context.getString(R.string.checker_vpn_detector_category_name),
                detected = false,
                findings = listOf(Finding(description = description, isInformational = true)),
                needsReview = false,
                evidence = emptyList(),
            )
        }

        val rows = runCatching { NativeSignsBridge.detectVpnDetector() }.getOrDefault(emptyArray())
        val parsed = rows.mapNotNull { parseRow(it) }

        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<com.notcvnt.rknhardering.model.EvidenceItem>()
        var detected = false
        var needsReview = false

        val groups = listOf(
            Triple(context.getString(R.string.vpn_detector_group_direct), DIRECT_KINDS, EvidenceSource.NATIVE_INTERFACE),
            Triple(context.getString(R.string.vpn_detector_group_network), NETWORK_KINDS, EvidenceSource.NATIVE_SOCKET),
            Triple(context.getString(R.string.vpn_detector_group_indirect), INDIRECT_KINDS, EvidenceSource.NATIVE_ROUTE),
            Triple(context.getString(R.string.vpn_detector_group_env), ENV_KINDS, EvidenceSource.NATIVE_INTERFACE),
        )

        for ((groupTitle, kinds, source) in groups) {
            val items = parsed.filter { it.kind in kinds }
            if (items.isEmpty()) continue
            findings += Finding(
                description = context.getString(R.string.vpn_detector_section, groupTitle),
                isInformational = true,
            )
            for (item in items) {
                val isHigh = item.kind in HIGH_CONFIDENCE
                val confidence = if (isHigh) EvidenceConfidence.HIGH else EvidenceConfidence.MEDIUM
                findings += Finding(
                    description = describe(context, item.kind, item.detail),
                    detected = isHigh,
                    needsReview = !isHigh,
                    source = source,
                    confidence = confidence,
                )
                evidence += com.notcvnt.rknhardering.model.EvidenceItem(
                    source = source,
                    detected = true,
                    confidence = confidence,
                    description = describe(context, item.kind, item.detail),
                )
                detected = detected || isHigh
                needsReview = needsReview || !isHigh
            }
        }

        if (findings.isEmpty()) {
            findings += Finding(
                description = context.getString(R.string.checker_vpn_detector_no_anomalies),
                isInformational = true,
            )
        }

        CategoryResult(
            name = context.getString(R.string.checker_vpn_detector_category_name),
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    private data class ParsedRow(val kind: String, val detail: String)

    private fun parseRow(row: String): ParsedRow? {
        if (!row.startsWith("vdet|")) return null
        val body = row.removePrefix("vdet|")
        val sep = body.indexOf('|')
        if (sep <= 0) return null
        val kind = body.substring(0, sep)
        val detail = body.substring(sep + 1).takeIf { it.isNotBlank() } ?: return null
        return ParsedRow(kind, detail)
    }

    private fun describe(context: Context, kind: String, detail: String): String {
        val resId = when (kind) {
            "sysfs_vpn_leak" -> R.string.vpn_desc_sysfs_leak
            "getifaddrs_vpn" -> R.string.vpn_desc_getifaddrs
            "sysclassnet_vpn" -> R.string.vpn_desc_sysclassnet
            "rtm_getlink_vpn" -> R.string.vpn_desc_rtm_getlink
            "proc_if_inet6_vpn" -> R.string.vpn_desc_proc_if_inet6
            "proc_ipv6_route_vpn" -> R.string.vpn_desc_proc_ipv6_route
            "proc_net_dev_vpn" -> R.string.vpn_desc_proc_net_dev
            "ifindexname_vpn" -> R.string.vpn_desc_ifindexname
            "vpn_policy_rules_netlink" -> R.string.vpn_desc_policy_rules_netlink
            "split_tunnel_uid" -> R.string.vpn_desc_split_tunnel
            "fib_trie_denied" -> R.string.vpn_desc_fib_trie
            "inet_diag_denied" -> R.string.vpn_desc_inet_diag
            "bindtodevice_leak" -> R.string.vpn_desc_bindtodevice_leak
            "getsockname_leak" -> R.string.vpn_desc_getsockname
            "udp_port_conflict_physical" -> R.string.vpn_desc_udp_port_physical
            "vpn_qdisc" -> R.string.vpn_desc_qdisc
            "bpf_map_accessible" -> R.string.vpn_desc_bpf
            "route_count" -> R.string.vpn_desc_route_count
            "trim_oracle" -> R.string.vpn_desc_trim_oracle
            "pmtu_mss_combined" -> R.string.vpn_desc_pmtu_mss
            "udp_pmtu_ok" -> R.string.vpn_desc_udp_pmtu_ok
            "udp_pmtu_fail" -> R.string.vpn_desc_udp_pmtu_fail
            "normal_pmtu" -> R.string.vpn_desc_normal_pmtu
            "timing_oracle" -> R.string.vpn_desc_timing_oracle
            "backpressure" -> R.string.vpn_desc_backpressure
            "gso_failed" -> R.string.vpn_desc_gso_failed
            "gso_send_failed" -> R.string.vpn_desc_gso_send_failed
            "gso_ok" -> R.string.vpn_desc_gso_ok
            "hw_timestamp" -> R.string.vpn_desc_hw_timestamp
            "traceroute_denied" -> R.string.vpn_desc_traceroute
            else -> null
        }
        return if (resId != null) {
            "$detail — ${context.getString(resId)}"
        } else {
            "$kind: $detail"
        }
    }
}
