package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.BetaProbeRowParser
import com.notcvnt.rknhardering.probe.NativeSignsBridge
import com.notcvnt.rknhardering.probe.ParsedBetaProbeRow
import com.notcvnt.rknhardering.probe.privileged.PrivilegedProbeKind
import com.notcvnt.rknhardering.probe.privileged.PrivilegedProbeResult

internal object KernelBetaChecker {
    internal data class WireGuardCounterSample(
        val row: ParsedBetaProbeRow,
        val rxBytes: Long,
        val txBytes: Long,
    )

    internal data class OvpnCounterSample(
        val row: ParsedBetaProbeRow,
        val rxBytes: Long,
        val txBytes: Long,
    )

    fun checkTunOnly(
        context: Context,
        epochId: String,
        at: Long,
        executionContext: ScanExecutionContext,
    ): BetaObservation {
        NativeSignsBridge.initIfNeeded()
        if (!NativeSignsBridge.isLibraryLoaded()) {
            return tunObservation(context, unavailableRow("tun_fd"), epochId, at)
        }
        executionContext.throwIfCancelled()
        return tunObservation(
            context,
            parse(NativeSignsBridge.betaTunFdProbe(executionContext.cancellationSignal), "tun_fd"),
            epochId,
            at,
        )
    }

    fun privilegedObservations(
        context: Context,
        results: Map<PrivilegedProbeKind, PrivilegedProbeResult>,
        epochId: String,
        at: Long,
    ): List<BetaObservation> = buildList {
        results[PrivilegedProbeKind.WIREGUARD]?.let {
            add(wireGuardObservation(context, privilegedRow(it, "wireguard_genl"), epochId, at))
        }
        results[PrivilegedProbeKind.OVPN]?.let {
            add(ovpnObservation(context, privilegedRow(it, "ovpn_genl"), epochId, at))
        }
        results[PrivilegedProbeKind.XFRM]?.let {
            add(xfrmObservation(context, privilegedRow(it, "xfrm"), epochId, at))
        }
        results[PrivilegedProbeKind.BPF_NETFILTER]?.let { result ->
            add(contextObservation(context, privilegedRow(result, "cgroup_bpf"), "beta.cgroup_bpf", epochId, at))
            add(contextObservation(context, privilegedRow(result, "bpf_netd"), "beta.bpf_netd", epochId, at))
            add(contextObservation(context, privilegedRow(result, "netfilter_path"), "beta.netfilter_path", epochId, at))
        }
    }

    fun wireGuardSample(result: PrivilegedProbeResult): WireGuardCounterSample {
        val row = privilegedRow(result, "wireguard_genl")
        return WireGuardCounterSample(row, row.fields.long("rx_bytes"), row.fields.long("tx_bytes"))
    }

    fun ovpnSample(result: PrivilegedProbeResult): OvpnCounterSample {
        val row = privilegedRow(result, "ovpn_genl")
        return OvpnCounterSample(row, row.fields.long("rx_bytes"), row.fields.long("tx_bytes"))
    }

    fun wireGuardDeltaObservation(
        context: Context,
        before: WireGuardCounterSample,
        after: WireGuardCounterSample,
        canaryTransferred: Boolean,
        expectedInterfaceIndex: Int?,
        epochId: String,
        at: Long,
    ): BetaObservation {
        val interfaceMatches = expectedInterfaceIndex != null &&
            after.row.fields["interface_indexes"]?.split(',')?.any {
                it.toIntOrNull() == expectedInterfaceIndex
            } == true
        val delta = canaryTransferred && interfaceMatches &&
            after.row.availability == ProbeAvailability.AVAILABLE &&
            before.row.availability == ProbeAvailability.AVAILABLE &&
            (after.rxBytes > before.rxBytes || after.txBytes > before.txBytes)
        val fields = after.row.fields + ("causal_counter_delta" to delta.toString())
        return wireGuardObservation(context, after.row.copy(fields = fields), epochId, at)
    }

    fun ovpnDeltaObservation(
        context: Context,
        before: OvpnCounterSample,
        after: OvpnCounterSample,
        canaryTransferred: Boolean,
        expectedInterfaceIndex: Int?,
        epochId: String,
        at: Long,
    ): BetaObservation {
        val interfaceMatches = expectedInterfaceIndex != null &&
            after.row.fields["interface_indexes"]?.split(',')?.any {
                it.toIntOrNull() == expectedInterfaceIndex
            } == true
        val delta = canaryTransferred && interfaceMatches &&
            after.row.availability == ProbeAvailability.AVAILABLE &&
            before.row.availability == ProbeAvailability.AVAILABLE &&
            (after.rxBytes > before.rxBytes || after.txBytes > before.txBytes)
        return ovpnObservation(
            context,
            after.row.copy(fields = after.row.fields + ("causal_counter_delta" to delta.toString())),
            epochId,
            at,
        )
    }

    internal fun wireGuardObservation(context: Context, row: ParsedBetaProbeRow, epochId: String, at: Long): BetaObservation {
        val activePeers = row.fields.long("peers_with_handshake_or_counters")
        return observation(
            context,
            row,
            "beta.wireguard_genl",
            EvidenceSource.BETA_WIREGUARD_GENL,
            "kernel_vpn",
            DetectionDomain.VPN_OR_PROXY,
            positive = row.fields["causal_counter_delta"] == "true" && activePeers > 0,
            clean = row.fields.long("devices") == 0L || row.fields.long("peers") == 0L,
            confidence = if (row.fields["causal_counter_delta"] == "true") EvidenceConfidence.HIGH else EvidenceConfidence.LOW,
            epochId,
            at,
            suppressions = if (row.fields["causal_counter_delta"] == "true") {
                listOf(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS)
            } else emptyList(),
        )
    }

    internal fun ovpnObservation(context: Context, row: ParsedBetaProbeRow, epochId: String, at: Long): BetaObservation {
        val peers = row.fields.long("peers")
        return observation(
            context, row, "beta.ovpn_genl", EvidenceSource.BETA_OVPN_GENL, "kernel_vpn",
            DetectionDomain.VPN_OR_PROXY, row.fields["causal_counter_delta"] == "true" && peers > 0,
            row.fields.long("interfaces") == 0L,
            if (row.fields["causal_counter_delta"] == "true") EvidenceConfidence.HIGH else EvidenceConfidence.LOW, epochId, at,
            suppressions = if (row.fields["causal_counter_delta"] == "true") {
                listOf(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS)
            } else emptyList(),
        )
    }

    internal fun xfrmObservation(context: Context, row: ParsedBetaProbeRow, epochId: String, at: Long): BetaObservation {
        val classification = row.fields["classification"]
        val positive = classification == "unknown_ipsec" && row.fields["causal_counter_delta"] == "true"
        return observation(
            context, row, "beta.xfrm", EvidenceSource.BETA_XFRM, "kernel_ipsec",
            DetectionDomain.VPN_OR_PROXY, positive, classification == "none",
            if (positive) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW, epochId, at,
            suppressions = if (classification == "system_ims") listOf(BetaSuppressionRuleId.IMS_OR_EIMS_CONTEXT) else emptyList(),
        )
    }

    internal fun tunObservation(context: Context, row: ParsedBetaProbeRow, epochId: String, at: Long): BetaObservation {
        val count = row.fields.long("tun_fds")
        return observation(
            context, row, "beta.tun_fd", EvidenceSource.BETA_TUN_FD, "process_fd",
            DetectionDomain.VPN_OR_PROXY, count > 0, row.fields.long("inspected") > 0 && count == 0L,
            if (count > 0) EvidenceConfidence.HIGH else EvidenceConfidence.LOW, epochId, at,
        )
    }

    private fun contextObservation(
        context: Context,
        row: ParsedBetaProbeRow,
        checkId: String,
        epochId: String,
        at: Long,
    ): BetaObservation = observation(
        context, row, checkId, EvidenceSource.BETA_BPF_NETFILTER, "packet_policy",
        DetectionDomain.NETWORK_PATH_DIVERGENCE, positive = false,
        clean = row.availability == ProbeAvailability.AVAILABLE,
        confidence = EvidenceConfidence.LOW, epochId = epochId, at = at,
    )

    private fun observation(
        context: Context,
        row: ParsedBetaProbeRow,
        checkId: String,
        source: EvidenceSource,
        group: String,
        domain: DetectionDomain,
        positive: Boolean,
        clean: Boolean,
        confidence: EvidenceConfidence,
        epochId: String,
        at: Long,
        suppressions: List<BetaSuppressionRuleId> = emptyList(),
    ) = BetaObservation(
        checkId = checkId,
        source = source,
        availability = row.availability,
        polarity = when {
            row.availability != ProbeAvailability.AVAILABLE -> ObservationPolarity.INCONCLUSIVE
            positive -> ObservationPolarity.POSITIVE
            clean -> ObservationPolarity.AUTHORITATIVE_NEGATIVE
            else -> ObservationPolarity.INCONCLUSIVE
        },
        authority = ObservationAuthority.KERNEL_QUERY,
        confidence = confidence,
        independenceGroup = group,
        detectionDomain = domain,
        facts = row.fields.filter { (k, _) ->
            val kl = k.lowercase()
            !kl.contains("cookie") && !kl.contains("inode") && !kl.contains("interface") && !kl.contains("ifname")
        } + ("summary" to context.getString(summaryResource(checkId, positive))),
        suppressions = suppressions,
        observedAtElapsedMs = at,
        networkEpochId = epochId,
    )

    private fun summaryResource(checkId: String, positive: Boolean): Int = when (checkId) {
        "beta.wireguard_genl" -> if (positive) R.string.beta_kernel_wireguard_active else R.string.beta_kernel_wireguard_checked
        "beta.ovpn_genl" -> if (positive) R.string.beta_kernel_ovpn_active else R.string.beta_kernel_ovpn_checked
        "beta.xfrm" -> if (positive) R.string.beta_kernel_xfrm_active else R.string.beta_kernel_xfrm_checked
        "beta.tun_fd" -> if (positive) R.string.beta_kernel_tun_active else R.string.beta_kernel_tun_checked
        else -> R.string.beta_kernel_policy_checked
    }

    private fun parse(rows: Array<String>, checkId: String) = BetaProbeRowParser.parse(rows, checkId)

    private fun privilegedRow(result: PrivilegedProbeResult, checkId: String): ParsedBetaProbeRow = when (result) {
        is PrivilegedProbeResult.Available -> parse(result.rows, checkId)
        is PrivilegedProbeResult.PermissionDenied ->
            ParsedBetaProbeRow(checkId, ProbeAvailability.PERMISSION_DENIED, emptyMap())
        is PrivilegedProbeResult.MalformedResponse ->
            ParsedBetaProbeRow(checkId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
        is PrivilegedProbeResult.Unavailable -> unavailableRow(checkId)
        PrivilegedProbeResult.Disabled -> ParsedBetaProbeRow(checkId, ProbeAvailability.SKIPPED, emptyMap())
    }
    private fun Map<String, String>.long(key: String): Long = this[key]?.toLongOrNull() ?: 0L

    private fun unavailableRow(checkId: String) =
        ParsedBetaProbeRow(checkId, ProbeAvailability.UNAVAILABLE, emptyMap())
}
