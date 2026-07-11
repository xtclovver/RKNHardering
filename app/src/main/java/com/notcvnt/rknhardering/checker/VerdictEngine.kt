package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VerdictDecision
import com.notcvnt.rknhardering.model.VerdictParticipant
import com.notcvnt.rknhardering.model.VerdictRuleCode
import android.util.Log

object VerdictEngine {
    private const val TAG = "VerdictEngine"

    private val HARD_DETECT_BYPASS = setOf(
        EvidenceSource.SPLIT_TUNNEL_BYPASS,
        EvidenceSource.PROXY_AUTH_BYPASS,
        EvidenceSource.XRAY_API,
        EvidenceSource.CLASH_API,
        EvidenceSource.VPN_GATEWAY_LEAK,
        EvidenceSource.VPN_NETWORK_BINDING,
    )

    private val MATRIX_DIRECT_SOURCES = setOf(
        EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
        EvidenceSource.SYSTEM_PROXY,
    )

    private val MATRIX_INDIRECT_SOURCES = setOf(
        EvidenceSource.INDIRECT_NETWORK_CAPABILITIES,
        EvidenceSource.ACTIVE_VPN,
        EvidenceSource.NETWORK_INTERFACE,
        EvidenceSource.ROUTING,
        EvidenceSource.DNS,
        EvidenceSource.PROXY_TECHNICAL_SIGNAL,
        EvidenceSource.IPTABLES_RULES,
        EvidenceSource.MITM_PROXY_CERT,
        EvidenceSource.NATIVE_INTERFACE,
        EvidenceSource.NATIVE_ROUTE,
        EvidenceSource.NATIVE_JVM_MISMATCH,
    )

    private val NATIVE_REVIEW_SOURCES = setOf(
        EvidenceSource.NATIVE_HOST_ROUTE,
        EvidenceSource.NATIVE_HOOK_MARKERS,
        EvidenceSource.NATIVE_LIBRARY_INTEGRITY,
        EvidenceSource.NATIVE_EMULATOR,
        EvidenceSource.SANDBOX_ISOLATION,
    )

    fun evaluate(
        geoIp: CategoryResult,
        directSigns: CategoryResult,
        indirectSigns: CategoryResult,
        locationSignals: CategoryResult,
        bypassResult: BypassResult,
        ipConsensus: IpConsensusResult,
        nativeSigns: CategoryResult = CategoryResult(name = "", detected = false, findings = emptyList()),
        icmpSpoofing: CategoryResult = CategoryResult(name = "", detected = false, findings = emptyList()),
        geoCheckAvailable: Boolean = true,
    ): Verdict = evaluateDetailed(
        geoIp = geoIp,
        directSigns = directSigns,
        indirectSigns = indirectSigns,
        locationSignals = locationSignals,
        bypassResult = bypassResult,
        ipConsensus = ipConsensus,
        nativeSigns = nativeSigns,
        icmpSpoofing = icmpSpoofing,
        geoCheckAvailable = geoCheckAvailable,
    ).verdict

    fun evaluateDetailed(
        geoIp: CategoryResult,
        directSigns: CategoryResult,
        indirectSigns: CategoryResult,
        locationSignals: CategoryResult,
        bypassResult: BypassResult,
        ipConsensus: IpConsensusResult,
        nativeSigns: CategoryResult = CategoryResult(name = "", detected = false, findings = emptyList()),
        icmpSpoofing: CategoryResult = CategoryResult(name = "", detected = false, findings = emptyList()),
        geoCheckAvailable: Boolean = true,
    ): VerdictDecision {
        return try {
            evaluateDetailedInternal(
                geoIp, directSigns, indirectSigns, locationSignals,
                bypassResult, ipConsensus, nativeSigns, icmpSpoofing, geoCheckAvailable,
            )
        } catch (e: Exception) {
            Log.e(TAG, "evaluateDetailed failed", e)
            decision(
                Verdict.NEEDS_REVIEW,
                VerdictRuleCode.R5_MATRIX_DEFAULT,
                participant("evaluate_detailed_error", setOf(EvidenceSource.VERDICT_ENGINE)),
            )
        }
    }

    private fun evaluateDetailedInternal(
        geoIp: CategoryResult,
        directSigns: CategoryResult,
        indirectSigns: CategoryResult,
        locationSignals: CategoryResult,
        bypassResult: BypassResult,
        ipConsensus: IpConsensusResult,
        nativeSigns: CategoryResult,
        icmpSpoofing: CategoryResult,
        geoCheckAvailable: Boolean = true,
    ): VerdictDecision {
        // R1
        val hardBypassSources = bypassResult.evidence
            .filter { it.detected && it.source in HARD_DETECT_BYPASS }
            .mapTo(linkedSetOf()) { it.source }
        if (hardBypassSources.isNotEmpty()) {
            return decision(
                Verdict.DETECTED,
                VerdictRuleCode.R1_HARD_BYPASS,
                participant("hard_bypass", hardBypassSources),
            )
        }

        val geoAxis = ipConsensus.foreignIps.isNotEmpty() ||
            ipConsensus.geoCountryMismatch ||
            ipConsensus.warpLikeIndicator
        // R3
        if (ipConsensus.probeTargetDivergence && geoAxis) {
            return decision(
                Verdict.DETECTED,
                VerdictRuleCode.R3_PROBE_TARGET_DIVERGENCE,
                participant("probe_target_divergence"),
                participant("geo_axis"),
            )
        }
        if (ipConsensus.probeTargetDirectDivergence && geoAxis) {
            return decision(
                Verdict.DETECTED,
                VerdictRuleCode.R3_PROBE_TARGET_DIRECT_DIVERGENCE,
                participant("probe_target_direct_divergence"),
                participant("geo_axis"),
            )
        }
        if (ipConsensus.crossChannelMismatch && geoAxis) {
            return decision(
                Verdict.DETECTED,
                VerdictRuleCode.R3_CROSS_CHANNEL_MISMATCH,
                participant("cross_channel_mismatch"),
                participant("geo_axis"),
            )
        }

        // R4
        val locationConfirmsRussia = locationSignals.findings.any {
            it.description.contains("network_mcc_ru:true") ||
                it.description.contains("cell_country_ru:true") ||
                it.description.contains("location_country_ru:true")
        }
        val homeRoutedRoaming = locationSignals.locationFacts?.homeRoutedRoaming == true
        val geo = geoIp.geoFacts
        // Home-routed roaming: foreign SIM on a Russian visited network
        // legitimately exits via the SIM's home country. Treat the resulting
        // geo mismatch as expected and never auto-detect bypass on geo alone.
        val expectedRoamingExit = geo?.expectedRoamingExit == true || homeRoutedRoaming
        val geoAxisAvailable = geoCheckAvailable && geo?.fetchError != true
        val anyOtherSignal = directSigns.evidence.any { it.detected } ||
            indirectSigns.evidence.any { it.detected } ||
            ipConsensus.crossChannelMismatch ||
            ipConsensus.probeTargetDivergence ||
            ipConsensus.probeTargetDirectDivergence
        if (locationConfirmsRussia && geo?.outsideRu == true && !expectedRoamingExit) {
            return decision(
                Verdict.DETECTED,
                VerdictRuleCode.R4_LOCATION_GEO_CONFLICT,
                participant("location_confirms_russia", setOf(EvidenceSource.LOCATION_SIGNALS)),
                participant("geo_outside_russia", setOf(EvidenceSource.GEO_IP)),
            )
        }
        if (locationConfirmsRussia &&
            (geo?.hosting == true || geo?.proxyDb == true) &&
            geo?.outsideRu != true &&
            !anyOtherSignal
        ) {
            return decision(
                Verdict.NEEDS_REVIEW,
                VerdictRuleCode.R4_HOSTING_REVIEW,
                participant("location_confirms_russia", setOf(EvidenceSource.LOCATION_SIGNALS)),
                participant("hosting_or_proxy_database", setOf(EvidenceSource.GEO_IP)),
            )
        }

        val whitelistEntry = geo?.let(CorporateVpnWhitelist::match)
        val whitelisted = whitelistEntry != null

        // R5 — 3-bit matrix (geo x direct x indirect)
        val geoHit = geo?.outsideRu == true && !expectedRoamingExit && !whitelisted
        val directHit = directSigns.evidence.any { it.detected && it.source in MATRIX_DIRECT_SOURCES }
        val indirectHit = indirectSigns.evidence.any { it.detected && it.source in MATRIX_INDIRECT_SOURCES } ||
            nativeSigns.evidence.any {
                it.detected && (
                    it.source in MATRIX_INDIRECT_SOURCES ||
                        (it.source == EvidenceSource.NATIVE_SOCKET && it.confidence == EvidenceConfidence.HIGH)
                    )
            }
        val matrix = when {
            !geoHit && !directHit && !indirectHit -> Verdict.NOT_DETECTED
            !geoHit && directHit && !indirectHit -> Verdict.NOT_DETECTED
            !geoHit && !directHit && indirectHit -> Verdict.NOT_DETECTED
            geoHit && !directHit && !indirectHit -> Verdict.NEEDS_REVIEW
            !geoHit && directHit && indirectHit -> Verdict.NEEDS_REVIEW
            geoHit && directHit && !indirectHit -> Verdict.DETECTED
            geoHit && !directHit && indirectHit -> Verdict.DETECTED
            geoHit && directHit && indirectHit -> Verdict.DETECTED
            else -> Verdict.NOT_DETECTED
        }

        // R6 — needs-review fallbacks
        val hasActionableCallTransportLeak = indirectSigns.callTransportLeaks.any {
            it.status == CallTransportStatus.NEEDS_REVIEW &&
                it.networkPath != CallTransportNetworkPath.LOCAL_PROXY
        }
        val nativeReviewHit = nativeSigns.evidence.any {
            it.detected && (
                it.source in NATIVE_REVIEW_SOURCES ||
                    (it.source == EvidenceSource.NATIVE_SOCKET && it.confidence == EvidenceConfidence.HIGH)
                )
        }
        val tunProbeReview = directSigns.evidence.any {
            it.source == EvidenceSource.TUN_ACTIVE_PROBE && !it.detected
        }
        val locationSignalHit = locationSignals.detected && !expectedRoamingExit
        if (matrix == Verdict.NOT_DETECTED && (
                bypassResult.needsReview ||
                    directSigns.needsReview ||
                    indirectSigns.needsReview ||
                    locationSignalHit ||
                    hasActionableCallTransportLeak ||
                    icmpSpoofing.needsReview ||
                    nativeReviewHit ||
                    ipConsensus.needsReview ||
                    ipConsensus.channelConflict.isNotEmpty() ||
                    ipConsensus.probeTargetDivergence ||
                    tunProbeReview
                )
        ) {
            val participants = buildList {
                if (bypassResult.needsReview) add(participant("bypass_needs_review", bypassResult.evidence.mapTo(linkedSetOf()) { it.source }))
                if (directSigns.needsReview) add(participant("direct_needs_review", directSigns.evidence.mapTo(linkedSetOf()) { it.source }))
                if (indirectSigns.needsReview) add(participant("indirect_needs_review", indirectSigns.evidence.mapTo(linkedSetOf()) { it.source }))
                if (locationSignalHit) add(participant("location_signal", setOf(EvidenceSource.LOCATION_SIGNALS)))
                if (hasActionableCallTransportLeak) add(participant("call_transport_leak"))
                if (icmpSpoofing.needsReview) add(participant("icmp_needs_review", setOf(EvidenceSource.ICMP_SPOOFING)))
                if (nativeReviewHit) add(participant("native_needs_review", nativeSigns.evidence.mapTo(linkedSetOf()) { it.source }))
                if (ipConsensus.needsReview) add(participant("ip_consensus_needs_review"))
                if (ipConsensus.channelConflict.isNotEmpty()) add(participant("ip_channel_conflict"))
                if (ipConsensus.probeTargetDivergence) add(participant("probe_target_divergence"))
                if (tunProbeReview) add(participant("tun_probe_review", setOf(EvidenceSource.TUN_ACTIVE_PROBE)))
            }
            return decision(Verdict.NEEDS_REVIEW, VerdictRuleCode.R6_FALLBACK, *participants.toTypedArray())
        }

        val matrixSources = buildSet {
            if (directHit) addAll(directSigns.evidence.filter { it.detected && it.source in MATRIX_DIRECT_SOURCES }.map { it.source })
            if (indirectHit) {
                addAll(indirectSigns.evidence.filter { it.detected && it.source in MATRIX_INDIRECT_SOURCES }.map { it.source })
                addAll(nativeSigns.evidence.filter { it.detected }.map { it.source })
            }
            if (geoHit) add(EvidenceSource.GEO_IP)
        }
        val r5Participants = mutableListOf(
            participant("geo=$geoHit"),
            participant("direct=$directHit"),
            participant("indirect=$indirectHit", matrixSources),
            participant("geo_available=$geoAxisAvailable"),
            participant("expected_roaming_exit=$expectedRoamingExit"),
        )
        if (whitelisted) {
            r5Participants.add(
                participant("corporate_vpn_whitelisted=${whitelistEntry?.name}", setOf(EvidenceSource.CORPORATE_VPN_WHITELIST)),
            )
        }
        return decision(matrix, VerdictRuleCode.R5_MATRIX, *r5Participants.toTypedArray())
    }

    private fun participant(
        factor: String,
        sources: Set<EvidenceSource> = emptySet(),
    ): VerdictParticipant = VerdictParticipant(factor = factor, evidenceSources = sources)

    private fun decision(
        verdict: Verdict,
        rule: VerdictRuleCode,
        vararg participants: VerdictParticipant,
    ): VerdictDecision = VerdictDecision(
        verdict = verdict,
        rule = rule,
        participants = participants.toList(),
    )
}
