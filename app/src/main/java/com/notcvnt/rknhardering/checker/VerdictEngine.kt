package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.Verdict

object VerdictEngine {

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
        EvidenceSource.NATIVE_INTERFACE,
        EvidenceSource.NATIVE_ROUTE,
        EvidenceSource.NATIVE_JVM_MISMATCH,
    )

    private val NATIVE_REVIEW_SOURCES = setOf(
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
    ): Verdict {
        // R1
        if (bypassResult.evidence.any { it.detected && it.source in HARD_DETECT_BYPASS }) {
            return Verdict.DETECTED
        }

        val geoAxis = ipConsensus.foreignIps.isNotEmpty() ||
            ipConsensus.geoCountryMismatch ||
            ipConsensus.warpLikeIndicator
        // R3
        if (ipConsensus.probeTargetDivergence && geoAxis) {
            return Verdict.DETECTED
        }
        if (ipConsensus.probeTargetDirectDivergence && geoAxis) {
            return Verdict.DETECTED
        }
        if (ipConsensus.crossChannelMismatch && geoAxis) {
            return Verdict.DETECTED
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
            return Verdict.DETECTED
        }
        if (locationConfirmsRussia &&
            (geo?.hosting == true || geo?.proxyDb == true) &&
            geo.outsideRu != true &&
            !anyOtherSignal
        ) {
            return Verdict.NEEDS_REVIEW
        }

        // R5 — 3-bit matrix (geo x direct x indirect)
        val geoHit = geo?.outsideRu == true && !expectedRoamingExit
        val directHit = directSigns.evidence.any { it.detected && it.source in MATRIX_DIRECT_SOURCES }
        val indirectHit = indirectSigns.evidence.any { it.detected && it.source in MATRIX_INDIRECT_SOURCES } ||
            nativeSigns.evidence.any { it.detected && it.source in MATRIX_INDIRECT_SOURCES }
        val matrix = when {
            !geoHit && !directHit && !indirectHit -> Verdict.NOT_DETECTED
            !geoHit && directHit && !indirectHit -> Verdict.NOT_DETECTED
            !geoHit && !directHit && indirectHit -> Verdict.NOT_DETECTED
            geoHit && !directHit && !indirectHit -> Verdict.NEEDS_REVIEW
            !geoHit && directHit && indirectHit ->
                if (geoAxisAvailable) Verdict.NEEDS_REVIEW else Verdict.DETECTED
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
        val nativeReviewHit = nativeSigns.evidence.any { it.detected && it.source in NATIVE_REVIEW_SOURCES }
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
            return Verdict.NEEDS_REVIEW
        }

        return matrix
    }
}
