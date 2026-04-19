package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Verdict

object VerdictEngine {

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
    )

    fun evaluate(
        geoIp: CategoryResult,
        directSigns: CategoryResult,
        indirectSigns: CategoryResult,
        locationSignals: CategoryResult,
        bypassResult: BypassResult,
        nativeSigns: CategoryResult = CategoryResult(
            name = "",
            detected = false,
            findings = emptyList(),
        ),
    ): Verdict {
        val directEvidence = directSigns.evidence.filter { it.detected }
        val indirectEvidence = indirectSigns.evidence.filter { it.detected }
        val bypassEvidence = bypassResult.evidence.filter { it.detected }
        val nativeEvidence = nativeSigns.evidence.filter { it.detected }

        if (bypassEvidence.any { it.source == EvidenceSource.SPLIT_TUNNEL_BYPASS }) {
            return Verdict.DETECTED
        }
        if (bypassEvidence.any { it.source == EvidenceSource.XRAY_API }) {
            return Verdict.DETECTED
        }
        if (bypassEvidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK }) {
            return Verdict.DETECTED
        }
        if (bypassEvidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING }) {
            return Verdict.DETECTED
        }

        val locationConfirmsRussia = locationSignals.findings.any {
            it.description.contains("network_mcc_ru:true") ||
                it.description.contains("cell_country_ru:true") ||
                it.description.contains("location_country_ru:true")
        }
        val foreignGeoSignal = geoIp.needsReview || geoIp.evidence.any {
            it.source == EvidenceSource.GEO_IP && it.detected
        }
        if (locationConfirmsRussia && foreignGeoSignal) {
            return Verdict.DETECTED
        }

        val geoMatrixHit = foreignGeoSignal
        val directMatrixHit = directEvidence.any { it.source in MATRIX_DIRECT_SOURCES }
        val indirectMatrixHit =
            indirectEvidence.any { it.source in MATRIX_INDIRECT_SOURCES } ||
                nativeEvidence.any { it.source in MATRIX_INDIRECT_SOURCES }
        val nativeReviewHit = nativeEvidence.any { it.source in NATIVE_REVIEW_SOURCES }

        val matrixVerdict = when {
            !geoMatrixHit && !directMatrixHit && !indirectMatrixHit -> Verdict.NOT_DETECTED
            !geoMatrixHit && directMatrixHit && !indirectMatrixHit -> Verdict.NOT_DETECTED
            !geoMatrixHit && !directMatrixHit && indirectMatrixHit -> Verdict.NOT_DETECTED
            geoMatrixHit && !directMatrixHit && !indirectMatrixHit -> Verdict.NEEDS_REVIEW
            !geoMatrixHit && directMatrixHit && indirectMatrixHit -> Verdict.NEEDS_REVIEW
            else -> Verdict.DETECTED
        }
        val hasActionableCallTransportLeak = indirectSigns.callTransportLeaks.any {
            it.status == CallTransportStatus.NEEDS_REVIEW &&
                it.networkPath != CallTransportNetworkPath.LOCAL_PROXY
        }

        if (bypassResult.needsReview && matrixVerdict == Verdict.NOT_DETECTED) {
            return Verdict.NEEDS_REVIEW
        }
        if (hasActionableCallTransportLeak && matrixVerdict == Verdict.NOT_DETECTED) {
            return Verdict.NEEDS_REVIEW
        }
        if (nativeReviewHit && matrixVerdict == Verdict.NOT_DETECTED) {
            return Verdict.NEEDS_REVIEW
        }

        return matrixVerdict
    }
}
