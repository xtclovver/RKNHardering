package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceItem
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
    )

    fun evaluate(
        geoIp: CategoryResult,
        directSigns: CategoryResult,
        indirectSigns: CategoryResult,
        locationSignals: CategoryResult,
        bypassResult: BypassResult,
    ): Verdict {
        val directEvidence = directSigns.evidence.filter { it.detected }
        val indirectEvidence = indirectSigns.evidence.filter { it.detected }
        val bypassEvidence = bypassResult.evidence.filter { it.detected }
        val callTransportNeedsReview = bypassResult.callTransportLeaks.any {
            it.status == CallTransportStatus.NEEDS_REVIEW
        }

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
        val indirectMatrixHit = indirectEvidence.any { it.source in MATRIX_INDIRECT_SOURCES }

        val matrixVerdict = when {
            !geoMatrixHit && !directMatrixHit && !indirectMatrixHit -> Verdict.NOT_DETECTED
            !geoMatrixHit && directMatrixHit && !indirectMatrixHit -> Verdict.NOT_DETECTED
            !geoMatrixHit && !directMatrixHit && indirectMatrixHit -> Verdict.NOT_DETECTED
            geoMatrixHit && !directMatrixHit && !indirectMatrixHit -> Verdict.NEEDS_REVIEW
            !geoMatrixHit && directMatrixHit && indirectMatrixHit -> Verdict.NEEDS_REVIEW
            else -> Verdict.DETECTED
        }

        if ((bypassResult.needsReview || callTransportNeedsReview) && matrixVerdict == Verdict.NOT_DETECTED) {
            return Verdict.NEEDS_REVIEW
        }

        return matrixVerdict
    }
}
