package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VpnAppKind

object VerdictEngine {

    fun evaluate(
        geoIp: CategoryResult,
        directSigns: CategoryResult,
        indirectSigns: CategoryResult,
        locationSignals: CategoryResult,
        bypassResult: BypassResult,
    ): Verdict {
        val evidence = buildList {
            addAll(geoIp.evidence)
            addAll(directSigns.evidence)
            addAll(indirectSigns.evidence)
            addAll(locationSignals.evidence)
            addAll(bypassResult.evidence)
        }

        if (evidence.any { it.source == EvidenceSource.SPLIT_TUNNEL_BYPASS && it.detected }) {
            return Verdict.DETECTED
        }
        if (evidence.any { it.source == EvidenceSource.XRAY_API && it.detected }) {
            return Verdict.DETECTED
        }
        if (evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected }) {
            return Verdict.DETECTED
        }

        // Location signals: Network MCC is RU + GeoIP is foreign -> DETECTED
        val networkMccIsRu = locationSignals.findings.any {
            it.description.contains("network_mcc_ru:true")
        }
        val hasGeoSignal = geoIp.needsReview || evidence.any {
            it.source == EvidenceSource.GEO_IP && it.detected
        }
        if (networkMccIsRu && hasGeoSignal) {
            return Verdict.DETECTED
        }

        val hasStrongTransport = evidence.any {
            it.source == EvidenceSource.NETWORK_CAPABILITIES && it.confidence == EvidenceConfidence.HIGH
        }
        val hasLocalProxy = evidence.any { it.source == EvidenceSource.LOCAL_PROXY && it.detected }
        val hasTargetedInstalled = evidence.any {
            it.source == EvidenceSource.INSTALLED_APP && it.kind == VpnAppKind.TARGETED_BYPASS
        }
        val hasTargetedActive = evidence.any {
            it.source == EvidenceSource.ACTIVE_VPN && it.kind == VpnAppKind.TARGETED_BYPASS
        }
        val hasGenericActive = evidence.any {
            it.source == EvidenceSource.ACTIVE_VPN && it.kind == VpnAppKind.GENERIC_VPN
        }

        if (hasTargetedActive &&
            (hasLocalProxy || hasStrongTransport || hasGeoSignal || hasTargetedInstalled)
        ) {
            return Verdict.DETECTED
        }

        if (hasGeoSignal && (hasStrongTransport || hasLocalProxy || hasTargetedActive)) {
            return Verdict.DETECTED
        }

        val score = evidence.sumOf(::weight)
        return when {
            score >= 11 && (hasTargetedInstalled || hasTargetedActive || hasLocalProxy) -> Verdict.DETECTED
            hasGenericActive || score >= 4 || directSigns.needsReview || indirectSigns.needsReview -> Verdict.NEEDS_REVIEW
            else -> Verdict.NOT_DETECTED
        }
    }

    private fun weight(item: EvidenceItem): Int {
        val confidenceWeight = when (item.confidence) {
            EvidenceConfidence.HIGH -> 5
            EvidenceConfidence.MEDIUM -> 3
            EvidenceConfidence.LOW -> 1
        }
        val kindWeight = when (item.kind) {
            VpnAppKind.TARGETED_BYPASS -> 2
            VpnAppKind.GENERIC_VPN -> 0
            null -> 0
        }
        val sourceWeight = when (item.source) {
            EvidenceSource.ACTIVE_VPN -> 2
            EvidenceSource.LOCAL_PROXY -> 2
            EvidenceSource.XRAY_API -> 4
            EvidenceSource.SPLIT_TUNNEL_BYPASS -> 5
            EvidenceSource.VPN_GATEWAY_LEAK -> 5
            else -> 0
        }
        return confidenceWeight + kindWeight + sourceWeight
    }
}
