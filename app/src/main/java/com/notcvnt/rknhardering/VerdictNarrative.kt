package com.notcvnt.rknhardering

import android.content.Context
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.probe.XrayOutboundSummary

enum class ExposureStatus {
    REMOTE_ENDPOINT_DISCOVERED,
    PUBLIC_IP_ONLY,
    LOCAL_PROXY_OR_API_ONLY,
    TECHNICAL_SIGNAL_ONLY,
    INSUFFICIENT_DATA;

    fun label(context: Context): String = when (this) {
        REMOTE_ENDPOINT_DISCOVERED -> context.getString(R.string.narrative_exposure_remote_endpoint)
        PUBLIC_IP_ONLY -> context.getString(R.string.narrative_exposure_public_ip)
        LOCAL_PROXY_OR_API_ONLY -> context.getString(R.string.narrative_exposure_local_proxy)
        TECHNICAL_SIGNAL_ONLY -> context.getString(R.string.narrative_exposure_technical_signal)
        INSUFFICIENT_DATA -> context.getString(R.string.narrative_exposure_insufficient)
    }
}

data class NarrativeRow(
    val label: String,
    val value: String,
)

data class VerdictNarrative(
    val explanation: String,
    val exposureStatus: ExposureStatus,
    val meaningRows: List<String>,
    val discoveredRows: List<NarrativeRow>,
    val reasonRows: List<String>,
)

object VerdictNarrativeBuilder {

    private val ipv4Regex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
    private val ipv6Regex = Regex("""(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9])""")

    fun build(context: Context, result: CheckResult, privacyMode: Boolean = false): VerdictNarrative {
        val snapshot = collectSnapshot(context, result)
        val exposureStatus = determineExposureStatus(snapshot)

        return VerdictNarrative(
            explanation = buildExplanation(context, result.verdict, exposureStatus),
            exposureStatus = exposureStatus,
            meaningRows = buildMeaningRows(context, result.verdict, exposureStatus),
            discoveredRows = buildDiscoveredRows(context, snapshot, exposureStatus, privacyMode),
            reasonRows = buildReasonRows(context, result),
        )
    }

    private fun collectSnapshot(context: Context, result: CheckResult): Snapshot {
        val xrayApi = result.bypassResult.xrayApiScanResult
        val gatewayLeakFinding = result.bypassResult.findings.firstOrNull {
            it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected
        }
        val gatewayLeakIps = gatewayLeakFinding?.description?.let(::extractIps).orEmpty()
        val gatewayLeakIpPair = gatewayLeakIps.takeIf { it.size >= 2 }
        val vpnProbeFinding = result.bypassResult.findings.firstOrNull {
            (it.source == EvidenceSource.VPN_NETWORK_BINDING || it.source == EvidenceSource.TUN_ACTIVE_PROBE) &&
                extractIps(it.description).isNotEmpty()
        }
        val callTransportLeak = result.bypassResult.callTransportLeaks.firstOrNull {
            it.status == CallTransportStatus.NEEDS_REVIEW
        }

        return Snapshot(
            remoteEndpoints = xrayApi?.outbounds.orEmpty().mapNotNull(::formatRemoteEndpoint).distinct(),
            localApiEndpoint = xrayApi?.endpoint?.let { formatHostPort(it.host, it.port) },
            localProxyEndpoint = result.bypassResult.proxyEndpoint?.let {
                "${it.type.name} ${formatHostPort(it.host, it.port)}"
            },
            ownerApp = result.bypassResult.proxyOwner?.let { LocalProxyOwnerFormatter.format(context, it) },
            vpnNetworkIp = gatewayLeakIpPair?.get(0)
                ?: result.bypassResult.vpnNetworkIp
                ?: vpnProbeFinding?.description?.let(::extractIps)?.firstOrNull(),
            realIp = gatewayLeakIpPair?.get(1) ?: result.bypassResult.underlyingIp,
            directIp = result.bypassResult.directIp,
            proxyIp = result.bypassResult.proxyIp,
            geoIp = extractGeoIp(context, result.geoIp),
            ruCheckerIp = result.ipComparison.ruGroup.canonicalIp,
            nonRuCheckerIp = result.ipComparison.nonRuGroup.canonicalIp,
            callTransportLeak = callTransportLeak,
            technicalSignalsPresent = hasTechnicalSignals(result),
        )
    }

    private fun determineExposureStatus(snapshot: Snapshot): ExposureStatus {
        return when {
            snapshot.remoteEndpoints.isNotEmpty() -> ExposureStatus.REMOTE_ENDPOINT_DISCOVERED
            snapshot.hasPublicIp -> ExposureStatus.PUBLIC_IP_ONLY
            snapshot.localApiEndpoint != null || snapshot.localProxyEndpoint != null ->
                ExposureStatus.LOCAL_PROXY_OR_API_ONLY
            snapshot.technicalSignalsPresent -> ExposureStatus.TECHNICAL_SIGNAL_ONLY
            else -> ExposureStatus.INSUFFICIENT_DATA
        }
    }

    private fun buildExplanation(context: Context, verdict: Verdict, exposureStatus: ExposureStatus): String {
        val base = when (verdict) {
            Verdict.DETECTED -> context.getString(R.string.narrative_explanation_detected)
            Verdict.NEEDS_REVIEW -> context.getString(R.string.narrative_explanation_needs_review)
            Verdict.NOT_DETECTED -> context.getString(R.string.narrative_explanation_not_detected)
        }
        val exposure = when (exposureStatus) {
            ExposureStatus.REMOTE_ENDPOINT_DISCOVERED ->
                context.getString(R.string.narrative_explanation_exposure_remote)
            ExposureStatus.PUBLIC_IP_ONLY ->
                context.getString(R.string.narrative_explanation_exposure_public_ip)
            ExposureStatus.LOCAL_PROXY_OR_API_ONLY ->
                context.getString(R.string.narrative_explanation_exposure_local_proxy)
            ExposureStatus.TECHNICAL_SIGNAL_ONLY ->
                context.getString(R.string.narrative_explanation_exposure_technical)
            ExposureStatus.INSUFFICIENT_DATA ->
                context.getString(R.string.narrative_explanation_exposure_insufficient)
        }
        return "$base $exposure"
    }

    private fun buildMeaningRows(context: Context, verdict: Verdict, exposureStatus: ExposureStatus): List<String> {
        val verdictMeaning = when (verdict) {
            Verdict.DETECTED -> context.getString(R.string.narrative_meaning_detected)
            Verdict.NEEDS_REVIEW -> context.getString(R.string.narrative_meaning_needs_review)
            Verdict.NOT_DETECTED -> context.getString(R.string.narrative_meaning_not_detected)
        }
        val exposureMeaning = when (exposureStatus) {
            ExposureStatus.REMOTE_ENDPOINT_DISCOVERED ->
                context.getString(R.string.narrative_meaning_exposure_remote)
            ExposureStatus.PUBLIC_IP_ONLY ->
                context.getString(R.string.narrative_meaning_exposure_public_ip)
            ExposureStatus.LOCAL_PROXY_OR_API_ONLY ->
                context.getString(R.string.narrative_meaning_exposure_local_proxy)
            ExposureStatus.TECHNICAL_SIGNAL_ONLY ->
                context.getString(R.string.narrative_meaning_exposure_technical)
            ExposureStatus.INSUFFICIENT_DATA ->
                context.getString(R.string.narrative_meaning_exposure_insufficient)
        }
        return listOf(verdictMeaning, exposureMeaning)
    }

    private fun buildDiscoveredRows(
        context: Context,
        snapshot: Snapshot,
        exposureStatus: ExposureStatus,
        privacyMode: Boolean,
    ): List<NarrativeRow> {
        val rows = mutableListOf<NarrativeRow>()

        fun addRow(label: String, value: String?) {
            if (value.isNullOrBlank()) return
            rows += NarrativeRow(label, maybeMask(value, privacyMode))
        }

        addRow(context.getString(R.string.narrative_label_exposure_level), exposureStatus.label(context))
        addRow(context.getString(R.string.narrative_label_xray_api), snapshot.localApiEndpoint)

        snapshot.remoteEndpoints.take(3).forEachIndexed { index, endpoint ->
            addRow(
                if (index == 0) context.getString(R.string.narrative_label_remote_endpoint)
                else context.getString(R.string.narrative_label_remote_endpoint_extra),
                endpoint,
            )
        }

        addRow(context.getString(R.string.narrative_label_local_proxy), snapshot.localProxyEndpoint)
        addRow(context.getString(R.string.narrative_label_owner_app), snapshot.ownerApp)
        addRow(context.getString(R.string.narrative_label_vpn_network_ip), snapshot.vpnNetworkIp)
        addRow(context.getString(R.string.narrative_label_real_ip), snapshot.realIp)
        addRow(context.getString(R.string.narrative_label_direct_ip), snapshot.directIp)
        addRow(context.getString(R.string.narrative_label_proxy_ip), snapshot.proxyIp)
        snapshot.callTransportLeak?.let { leak ->
            addRow(
                context.getString(R.string.narrative_label_call_transport),
                "${leak.service.label()} (${leak.probeKind.label(context)})",
            )
            addRow(
                context.getString(R.string.narrative_label_call_transport_path),
                leak.networkPath.label(),
            )
            addRow(
                context.getString(R.string.narrative_label_call_transport_target),
                leak.targetHost?.let { host -> formatHostPort(host, leak.targetPort) },
            )
            addRow(
                context.getString(R.string.narrative_label_call_transport_public_ip),
                leak.observedPublicIp,
            )
            addRow(
                context.getString(R.string.narrative_label_call_transport_mapped_ip),
                leak.mappedIp,
            )
        }

        if (!snapshot.ruCheckerIp.isNullOrBlank() && snapshot.ruCheckerIp == snapshot.nonRuCheckerIp) {
            addRow(context.getString(R.string.narrative_label_checkers_ip), snapshot.ruCheckerIp)
        } else {
            addRow(context.getString(R.string.narrative_label_ru_checkers_ip), snapshot.ruCheckerIp)
            addRow(context.getString(R.string.narrative_label_non_ru_checkers_ip), snapshot.nonRuCheckerIp)
        }

        addRow(context.getString(R.string.narrative_label_geo_ip), snapshot.geoIp)
        return rows
    }

    private fun buildReasonRows(context: Context, result: CheckResult): List<String> {
        val reasons = linkedSetOf<String>()

        if (hasBypassEvidence(result.bypassResult, EvidenceSource.XRAY_API)) {
            reasons += context.getString(R.string.narrative_reason_xray_api)
        }
        if (hasBypassEvidence(result.bypassResult, EvidenceSource.SPLIT_TUNNEL_BYPASS)) {
            reasons += context.getString(R.string.narrative_reason_split_tunnel)
        }
        if (hasBypassEvidence(result.bypassResult, EvidenceSource.VPN_GATEWAY_LEAK)) {
            reasons += context.getString(R.string.narrative_reason_vpn_gateway_leak)
        }
        if (hasBypassEvidence(result.bypassResult, EvidenceSource.VPN_NETWORK_BINDING)) {
            reasons += context.getString(R.string.narrative_reason_vpn_network_binding)
        }
        if (result.bypassResult.needsReview) {
            reasons += context.getString(R.string.narrative_reason_bypass_unconfirmed)
        }
        if (result.ipComparison.detected) {
            reasons += context.getString(R.string.narrative_reason_ip_comparison_detected)
        } else if (result.ipComparison.needsReview) {
            reasons += context.getString(R.string.narrative_reason_ip_comparison_review)
        }

        val foreignGeoSignal = result.geoIp.needsReview || result.geoIp.evidence.any {
            it.source == EvidenceSource.GEO_IP && it.detected
        }
        val locationConfirmsRussia = result.locationSignals.findings.any {
            it.description.contains("network_mcc_ru:true") ||
                it.description.contains("cell_country_ru:true") ||
                it.description.contains("location_country_ru:true")
        }
        if (foreignGeoSignal && locationConfirmsRussia) {
            reasons += context.getString(R.string.narrative_reason_geo_location_conflict)
        } else if (foreignGeoSignal) {
            reasons += context.getString(R.string.narrative_reason_geo_foreign)
        }

        if (result.directSigns.detected) {
            reasons += context.getString(R.string.narrative_reason_direct_signs)
        }
        if (result.indirectSigns.detected) {
            reasons += context.getString(R.string.narrative_reason_indirect_signs)
        }
        if (result.bypassResult.callTransportLeaks.any { it.status == CallTransportStatus.NEEDS_REVIEW }) {
            reasons += context.getString(R.string.narrative_reason_call_transport_signal)
        }

        if (reasons.isEmpty()) {
            reasons += when (result.verdict) {
                Verdict.DETECTED -> context.getString(R.string.narrative_reason_fallback_detected)
                Verdict.NEEDS_REVIEW -> context.getString(R.string.narrative_reason_fallback_review)
                Verdict.NOT_DETECTED -> context.getString(R.string.narrative_reason_fallback_clean)
            }
        }

        return reasons.take(5)
    }

    private fun extractGeoIp(context: Context, result: CategoryResult): String? {
        val prefix = context.getString(R.string.checker_geo_info_ip, "").trim()
        return result.findings.firstOrNull {
            it.isInformational && it.description.startsWith(prefix)
        }?.description?.removePrefix(prefix)?.trim()
    }

    private fun hasTechnicalSignals(result: CheckResult): Boolean {
        return result.directSigns.detected ||
            result.directSigns.needsReview ||
            result.indirectSigns.detected ||
            result.indirectSigns.needsReview ||
            result.geoIp.detected ||
            result.geoIp.needsReview ||
            result.locationSignals.detected ||
            result.locationSignals.needsReview ||
            result.ipComparison.detected ||
            result.ipComparison.needsReview ||
            result.bypassResult.callTransportLeaks.any { it.status == CallTransportStatus.NEEDS_REVIEW } ||
            result.bypassResult.findings.any {
                it.source == EvidenceSource.TUN_ACTIVE_PROBE ||
                    it.source == EvidenceSource.VPN_NETWORK_BINDING ||
                    it.source == EvidenceSource.VPN_GATEWAY_LEAK
            } ||
            result.bypassResult.evidence.any { it.detected }
    }

    private fun hasBypassEvidence(result: BypassResult, source: EvidenceSource): Boolean {
        return result.evidence.any { it.source == source && it.detected } ||
            result.findings.any { it.source == source && it.detected }
    }

    private fun formatRemoteEndpoint(outbound: XrayOutboundSummary): String? {
        val host = outbound.address ?: outbound.sni ?: return null
        return formatHostPort(host, outbound.port)
    }

    private fun formatHostPort(host: String, port: Int?): String {
        val renderedHost = if (host.contains(':') && !host.startsWith("[")) {
            "[$host]"
        } else {
            host
        }
        return if (port != null) "$renderedHost:$port" else renderedHost
    }

    private fun extractIps(text: String): List<String> {
        val combinedIpRegex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9])""")
        return combinedIpRegex.findAll(text).map { it.value }.distinct().toList()
    }

    private fun maybeMask(value: String, privacyMode: Boolean): String {
        if (!privacyMode) return value
        val maskedIpv4 = ipv4Regex.replace(value) { maskIpv4(it.value) }
        return ipv6Regex.replace(maskedIpv4) { maskIpv6(it.value) }
    }

    private fun maskIpv4(value: String): String {
        val parts = value.split(".")
        if (parts.size != 4) return value
        return "${parts[0]}.${parts[1]}.*.*"
    }

    private fun maskIpv6(value: String): String {
        val parts = value.trim('[', ']').split(':').filter { it.isNotEmpty() }
        if (parts.isEmpty()) return "*:*:*:*"
        val visible = parts.take(4)
        return visible.joinToString(":") + ":*:*:*:*"
    }

    private fun CallTransportNetworkPath.label(): String {
        return when (this) {
            CallTransportNetworkPath.ACTIVE -> "active network"
            CallTransportNetworkPath.UNDERLYING -> "underlying network"
            CallTransportNetworkPath.LOCAL_PROXY -> "local proxy"
        }
    }

    private fun CallTransportService.label(): String {
        return when (this) {
            CallTransportService.TELEGRAM -> "Telegram"
            CallTransportService.WHATSAPP -> "WhatsApp"
        }
    }

    private fun CallTransportProbeKind.label(context: Context): String {
        return when (this) {
            CallTransportProbeKind.DIRECT_UDP_STUN ->
                context.getString(R.string.narrative_value_call_transport_direct_udp_stun)
            CallTransportProbeKind.PROXY_ASSISTED_TELEGRAM ->
                context.getString(R.string.narrative_value_call_transport_proxy_assisted_telegram)
            CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN ->
                context.getString(R.string.narrative_value_call_transport_proxy_assisted_udp_stun)
        }
    }

    private data class Snapshot(
        val remoteEndpoints: List<String>,
        val localApiEndpoint: String?,
        val localProxyEndpoint: String?,
        val ownerApp: String?,
        val vpnNetworkIp: String?,
        val realIp: String?,
        val directIp: String?,
        val proxyIp: String?,
        val geoIp: String?,
        val ruCheckerIp: String?,
        val nonRuCheckerIp: String?,
        val callTransportLeak: CallTransportLeakResult?,
        val technicalSignalsPresent: Boolean,
    ) {
        val hasPublicIp: Boolean
            get() = listOf(
                vpnNetworkIp,
                realIp,
                directIp,
                proxyIp,
                callTransportLeak?.observedPublicIp,
                callTransportLeak?.mappedIp,
                geoIp,
                ruCheckerIp,
                nonRuCheckerIp,
            ).any { !it.isNullOrBlank() }
    }
}
