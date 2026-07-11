package com.notcvnt.rknhardering.ui.main

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.DomainReachabilityResult
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.LocalProxyCheckStatus
import com.notcvnt.rknhardering.model.StunProbeGroupResult

internal enum class SimpleResultStatus {
    RUNNING,
    CLEAN,
    REVIEW,
    DETECTED,
    ERROR,
    DISABLED,
}

internal enum class SimpleSignalArea {
    PUBLIC_ADDRESS,
    DEVICE_NETWORK,
    LOCAL_APP,
    LOCAL_PROXY,
    NETWORK_ROUTE,
    CALL_ROUTE,
    LOCATION,
    REMOTE_SITE,
    DEVICE_ENVIRONMENT,
    MULTIPLE,
    NONE,
}

internal enum class SimpleResultCause {
    IP_RU_SERVICES_DISAGREE,
    IP_NON_RU_SERVICES_DISAGREE,
    IP_GROUPS_DISAGREE,
    IP_FAMILIES_DIFFER,
    IP_PARTIAL_RESPONSE,
    IP_UNAVAILABLE,
    CDN_RESPONSES_DIFFER,
    CDN_PARTIAL_RESPONSE,
    PUBLIC_IP_LOCATION,
    VPN_NETWORK_STATE,
    ACTIVE_VPN_APP,
    SYSTEM_PROXY,
    LOCAL_PROXY,
    VPN_INTERFACE,
    VPN_ROUTE,
    PUBLIC_HOST_ROUTE,
    DNS_REDIRECTION,
    TRAFFIC_BYPASS,
    PROXY_AUTH_REQUIRED,
    LOCATION_CONFLICT,
    ICMP_RESPONSE_MISMATCH,
    RTT_ROUTE_PATTERN,
    TELEGRAM_CALL_PATH,
    WHATSAPP_CALL_PATH,
    CALL_CHECK_UNAVAILABLE,
    DOMAIN_DNS_MISMATCH,
    DOMAIN_TCP_MISMATCH,
    DOMAIN_TLS_MISMATCH,
    PUBLIC_DATA_UNAVAILABLE,
    NETWORK_DATA_UNAVAILABLE,
    REMOTE_DATA_UNAVAILABLE,
    DEVICE_DATA_UNAVAILABLE,
    DEVICE_ENVIRONMENT,
}

internal data class SimpleCardModel(
    val status: SimpleResultStatus,
    val area: SimpleSignalArea = SimpleSignalArea.NONE,
    val extraInformation: Boolean = false,
    val causes: List<SimpleResultCause> = emptyList(),
)

internal object SimpleResultModels {
    fun category(result: CategoryResult, extraInformation: Boolean = false): SimpleCardModel {
        val status = status(result.detected, result.needsReview, result.hasError)
        val hasDiagnosticAppSignal = result.matchedApps.isNotEmpty() ||
            result.evidence.any {
                it.source == EvidenceSource.INSTALLED_APP ||
                    it.source == EvidenceSource.VPN_SERVICE_DECLARATION
            }
        val signalSources = buildSet {
            result.evidence.filter { it.detected }.mapTo(this) { it.source }
            result.findings
                .filter { it.detected || it.needsReview }
                .mapNotNullTo(this) { it.source }
            if (result.activeApps.isNotEmpty()) add(EvidenceSource.ACTIVE_VPN)
        }
        val areaSources = buildSet {
            addAll(signalSources)
            result.findings.filter { it.isError }.mapNotNullTo(this) { it.source }
            if (result.matchedApps.isNotEmpty()) add(EvidenceSource.INSTALLED_APP)
        }
        return SimpleCardModel(
            status = status,
            area = signalArea(areaSources),
            extraInformation = extraInformation || hasDiagnosticAppSignal,
            causes = if (status == SimpleResultStatus.CLEAN) {
                emptyList()
            } else {
                buildList {
                    result.findings.filter { it.isError }.mapNotNullTo(this) { errorCause(it.source) }
                    signalSources.mapNotNullTo(this) { signalCause(it) }
                }.distinct().sortedBy { it.ordinal }.take(MAX_CAUSES)
            },
        )
    }

    fun ipComparison(result: IpComparisonResult): SimpleCardModel {
        val successfulCount = result.ruGroup.responses.count { it.ip != null } +
            result.nonRuGroup.responses.count { it.ip != null }
        val ruIp = result.ruGroup.canonicalIp
        val nonRuIp = result.nonRuGroup.canonicalIp
        val causes = buildList {
            if (result.ruGroup.detected) add(SimpleResultCause.IP_RU_SERVICES_DISAGREE)
            if (result.nonRuGroup.detected) add(SimpleResultCause.IP_NON_RU_SERVICES_DISAGREE)
            if (ruIp != null && nonRuIp != null) {
                if ((ruIp.contains(':')) != (nonRuIp.contains(':'))) {
                    add(SimpleResultCause.IP_FAMILIES_DIFFER)
                } else if (ruIp != nonRuIp) {
                    add(SimpleResultCause.IP_GROUPS_DISAGREE)
                }
            }
            if (successfulCount == 0 && (result.hasError || result.needsReview) && isEmpty()) {
                add(SimpleResultCause.IP_UNAVAILABLE)
            } else if (result.needsReview && isEmpty()) {
                add(SimpleResultCause.IP_PARTIAL_RESPONSE)
            }
        }
        return SimpleCardModel(
            status = status(result.detected, result.needsReview, result.hasError),
            area = SimpleSignalArea.PUBLIC_ADDRESS,
            causes = causes.distinct().take(MAX_CAUSES),
        )
    }

    fun cdn(result: CdnPullingResult): SimpleCardModel {
        val cause = when {
            result.hasError && result.responses.none { it.ip != null || it.ipv4 != null || it.ipv6 != null } ->
                SimpleResultCause.REMOTE_DATA_UNAVAILABLE
            result.detected -> SimpleResultCause.CDN_RESPONSES_DIFFER
            result.needsReview -> SimpleResultCause.CDN_PARTIAL_RESPONSE
            else -> null
        }
        return SimpleCardModel(
            status = status(result.detected, result.needsReview, result.hasError),
            area = SimpleSignalArea.REMOTE_SITE,
            extraInformation = true,
            causes = listOfNotNull(cause),
        )
    }

    fun bypass(result: BypassResult): SimpleCardModel {
        val sources = buildSet {
            result.evidence.filter { it.detected }.mapTo(this) { it.source }
            result.findings.filter { it.detected || it.needsReview }.mapNotNullTo(this) { it.source }
        }
        val causes = buildList {
            result.findings.filter { it.isError }.mapNotNullTo(this) { errorCause(it.source) }
            sources.mapNotNullTo(this) { signalCause(it) }
            result.proxyChecks.forEach { check ->
                when (check.status) {
                    LocalProxyCheckStatus.CONFIRMED_BYPASS -> add(SimpleResultCause.TRAFFIC_BYPASS)
                    LocalProxyCheckStatus.AUTH_REQUIRED -> add(SimpleResultCause.PROXY_AUTH_REQUIRED)
                    LocalProxyCheckStatus.PROXY_IP_UNAVAILABLE,
                    LocalProxyCheckStatus.DIRECT_IP_UNAVAILABLE,
                    -> add(SimpleResultCause.PUBLIC_DATA_UNAVAILABLE)
                    LocalProxyCheckStatus.SAME_IP -> Unit
                }
            }
        }.distinct().sortedBy { it.ordinal }.take(MAX_CAUSES)
        return SimpleCardModel(
            status = status(result.detected, result.needsReview, result.hasError),
            area = signalArea(sources),
            causes = causes,
        )
    }

    fun callTransport(
        leaks: List<CallTransportLeakResult>,
        stunGroups: List<StunProbeGroupResult>,
    ): SimpleCardModel {
        val status = when {
            leaks.any { it.status == CallTransportStatus.ERROR } -> SimpleResultStatus.ERROR
            leaks.any { it.status == CallTransportStatus.NEEDS_REVIEW } -> SimpleResultStatus.REVIEW
            leaks.isEmpty() && stunGroups.isEmpty() -> SimpleResultStatus.ERROR
            else -> SimpleResultStatus.CLEAN
        }
        val causes = when {
            status == SimpleResultStatus.ERROR -> listOf(SimpleResultCause.CALL_CHECK_UNAVAILABLE)
            status == SimpleResultStatus.REVIEW -> leaks
                .filter { it.status == CallTransportStatus.NEEDS_REVIEW }
                .map {
                    when (it.service) {
                        com.notcvnt.rknhardering.model.CallTransportService.TELEGRAM ->
                            SimpleResultCause.TELEGRAM_CALL_PATH
                        com.notcvnt.rknhardering.model.CallTransportService.WHATSAPP ->
                            SimpleResultCause.WHATSAPP_CALL_PATH
                    }
                }
                .distinct()
                .take(MAX_CAUSES)
            else -> emptyList()
        }
        return SimpleCardModel(status, SimpleSignalArea.CALL_ROUTE, causes = causes)
    }

    fun domainReachability(result: DomainReachabilityResult): SimpleCardModel {
        val status = when {
            result.isEmpty -> SimpleResultStatus.ERROR
            result.responses.any { !it.matchesExpectation } -> SimpleResultStatus.DETECTED
            else -> SimpleResultStatus.CLEAN
        }
        val causes = if (result.isEmpty) {
            listOf(SimpleResultCause.REMOTE_DATA_UNAVAILABLE)
        } else {
            buildList {
                result.responses.filter { !it.matchesExpectation }.forEach { response ->
                    if ((response.dnsStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK) !=
                        response.expectedDnsAvailable
                    ) {
                        add(SimpleResultCause.DOMAIN_DNS_MISMATCH)
                    }
                    if (response.dnsStatus != com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.FAILED &&
                        (response.tcpStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK) !=
                        response.expectedTcpAvailable
                    ) {
                        add(SimpleResultCause.DOMAIN_TCP_MISMATCH)
                    }
                    if (response.tcpStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK &&
                        (response.tlsStatus == com.notcvnt.rknhardering.model.DomainReachabilityStepStatus.OK) !=
                        response.expectedTlsAvailable
                    ) {
                        add(SimpleResultCause.DOMAIN_TLS_MISMATCH)
                    }
                }
            }.distinct().take(MAX_CAUSES)
        }
        return SimpleCardModel(
            status = status,
            area = SimpleSignalArea.REMOTE_SITE,
            extraInformation = true,
            causes = causes,
        )
    }

    private fun status(detected: Boolean, needsReview: Boolean, hasError: Boolean): SimpleResultStatus =
        when {
            hasError -> SimpleResultStatus.ERROR
            detected -> SimpleResultStatus.DETECTED
            needsReview -> SimpleResultStatus.REVIEW
            else -> SimpleResultStatus.CLEAN
        }

    private fun signalArea(sources: Set<EvidenceSource>): SimpleSignalArea {
        val areas = sources.mapTo(linkedSetOf()) { source ->
            when (source) {
                EvidenceSource.GEO_IP -> SimpleSignalArea.PUBLIC_ADDRESS
                EvidenceSource.INSTALLED_APP,
                EvidenceSource.VPN_SERVICE_DECLARATION,
                EvidenceSource.ACTIVE_VPN,
                -> SimpleSignalArea.LOCAL_APP
                EvidenceSource.LOCAL_PROXY,
                EvidenceSource.XRAY_API,
                EvidenceSource.CLASH_API,
                EvidenceSource.PROXY_AUTH_BYPASS,
                EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                -> SimpleSignalArea.LOCAL_PROXY
                EvidenceSource.ROUTING,
                EvidenceSource.DNS,
                EvidenceSource.NETWORK_INTERFACE,
                EvidenceSource.NATIVE_HOST_ROUTE,
                EvidenceSource.SPLIT_TUNNEL_BYPASS,
                EvidenceSource.VPN_GATEWAY_LEAK,
                EvidenceSource.VPN_NETWORK_BINDING,
                EvidenceSource.TUN_ACTIVE_PROBE,
                EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
                EvidenceSource.INDIRECT_NETWORK_CAPABILITIES,
                EvidenceSource.SYSTEM_PROXY,
                -> SimpleSignalArea.NETWORK_ROUTE
                EvidenceSource.TELEGRAM_CALL_TRANSPORT,
                EvidenceSource.WHATSAPP_CALL_TRANSPORT,
                EvidenceSource.STUN_PROBE,
                -> SimpleSignalArea.CALL_ROUTE
                EvidenceSource.LOCATION_SIGNALS,
                EvidenceSource.HOME_ROUTED_ROAMING,
                -> SimpleSignalArea.LOCATION
                EvidenceSource.NATIVE_INTERFACE,
                EvidenceSource.NATIVE_ROUTE,
                EvidenceSource.NATIVE_SOCKET,
                EvidenceSource.NATIVE_HOOK_MARKERS,
                EvidenceSource.NATIVE_JVM_MISMATCH,
                EvidenceSource.NATIVE_LIBRARY_INTEGRITY,
                EvidenceSource.NATIVE_ROOT_DETECTION,
                EvidenceSource.NATIVE_EMULATOR,
                EvidenceSource.SANDBOX_ISOLATION,
                EvidenceSource.DUMPSYS,
                -> SimpleSignalArea.DEVICE_ENVIRONMENT
                EvidenceSource.ICMP_SPOOFING,
                EvidenceSource.RTT_TRIANGULATION,
                -> SimpleSignalArea.REMOTE_SITE
            }
        }
        return when (areas.size) {
            0 -> SimpleSignalArea.NONE
            1 -> areas.first()
            else -> SimpleSignalArea.MULTIPLE
        }
    }

    private fun signalCause(source: EvidenceSource): SimpleResultCause? = when (source) {
        EvidenceSource.GEO_IP -> SimpleResultCause.PUBLIC_IP_LOCATION
        EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
        EvidenceSource.INDIRECT_NETWORK_CAPABILITIES,
        EvidenceSource.DUMPSYS,
        -> SimpleResultCause.VPN_NETWORK_STATE
        EvidenceSource.ACTIVE_VPN -> SimpleResultCause.ACTIVE_VPN_APP
        EvidenceSource.SYSTEM_PROXY -> SimpleResultCause.SYSTEM_PROXY
        EvidenceSource.LOCAL_PROXY,
        EvidenceSource.XRAY_API,
        EvidenceSource.CLASH_API,
        EvidenceSource.PROXY_TECHNICAL_SIGNAL,
        -> SimpleResultCause.LOCAL_PROXY
        EvidenceSource.PROXY_AUTH_BYPASS -> SimpleResultCause.PROXY_AUTH_REQUIRED
        EvidenceSource.NETWORK_INTERFACE,
        EvidenceSource.NATIVE_INTERFACE,
        -> SimpleResultCause.VPN_INTERFACE
        EvidenceSource.ROUTING,
        EvidenceSource.NATIVE_ROUTE,
        -> SimpleResultCause.VPN_ROUTE
        EvidenceSource.NATIVE_HOST_ROUTE -> SimpleResultCause.PUBLIC_HOST_ROUTE
        EvidenceSource.DNS -> SimpleResultCause.DNS_REDIRECTION
        EvidenceSource.SPLIT_TUNNEL_BYPASS,
        EvidenceSource.VPN_GATEWAY_LEAK,
        EvidenceSource.VPN_NETWORK_BINDING,
        EvidenceSource.TUN_ACTIVE_PROBE,
        -> SimpleResultCause.TRAFFIC_BYPASS
        EvidenceSource.LOCATION_SIGNALS,
        EvidenceSource.HOME_ROUTED_ROAMING,
        -> SimpleResultCause.LOCATION_CONFLICT
        EvidenceSource.ICMP_SPOOFING -> SimpleResultCause.ICMP_RESPONSE_MISMATCH
        EvidenceSource.RTT_TRIANGULATION -> SimpleResultCause.RTT_ROUTE_PATTERN
        EvidenceSource.TELEGRAM_CALL_TRANSPORT -> SimpleResultCause.TELEGRAM_CALL_PATH
        EvidenceSource.WHATSAPP_CALL_TRANSPORT -> SimpleResultCause.WHATSAPP_CALL_PATH
        EvidenceSource.STUN_PROBE -> SimpleResultCause.CALL_CHECK_UNAVAILABLE
        EvidenceSource.NATIVE_SOCKET,
        EvidenceSource.NATIVE_HOOK_MARKERS,
        EvidenceSource.NATIVE_JVM_MISMATCH,
        EvidenceSource.NATIVE_LIBRARY_INTEGRITY,
        EvidenceSource.NATIVE_ROOT_DETECTION,
        EvidenceSource.NATIVE_EMULATOR,
        EvidenceSource.SANDBOX_ISOLATION,
        -> SimpleResultCause.DEVICE_ENVIRONMENT
        EvidenceSource.INSTALLED_APP,
        EvidenceSource.VPN_SERVICE_DECLARATION,
        -> null
    }

    private fun errorCause(source: EvidenceSource?): SimpleResultCause = when (source) {
        EvidenceSource.GEO_IP -> SimpleResultCause.PUBLIC_DATA_UNAVAILABLE
        EvidenceSource.ICMP_SPOOFING,
        EvidenceSource.RTT_TRIANGULATION,
        EvidenceSource.TELEGRAM_CALL_TRANSPORT,
        EvidenceSource.WHATSAPP_CALL_TRANSPORT,
        EvidenceSource.STUN_PROBE,
        -> SimpleResultCause.REMOTE_DATA_UNAVAILABLE
        EvidenceSource.NATIVE_INTERFACE,
        EvidenceSource.NATIVE_ROUTE,
        EvidenceSource.NATIVE_SOCKET,
        EvidenceSource.NATIVE_HOOK_MARKERS,
        EvidenceSource.NATIVE_JVM_MISMATCH,
        EvidenceSource.NATIVE_LIBRARY_INTEGRITY,
        EvidenceSource.NATIVE_ROOT_DETECTION,
        EvidenceSource.NATIVE_EMULATOR,
        EvidenceSource.SANDBOX_ISOLATION,
        -> SimpleResultCause.DEVICE_DATA_UNAVAILABLE
        null -> SimpleResultCause.NETWORK_DATA_UNAVAILABLE
        else -> SimpleResultCause.NETWORK_DATA_UNAVAILABLE
    }

    private const val MAX_CAUSES = 3
}
