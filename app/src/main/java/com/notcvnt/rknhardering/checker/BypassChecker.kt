package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.LocalProxyOwnerFormatter
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.probe.CallTransportLeakProber
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.IfconfigClient
import com.notcvnt.rknhardering.probe.LocalSocketInspector
import com.notcvnt.rknhardering.probe.LocalSocketListener
import com.notcvnt.rknhardering.probe.MtProtoProber
import com.notcvnt.rknhardering.probe.PortScanPlanner
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyScanner
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.ScanMode
import com.notcvnt.rknhardering.probe.ScanPhase
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayApiScanner
import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.net.InetAddress

object BypassChecker {

    internal data class UnderlyingEvaluation(
        val detected: Boolean,
        val needsReview: Boolean,
    )

    internal enum class ProxyOwnerStatus {
        RESOLVED,
        UNRESOLVED,
        AMBIGUOUS,
    }

    internal data class ProxyOwnerMatch(
        val owner: LocalProxyOwner? = null,
        val status: ProxyOwnerStatus,
    )

    private enum class IpComparisonOutcome {
        SAME,
        DIFFERENT,
        FAMILY_MISMATCH,
        INCOMPLETE,
    }

    enum class ProgressLine {
        BYPASS,
        XRAY_API,
        UNDERLYING_NETWORK,
        CALL_TRANSPORT,
    }

    data class Progress(
        val line: ProgressLine,
        val phase: String,
        val detail: String,
    )

    suspend fun check(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        splitTunnelEnabled: Boolean = true,
        callTransportProbeEnabled: Boolean = false,
        portRange: String = "full",
        portRangeStart: Int = 1024,
        portRangeEnd: Int = 65535,
        onProgress: (suspend (Progress) -> Unit)? = null,
    ): BypassResult = coroutineScope {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val scanPlan = PortScanPlanner.buildExecutionPlan(
            portRange = portRange,
            portRangeStart = portRangeStart,
            portRangeEnd = portRangeEnd,
        )

        val scanner = ProxyScanner(
            popularPorts = scanPlan.popularPorts,
            scanRange = scanPlan.scanRange,
        )
        val xrayScanner = XrayApiScanner()

        val proxyDeferred = if (splitTunnelEnabled) {
            async {
                onProgress?.invoke(
                    Progress(
                        line = ProgressLine.BYPASS,
                        phase = context.getString(R.string.checker_bypass_progress_port_scan_phase),
                        detail = context.getString(R.string.checker_bypass_progress_port_scan_detail),
                    ),
                )
                if (scanPlan.mode == ScanMode.POPULAR_ONLY) {
                    scanner.findOpenProxyEndpoint(
                        mode = ScanMode.POPULAR_ONLY,
                        manualPort = null,
                        onProgress = { progress ->
                            val percent = if (progress.total > 0) (progress.scanned * 100 / progress.total) else 0
                            onProgress?.invoke(
                                Progress(
                                    line = ProgressLine.BYPASS,
                                    phase = context.getString(R.string.checker_bypass_progress_popular_ports),
                                    detail = context.getString(
                                        R.string.checker_bypass_progress_port_detail,
                                        progress.currentPort,
                                        percent,
                                    ),
                                ),
                            )
                        },
                    )
                } else {
                    scanner.findOpenProxyEndpoint(
                        mode = scanPlan.mode,
                        manualPort = null,
                        onProgress = { progress ->
                            val phaseText = when (progress.phase) {
                                ScanPhase.POPULAR_PORTS -> context.getString(R.string.checker_bypass_progress_popular_ports)
                                ScanPhase.FULL_RANGE -> context.getString(R.string.checker_bypass_progress_full_scan)
                            }
                            val percent = if (progress.total > 0) (progress.scanned * 100 / progress.total) else 0
                            onProgress?.invoke(
                                Progress(
                                    line = ProgressLine.BYPASS,
                                    phase = phaseText,
                                    detail = context.getString(
                                        R.string.checker_bypass_progress_port_detail,
                                        progress.currentPort,
                                        percent,
                                    ),
                                ),
                            )
                        },
                    )
                }
            }
        } else {
            null
        }

        val xrayDeferred = if (splitTunnelEnabled) {
            async {
                onProgress?.invoke(
                    Progress(
                        line = ProgressLine.XRAY_API,
                        phase = "Xray API",
                        detail = context.getString(R.string.checker_bypass_progress_xray_detail),
                    ),
                )
                xrayScanner.findXrayApi { progress ->
                    val percent = if (progress.total > 0) (progress.scanned * 100 / progress.total) else 0
                    onProgress?.invoke(
                        Progress(
                            line = ProgressLine.XRAY_API,
                            phase = "Xray API",
                            detail = "${progress.host}:${progress.currentPort} ($percent%)",
                        ),
                    )
                }
            }
        } else {
            null
        }

        val underlyingDeferred = if (splitTunnelEnabled) {
            async {
                onProgress?.invoke(
                    Progress(
                        line = ProgressLine.UNDERLYING_NETWORK,
                        phase = "Underlying network",
                        detail = context.getString(R.string.checker_bypass_progress_underlying_detail),
                    ),
                )
                UnderlyingNetworkProber.probe(context, resolverConfig)
            }
        } else {
            null
        }

        val callTransportDeferred = if (callTransportProbeEnabled) {
            async {
                onProgress?.invoke(
                    Progress(
                        line = ProgressLine.CALL_TRANSPORT,
                        phase = context.getString(R.string.checker_bypass_progress_call_transport_phase),
                        detail = context.getString(R.string.checker_bypass_progress_call_transport_detail),
                    ),
                )
                CallTransportLeakProber.probeDirect(
                    context = context,
                    resolverConfig = resolverConfig,
                    onProgress = { service, detail ->
                        onProgress?.invoke(
                            Progress(
                                line = ProgressLine.CALL_TRANSPORT,
                                phase = service,
                                detail = detail,
                            ),
                        )
                    },
                )
            }
        } else {
            null
        }

        val proxyEndpoint = proxyDeferred?.await()
        val xrayApiScanResult = xrayDeferred?.await()
        val underlyingResult = underlyingDeferred?.await() ?: UnderlyingNetworkProber.ProbeResult(
            vpnActive = false,
            underlyingReachable = false,
        )
        val proxyOwnerMatch = proxyEndpoint?.let { resolveProxyOwner(context, it) }
        val callTransportLeaks = mutableListOf<CallTransportLeakResult>()
        callTransportDeferred?.await()?.let(callTransportLeaks::addAll)

        if (splitTunnelEnabled) {
            reportProxyResult(context, proxyEndpoint, proxyOwnerMatch, findings, evidence)
            reportXrayApiResult(context, xrayApiScanResult, findings, evidence)
        }
        val underlyingEvaluation = if (splitTunnelEnabled) {
            reportUnderlyingNetworkResult(context, underlyingResult, findings, evidence)
        } else {
            UnderlyingEvaluation(detected = false, needsReview = false)
        }
        reportCallTransportResults(context, callTransportLeaks, findings, evidence)

        var directIp: String? = null
        var proxyIp: String? = null
        var confirmedBypass = false

        if (splitTunnelEnabled && proxyEndpoint != null) {
            onProgress?.invoke(
                Progress(
                    line = ProgressLine.BYPASS,
                    phase = context.getString(R.string.checker_bypass_progress_ip_phase),
                    detail = context.getString(R.string.checker_bypass_progress_ip_detail),
                ),
            )

            val directDeferred = async { IfconfigClient.fetchDirectIp(resolverConfig = resolverConfig) }
            val proxyIpDeferred = async {
                IfconfigClient.fetchIpViaProxy(proxyEndpoint, resolverConfig = resolverConfig)
            }

            directIp = directDeferred.await().getOrNull()
            proxyIp = proxyIpDeferred.await().getOrNull()

            val unavailable = context.getString(R.string.checker_bypass_ip_unavailable)
            findings.add(Finding(context.getString(R.string.checker_bypass_direct_ip, directIp ?: unavailable)))
            findings.add(Finding(context.getString(R.string.checker_bypass_proxy_ip, proxyIp ?: unavailable)))

            if (directIp != null && proxyIp != null && directIp != proxyIp) {
                confirmedBypass = true
                findings.add(
                    Finding(
                        description = context.getString(R.string.checker_bypass_split_confirmed),
                        detected = true,
                        source = EvidenceSource.SPLIT_TUNNEL_BYPASS,
                        confidence = EvidenceConfidence.HIGH,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.SPLIT_TUNNEL_BYPASS,
                        detected = true,
                        confidence = EvidenceConfidence.HIGH,
                        description = "Direct IP differs from proxy IP",
                    ),
                )
            } else if (directIp != null && proxyIp != null) {
                findings.add(Finding(context.getString(R.string.checker_bypass_split_disabled)))
            }

            // MTProto probe: if SOCKS5 proxy found but HTTP didn't work through it,
            // check if it forwards Telegram DC traffic (MTProto-only proxy like tg-ws-proxy).
            // Skip if the port is already identified as Xray/V2Ray — that proxy is a full SOCKS5
            // tunnel, not an MTProto-only one; failed IP fetch just means the test site was blocked.
            // Informational only — does not contribute to verdict scoring.
            val isXrayPort = VpnAppCatalog.familiesForPort(proxyEndpoint.port)
                .contains(VpnAppCatalog.FAMILY_XRAY)
            if (proxyEndpoint.type == ProxyType.SOCKS5 && proxyIp == null && !isXrayPort) {
                onProgress?.invoke(
                    Progress(
                        line = ProgressLine.BYPASS,
                        phase = "MTProto probe",
                        detail = context.getString(R.string.checker_bypass_progress_mtproto_detail),
                    ),
                )
                val mtResult = MtProtoProber.probe(proxyEndpoint.host, proxyEndpoint.port)
                if (mtResult.reachable) {
                    val addr = mtResult.targetAddress
                    val targetAddress = addr?.let { "${it.address.hostAddress}:${it.port}" }
                        ?: unavailable
                    findings.add(
                        Finding(
                            description = context.getString(
                                R.string.checker_bypass_mtproto_reachable,
                                formatHostPort(proxyEndpoint.host, proxyEndpoint.port),
                                targetAddress,
                            ),
                            detected = true,
                            source = EvidenceSource.LOCAL_PROXY,
                            confidence = EvidenceConfidence.HIGH,
                            family = VpnAppCatalog.FAMILY_TG_WS_PROXY,
                        ),
                    )
                } else {
                    findings.add(Finding(context.getString(R.string.checker_bypass_mtproto_unreachable)))
                }
            }
        }

        if (callTransportProbeEnabled && proxyEndpoint?.type == ProxyType.SOCKS5) {
            CallTransportLeakProber.probeProxyAssistedTelegram(
                context = context,
                proxyEndpoint = proxyEndpoint,
                resolverConfig = resolverConfig,
            ).forEach { proxyLeak ->
                callTransportLeaks += proxyLeak
                reportCallTransportResults(context, listOf(proxyLeak), findings, evidence)
            }
        }

        val detected = confirmedBypass || xrayApiScanResult != null || underlyingEvaluation.detected
        val needsReview = !detected && (
            proxyEndpoint != null ||
                underlyingEvaluation.needsReview ||
                callTransportLeaks.any { it.status == CallTransportStatus.NEEDS_REVIEW }
            )

        BypassResult(
            proxyEndpoint = proxyEndpoint,
            proxyOwner = proxyOwnerMatch?.owner,
            directIp = directIp,
            proxyIp = proxyIp,
            vpnNetworkIp = underlyingResult.vpnIp,
            underlyingIp = underlyingResult.underlyingIp,
            xrayApiScanResult = xrayApiScanResult,
            callTransportLeaks = callTransportLeaks,
            findings = findings,
            detected = detected,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    private fun reportCallTransportResults(
        context: Context,
        results: List<CallTransportLeakResult>,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ) {
        for (result in results) {
            when (result.status) {
                CallTransportStatus.NEEDS_REVIEW -> {
                    findings.add(
                        Finding(
                            description = result.summary,
                            needsReview = true,
                            source = result.service.toEvidenceSource(),
                            confidence = result.confidence ?: EvidenceConfidence.MEDIUM,
                        ),
                    )
                    evidence.add(
                        EvidenceItem(
                            source = result.service.toEvidenceSource(),
                            detected = true,
                            confidence = result.confidence ?: EvidenceConfidence.MEDIUM,
                            description = result.summary,
                            family = result.service.name,
                        ),
                    )
                }
                CallTransportStatus.ERROR -> {
                    findings.add(
                        Finding(
                            description = result.summary,
                            isError = true,
                            source = result.service.toEvidenceSource(),
                            confidence = result.confidence,
                        ),
                    )
                }
                CallTransportStatus.NO_SIGNAL,
                CallTransportStatus.UNSUPPORTED,
                -> Unit
            }
        }
    }

    private fun reportProxyResult(
        context: Context,
        proxyEndpoint: ProxyEndpoint?,
        proxyOwnerMatch: ProxyOwnerMatch?,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ) {
        if (proxyEndpoint == null) {
            findings.add(Finding(context.getString(R.string.checker_bypass_no_open_proxy)))
            return
        }

        val candidateFamilies = VpnAppCatalog.familiesForPort(proxyEndpoint.port)
        val familySuffix = candidateFamilies.takeIf { it.isNotEmpty() }?.joinToString()
        val description = buildString {
            append(
                context.getString(
                    R.string.checker_bypass_open_proxy,
                    proxyEndpoint.type.name,
                    formatHostPort(proxyEndpoint.host, proxyEndpoint.port),
                ),
            )
            if (!familySuffix.isNullOrBlank()) {
                append(" [")
                append(familySuffix)
                append("]")
            }
            append(formatOwnerSuffix(context, proxyOwnerMatch))
            append(context.getString(R.string.checker_bypass_open_proxy_review_suffix))
        }

        findings.add(
            Finding(
                description = description,
                needsReview = true,
                source = EvidenceSource.LOCAL_PROXY,
                confidence = EvidenceConfidence.MEDIUM,
                family = familySuffix,
                packageName = LocalProxyOwnerFormatter.packageName(proxyOwnerMatch?.owner),
            ),
        )
        evidence.add(
            EvidenceItem(
                source = EvidenceSource.LOCAL_PROXY,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = buildString {
                    append("Detected open ${proxyEndpoint.type.name} proxy at ${formatHostPort(proxyEndpoint.host, proxyEndpoint.port)}")
                    append(formatOwnerSuffix(context, proxyOwnerMatch))
                },
                family = familySuffix,
                packageName = LocalProxyOwnerFormatter.packageName(proxyOwnerMatch?.owner),
            ),
        )
    }

    private fun reportXrayApiResult(
        context: Context,
        xrayApiScanResult: XrayApiScanResult?,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ) {
        if (xrayApiScanResult == null) {
            findings.add(Finding(context.getString(R.string.checker_bypass_no_xray)))
            return
        }

        val ep = xrayApiScanResult.endpoint
        findings.add(
            Finding(
                description = context.getString(
                    R.string.checker_bypass_xray_api,
                    formatHostPort(ep.host, ep.port),
                ),
                detected = true,
                source = EvidenceSource.XRAY_API,
                confidence = EvidenceConfidence.HIGH,
                family = VpnAppCatalog.FAMILY_XRAY,
            ),
        )
        evidence.add(
            EvidenceItem(
                source = EvidenceSource.XRAY_API,
                detected = true,
                confidence = EvidenceConfidence.HIGH,
                description = "Detected Xray gRPC API at ${formatHostPort(ep.host, ep.port)}",
                family = VpnAppCatalog.FAMILY_XRAY,
            ),
        )

        for (outbound in xrayApiScanResult.outbounds.take(10)) {
            val detail = buildString {
                append("  ")
                append(outbound.tag)
                outbound.protocolName?.let { append(" [$it]") }
                if (outbound.address != null && outbound.port != null) {
                    append(" -> ${outbound.address}:${outbound.port}")
                }
                outbound.sni?.let { append(", sni=$it") }
            }
            findings.add(
                Finding(
                    description = detail,
                    detected = true,
                    source = EvidenceSource.XRAY_API,
                    confidence = EvidenceConfidence.HIGH,
                    family = VpnAppCatalog.FAMILY_XRAY,
                ),
            )
        }
        if (xrayApiScanResult.outbounds.size > 10) {
            val extraOutboundsCount = xrayApiScanResult.outbounds.size - 10
            findings.add(
                Finding(
                    description = context.resources.getQuantityString(
                        R.plurals.checker_bypass_extra_outbounds,
                        extraOutboundsCount,
                        extraOutboundsCount,
                    ),
                    detected = true,
                    source = EvidenceSource.XRAY_API,
                    confidence = EvidenceConfidence.HIGH,
                    family = VpnAppCatalog.FAMILY_XRAY,
                ),
            )
        }
    }

    internal fun reportUnderlyingNetworkResult(
        context: Context,
        result: UnderlyingNetworkProber.ProbeResult,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): UnderlyingEvaluation {
        if (!result.vpnActive) {
            findings.add(Finding(context.getString(R.string.checker_bypass_vpn_not_active)))
            return UnderlyingEvaluation(detected = false, needsReview = false)
        }

        var detected = false
        var needsReview = false
        val unavailable = context.getString(R.string.checker_bypass_ip_unavailable)
        val vpnIpLabel = result.vpnIp ?: unavailable
        val nonVpnIpLabel = result.underlyingIp ?: unavailable
        val ipComparison = compareIpFamilies(result.vpnIp, result.underlyingIp)
        val ipsAreDifferent = ipComparison == IpComparisonOutcome.DIFFERENT
        val hasComparableIps = ipComparison == IpComparisonOutcome.SAME
        val hasMixedFamilies = ipComparison == IpComparisonOutcome.FAMILY_MISMATCH
        val reviewSource = if (result.activeNetworkIsVpn == false) {
            EvidenceSource.VPN_NETWORK_BINDING
        } else {
            EvidenceSource.VPN_GATEWAY_LEAK
        }

        if (result.vpnIp != null) {
            findings.add(
                Finding(
                    description = context.getString(
                        R.string.checker_bypass_tun_probe_success,
                        result.vpnIp,
                    ),
                    isInformational = true,
                    source = EvidenceSource.TUN_ACTIVE_PROBE,
                ),
            )
        } else {
            val description = result.vpnError
                ?.takeIf { it.isNotBlank() }
                ?.let { context.getString(R.string.checker_bypass_tun_probe_failure_reason, it) }
                ?: context.getString(R.string.checker_bypass_tun_probe_failure)
            findings.add(
                Finding(
                    description = description,
                    isInformational = true,
                    source = EvidenceSource.TUN_ACTIVE_PROBE,
                ),
            )
        }

        if (result.activeNetworkIsVpn == false && result.underlyingIp != null) {
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_bypass_default_non_vpn_ip, result.underlyingIp),
                    isInformational = true,
                ),
            )
        }

        if (result.activeNetworkIsVpn == false) {
            when {
                ipsAreDifferent -> {
                    findings.add(
                        Finding(
                            description = context.getString(
                                R.string.checker_bypass_vpn_network_binding,
                                result.vpnIp,
                                result.underlyingIp,
                            ),
                            detected = true,
                            source = EvidenceSource.VPN_NETWORK_BINDING,
                            confidence = EvidenceConfidence.HIGH,
                        ),
                    )
                    evidence.add(
                        EvidenceItem(
                            source = EvidenceSource.VPN_NETWORK_BINDING,
                            detected = true,
                            confidence = EvidenceConfidence.HIGH,
                            description = "Bound VPN IP differs from the default non-VPN IP",
                        ),
                    )
                    detected = true
                }
                hasComparableIps -> {
                    val ipSuffix = result.underlyingIp?.let { " ($it)" }.orEmpty()
                    findings.add(
                        Finding(
                            description = context.getString(R.string.checker_bypass_underlying_same_ip, ipSuffix),
                            isInformational = true,
                            source = EvidenceSource.VPN_NETWORK_BINDING,
                        ),
                    )
                }
                hasMixedFamilies -> {
                    findings.add(
                        Finding(
                            description = context.getString(
                                R.string.checker_bypass_compare_family_mismatch,
                                vpnIpLabel,
                                nonVpnIpLabel,
                            ),
                            needsReview = true,
                            source = EvidenceSource.VPN_NETWORK_BINDING,
                            confidence = EvidenceConfidence.LOW,
                        ),
                    )
                    needsReview = true
                }
                result.vpnIp != null || result.underlyingIp != null -> {
                    findings.add(
                        Finding(
                            description = context.getString(
                                R.string.checker_bypass_compare_incomplete,
                                vpnIpLabel,
                                nonVpnIpLabel,
                            ),
                            needsReview = true,
                            source = EvidenceSource.VPN_NETWORK_BINDING,
                            confidence = EvidenceConfidence.LOW,
                        ),
                    )
                    needsReview = true
                }
            }

            return UnderlyingEvaluation(detected = detected, needsReview = needsReview)
        }

        if (!result.underlyingReachable) {
            val description = result.underlyingError
                ?.takeIf { it.isNotBlank() }
                ?.let { context.getString(R.string.checker_bypass_underlying_unreachable_reason, it) }
                ?: context.getString(R.string.checker_bypass_underlying_unreachable)
            findings.add(Finding(description))

            if (result.vpnIp == null) {
                findings.add(
                    Finding(
                        description = context.getString(
                            R.string.checker_bypass_compare_incomplete,
                            vpnIpLabel,
                            nonVpnIpLabel,
                        ),
                        needsReview = true,
                        source = reviewSource,
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
                needsReview = true
            }

            return UnderlyingEvaluation(detected = false, needsReview = needsReview)
        }

        if (ipsAreDifferent) {
            val description = context.getString(
                R.string.checker_bypass_gateway_leak,
                result.vpnIp,
                result.underlyingIp,
            )
            findings.add(
                Finding(
                    description = description,
                    detected = true,
                    source = EvidenceSource.VPN_GATEWAY_LEAK,
                    confidence = EvidenceConfidence.HIGH,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.VPN_GATEWAY_LEAK,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "App can reach internet bypassing VPN tunnel via underlying network",
                ),
            )
            return UnderlyingEvaluation(detected = true, needsReview = false)
        }

        when {
            hasComparableIps -> {
                val ipSuffix = result.underlyingIp?.let { " ($it)" }.orEmpty()
                val infoDescription = context.getString(R.string.checker_bypass_underlying_same_ip, ipSuffix)
                findings.add(
                    Finding(
                        description = infoDescription,
                        isInformational = true,
                        source = EvidenceSource.VPN_GATEWAY_LEAK,
                    ),
                )
            }
            hasMixedFamilies -> {
                findings.add(
                    Finding(
                        description = context.getString(
                            R.string.checker_bypass_compare_family_mismatch,
                            vpnIpLabel,
                            nonVpnIpLabel,
                        ),
                        needsReview = true,
                        source = reviewSource,
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
                needsReview = true
            }
            result.vpnIp != null || result.underlyingIp != null -> {
                findings.add(
                    Finding(
                        description = context.getString(
                            R.string.checker_bypass_compare_incomplete,
                            vpnIpLabel,
                            nonVpnIpLabel,
                        ),
                        needsReview = true,
                        source = reviewSource,
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
                needsReview = true
            }
        }

        return UnderlyingEvaluation(detected = detected, needsReview = needsReview)
    }

    private fun resolveProxyOwner(context: Context, proxyEndpoint: ProxyEndpoint): ProxyOwnerMatch {
        val listeners = LocalSocketInspector.collect(context, protocols = setOf("tcp", "tcp6"))
        return matchProxyOwner(proxyEndpoint, listeners)
    }

    internal fun matchProxyOwner(proxyEndpoint: ProxyEndpoint, listeners: List<LocalSocketListener>): ProxyOwnerMatch {
        val samePortListeners = listeners.filter { it.port == proxyEndpoint.port }
        val exactMatches = samePortListeners.filter { normalizeHost(it.host) == normalizeHost(proxyEndpoint.host) }
        if (exactMatches.size == 1) {
            return exactMatches.single().owner?.let { ProxyOwnerMatch(it, ProxyOwnerStatus.RESOLVED) }
                ?: ProxyOwnerMatch(status = ProxyOwnerStatus.UNRESOLVED)
        }
        if (exactMatches.size > 1) {
            return ProxyOwnerMatch(status = ProxyOwnerStatus.AMBIGUOUS)
        }

        val fallbackMatches = samePortListeners.filter { listener ->
            isAnyAddress(listener.host) || (isLoopback(listener.host) && isLoopback(proxyEndpoint.host))
        }
        return when (fallbackMatches.size) {
            1 -> fallbackMatches.single().owner?.let { ProxyOwnerMatch(it, ProxyOwnerStatus.RESOLVED) }
                ?: ProxyOwnerMatch(status = ProxyOwnerStatus.UNRESOLVED)
            0 -> ProxyOwnerMatch(status = ProxyOwnerStatus.UNRESOLVED)
            else -> ProxyOwnerMatch(status = ProxyOwnerStatus.AMBIGUOUS)
        }
    }

    private fun formatOwnerSuffix(context: Context, proxyOwnerMatch: ProxyOwnerMatch?): String {
        val ownerText = when (proxyOwnerMatch?.status) {
            ProxyOwnerStatus.RESOLVED -> proxyOwnerMatch.owner?.let { LocalProxyOwnerFormatter.format(context, it) }
            ProxyOwnerStatus.AMBIGUOUS -> context.getString(R.string.checker_proxy_owner_ambiguous)
            ProxyOwnerStatus.UNRESOLVED, null -> context.getString(R.string.checker_proxy_owner_unresolved)
        } ?: context.getString(R.string.checker_proxy_owner_unresolved)
        return context.getString(R.string.checker_proxy_owner_suffix, ownerText)
    }

    private fun normalizeHost(host: String): String = host.substringBefore('%').lowercase()

    private fun isAnyAddress(host: String): Boolean = host == "0.0.0.0" || host == "::" || host == ":::"

    private fun isLoopback(host: String): Boolean = host == "::1" || host.startsWith("127.")

    private fun compareIpFamilies(vpnIp: String?, underlyingIp: String?): IpComparisonOutcome {
        if (vpnIp == null || underlyingIp == null) {
            return IpComparisonOutcome.INCOMPLETE
        }
        val sameFamily = runCatching {
            InetAddress.getByName(vpnIp)::class.java == InetAddress.getByName(underlyingIp)::class.java
        }.getOrDefault(false)
        if (!sameFamily) {
            return IpComparisonOutcome.FAMILY_MISMATCH
        }
        return if (vpnIp == underlyingIp) IpComparisonOutcome.SAME else IpComparisonOutcome.DIFFERENT
    }

    private fun formatHostPort(host: String, port: Int): String {
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }

    private fun CallTransportService.toEvidenceSource(): EvidenceSource {
        return when (this) {
            CallTransportService.TELEGRAM -> EvidenceSource.TELEGRAM_CALL_TRANSPORT
            CallTransportService.WHATSAPP -> EvidenceSource.WHATSAPP_CALL_TRANSPORT
        }
    }
}
