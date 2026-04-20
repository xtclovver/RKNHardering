package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.LocalProxyOwnerFormatter
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.TunProbeDiagnosticsFormatter
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.LocalProxyCheckResult
import com.notcvnt.rknhardering.model.LocalProxyCheckStatus
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.LocalProxyOwnerStatus
import com.notcvnt.rknhardering.model.LocalProxySummaryReason
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.IfconfigClient
import com.notcvnt.rknhardering.probe.LocalSocketInspector
import com.notcvnt.rknhardering.probe.LocalSocketListener
import com.notcvnt.rknhardering.probe.MtProtoProber
import com.notcvnt.rknhardering.probe.PortScanPlanner
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.PublicIpNetworkComparison
import com.notcvnt.rknhardering.probe.PublicIpProbeMode
import com.notcvnt.rknhardering.probe.PublicIpProbeStatus
import com.notcvnt.rknhardering.probe.ProxyScanner
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.ScanMode
import com.notcvnt.rknhardering.probe.ScanPhase
import com.notcvnt.rknhardering.probe.TunProbeResolveStrategy
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayApiScanner
import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.net.InetAddress

object BypassChecker {

    internal data class UnderlyingEvaluation(
        val detected: Boolean,
        val needsReview: Boolean,
    )

    internal data class ProxyOwnerMatch(
        val owner: LocalProxyOwner? = null,
        val status: LocalProxyOwnerStatus,
    )

    internal data class ProxyScanEvaluation(
        val directIp: String? = null,
        val summaryProxyEndpoint: ProxyEndpoint? = null,
        val summaryProxyOwner: LocalProxyOwner? = null,
        val summaryProxyIp: String? = null,
        val proxyChecks: List<LocalProxyCheckResult> = emptyList(),
        val confirmedBypass: Boolean = false,
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
        proxyScanEnabled: Boolean = true,
        xrayApiScanEnabled: Boolean = true,
        portRange: String = "full",
        portRangeStart: Int = 1024,
        portRangeEnd: Int = 65535,
        underlyingProbeDeferred: Deferred<UnderlyingNetworkProber.ProbeResult>? = null,
        onProgress: (suspend (Progress) -> Unit)? = null,
    ): BypassResult = coroutineScope {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val localScanEnabled = proxyScanEnabled || xrayApiScanEnabled
        val scanPlan = if (splitTunnelEnabled && localScanEnabled) {
            PortScanPlanner.buildExecutionPlan(
                portRange = portRange,
                portRangeStart = portRangeStart,
                portRangeEnd = portRangeEnd,
            )
        } else {
            null
        }

        val scanner = scanPlan?.let {
            ProxyScanner(
                popularPorts = it.popularPorts,
                scanRange = it.scanRange,
            )
        }
        val xrayScanner = scanPlan?.let {
            when (it.mode) {
                ScanMode.POPULAR_ONLY -> XrayApiScanner(
                    scanPorts = XrayApiScanner.DEFAULT_POPULAR_PORTS,
                )
                else -> XrayApiScanner(
                    scanRange = it.scanRange,
                )
            }
        }

        val proxyDeferred = if (splitTunnelEnabled && proxyScanEnabled && scanPlan != null && scanner != null) {
            async {
                onProgress?.invoke(
                    Progress(
                        line = ProgressLine.BYPASS,
                        phase = context.getString(R.string.checker_bypass_progress_port_scan_phase),
                        detail = context.getString(R.string.checker_bypass_progress_port_scan_detail),
                    ),
                )
                if (scanPlan.mode == ScanMode.POPULAR_ONLY) {
                    scanner.findOpenProxyEndpoints(
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
                    scanner.findOpenProxyEndpoints(
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

        val xrayDeferred = if (splitTunnelEnabled && xrayApiScanEnabled && xrayScanner != null) {
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
            underlyingProbeDeferred ?: async {
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

        val proxyEndpoints = proxyDeferred?.await().orEmpty()
        val xrayApiScanResult = xrayDeferred?.await()
        val underlyingResult = underlyingDeferred?.await() ?: UnderlyingNetworkProber.ProbeResult(
            vpnActive = false,
            underlyingReachable = false,
        )

        val proxyEvaluation = if (splitTunnelEnabled && proxyScanEnabled) {
            evaluateProxyEndpoints(
                context = context,
                resolverConfig = resolverConfig,
                proxyEndpoints = proxyEndpoints,
                findings = findings,
                evidence = evidence,
                onProgress = onProgress,
            )
        } else {
            ProxyScanEvaluation()
        }
        if (splitTunnelEnabled && xrayApiScanEnabled) {
            reportXrayApiResult(context, xrayApiScanResult, findings, evidence)
        }
        val underlyingEvaluation = if (splitTunnelEnabled) {
            reportUnderlyingNetworkResult(context, underlyingResult, findings, evidence)
        } else {
            UnderlyingEvaluation(detected = false, needsReview = false)
        }

        val detected = proxyEvaluation.confirmedBypass || xrayApiScanResult != null || underlyingEvaluation.detected
        val needsReview = !detected && (
            proxyEvaluation.proxyChecks.isNotEmpty() ||
                underlyingEvaluation.needsReview
            )

        BypassResult(
            proxyEndpoint = proxyEvaluation.summaryProxyEndpoint,
            proxyOwner = proxyEvaluation.summaryProxyOwner,
            directIp = proxyEvaluation.directIp,
            proxyIp = proxyEvaluation.summaryProxyIp,
            vpnNetworkIp = underlyingResult.vpnIp,
            underlyingIp = underlyingResult.underlyingIp,
            xrayApiScanResult = xrayApiScanResult,
            proxyChecks = proxyEvaluation.proxyChecks,
            findings = findings,
            detected = detected,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    internal suspend fun evaluateProxyEndpoints(
        context: Context,
        resolverConfig: DnsResolverConfig,
        proxyEndpoints: List<ProxyEndpoint>,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        onProgress: (suspend (Progress) -> Unit)? = null,
        fetchDirectIp: suspend () -> Result<String> = {
            IfconfigClient.fetchDirectIp(resolverConfig = resolverConfig)
        },
        fetchProxyIp: suspend (ProxyEndpoint) -> Result<String> = { endpoint ->
            IfconfigClient.fetchIpViaProxy(endpoint, resolverConfig = resolverConfig)
        },
        resolveProxyOwnerMatch: suspend (ProxyEndpoint) -> ProxyOwnerMatch = { endpoint ->
            resolveProxyOwner(context, endpoint)
        },
        probeMtProto: suspend (ProxyEndpoint) -> MtProtoProber.ProbeResult = { endpoint ->
            MtProtoProber.probe(endpoint.host, endpoint.port)
        },
    ): ProxyScanEvaluation {
        if (proxyEndpoints.isEmpty()) {
            reportProxyResults(context, directIp = null, proxyChecks = emptyList(), findings = findings, evidence = evidence)
            return ProxyScanEvaluation()
        }

        onProgress?.invoke(
            Progress(
                line = ProgressLine.BYPASS,
                phase = context.getString(R.string.checker_bypass_progress_ip_phase),
                detail = context.getString(R.string.checker_bypass_progress_ip_detail),
            ),
        )

        val directIp = fetchDirectIp().getOrNull()
        val rawChecks = mutableListOf<LocalProxyCheckResult>()

        for (proxyEndpoint in proxyEndpoints) {
            val proxyOwnerMatch = resolveProxyOwnerMatch(proxyEndpoint)
            val proxyIp = fetchProxyIp(proxyEndpoint).getOrNull()

            val isXrayPort = VpnAppCatalog.familiesForPort(proxyEndpoint.port)
                .contains(VpnAppCatalog.FAMILY_XRAY)
            val mtProtoResult = if (proxyEndpoint.type == ProxyType.SOCKS5 && proxyIp == null && !isXrayPort) {
                onProgress?.invoke(
                    Progress(
                        line = ProgressLine.BYPASS,
                        phase = "MTProto probe",
                        detail = context.getString(R.string.checker_bypass_progress_mtproto_detail),
                    ),
                )
                probeMtProto(proxyEndpoint)
            } else {
                null
            }

            val status = when {
                directIp == null -> LocalProxyCheckStatus.DIRECT_IP_UNAVAILABLE
                proxyIp == null -> LocalProxyCheckStatus.PROXY_IP_UNAVAILABLE
                directIp != proxyIp -> LocalProxyCheckStatus.CONFIRMED_BYPASS
                else -> LocalProxyCheckStatus.SAME_IP
            }

            rawChecks += LocalProxyCheckResult(
                endpoint = proxyEndpoint,
                owner = proxyOwnerMatch.owner,
                ownerStatus = proxyOwnerMatch.status,
                proxyIp = proxyIp,
                status = status,
                mtProtoReachable = mtProtoResult?.reachable,
                mtProtoTarget = mtProtoResult?.targetAddress?.let { "${it.address.hostAddress}:${it.port}" },
            )
        }

        val summarySelection = when {
            rawChecks.any { it.status == LocalProxyCheckStatus.CONFIRMED_BYPASS } ->
                rawChecks.indexOfFirst { it.status == LocalProxyCheckStatus.CONFIRMED_BYPASS } to
                    LocalProxySummaryReason.CONFIRMED_BYPASS
            rawChecks.any { it.proxyIp != null } ->
                rawChecks.indexOfFirst { it.proxyIp != null } to LocalProxySummaryReason.FIRST_WITH_PROXY_IP
            rawChecks.isNotEmpty() -> 0 to LocalProxySummaryReason.FIRST_DISCOVERED
            else -> null
        }

        val proxyChecks = rawChecks.mapIndexed { index, check ->
            if (summarySelection != null && index == summarySelection.first) {
                check.copy(summaryReason = summarySelection.second)
            } else {
                check
            }
        }

        reportProxyResults(context, directIp = directIp, proxyChecks = proxyChecks, findings = findings, evidence = evidence)

        val summaryCheck = summarySelection?.first?.let(proxyChecks::get)
        return ProxyScanEvaluation(
            directIp = directIp,
            summaryProxyEndpoint = summaryCheck?.endpoint,
            summaryProxyOwner = summaryCheck?.owner,
            summaryProxyIp = summaryCheck?.proxyIp,
            proxyChecks = proxyChecks,
            confirmedBypass = proxyChecks.any { it.status == LocalProxyCheckStatus.CONFIRMED_BYPASS },
        )
    }

    private fun reportProxyResults(
        context: Context,
        directIp: String?,
        proxyChecks: List<LocalProxyCheckResult>,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ) {
        if (proxyChecks.isEmpty()) {
            findings.add(Finding(context.getString(R.string.checker_bypass_no_open_proxy)))
            return
        }

        val unavailable = context.getString(R.string.checker_bypass_ip_unavailable)
        findings.add(Finding(context.getString(R.string.checker_bypass_direct_ip, directIp ?: unavailable)))

        proxyChecks.forEach { proxyCheck ->
            reportProxyCheck(context, proxyCheck, findings, evidence, unavailable)
        }
    }

    private fun reportProxyCheck(
        context: Context,
        proxyCheck: LocalProxyCheckResult,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        unavailable: String,
    ) {
        val proxyEndpoint = proxyCheck.endpoint
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
            append(formatOwnerSuffix(context, proxyCheck.owner, proxyCheck.ownerStatus))
            if (proxyCheck.status != LocalProxyCheckStatus.CONFIRMED_BYPASS) {
                append(context.getString(R.string.checker_bypass_open_proxy_review_suffix))
            }
        }

        findings.add(
            Finding(
                description = description,
                needsReview = proxyCheck.status != LocalProxyCheckStatus.CONFIRMED_BYPASS,
                source = EvidenceSource.LOCAL_PROXY,
                confidence = EvidenceConfidence.MEDIUM,
                family = familySuffix,
                packageName = LocalProxyOwnerFormatter.packageName(proxyCheck.owner),
            ),
        )
        evidence.add(
            EvidenceItem(
                source = EvidenceSource.LOCAL_PROXY,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = buildString {
                    append("Detected open ${proxyEndpoint.type.name} proxy at ${formatHostPort(proxyEndpoint.host, proxyEndpoint.port)}")
                    append(formatOwnerSuffix(context, proxyCheck.owner, proxyCheck.ownerStatus))
                },
                family = familySuffix,
                packageName = LocalProxyOwnerFormatter.packageName(proxyCheck.owner),
            ),
        )

        findings.add(Finding(context.getString(R.string.checker_bypass_proxy_ip, proxyCheck.proxyIp ?: unavailable)))

        when (proxyCheck.status) {
            LocalProxyCheckStatus.CONFIRMED_BYPASS -> {
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
                        description = "Direct IP differs from proxy IP at ${formatHostPort(proxyEndpoint.host, proxyEndpoint.port)}",
                    ),
                )
            }
            LocalProxyCheckStatus.SAME_IP -> {
                findings.add(Finding(context.getString(R.string.checker_bypass_split_disabled)))
            }
            LocalProxyCheckStatus.PROXY_IP_UNAVAILABLE,
            LocalProxyCheckStatus.DIRECT_IP_UNAVAILABLE,
            -> Unit
        }

        when (proxyCheck.mtProtoReachable) {
            true -> {
                findings.add(
                    Finding(
                        description = context.getString(
                            R.string.checker_bypass_mtproto_reachable,
                            formatHostPort(proxyEndpoint.host, proxyEndpoint.port),
                            proxyCheck.mtProtoTarget ?: unavailable,
                        ),
                        detected = true,
                        source = EvidenceSource.LOCAL_PROXY,
                        confidence = EvidenceConfidence.HIGH,
                        family = VpnAppCatalog.FAMILY_TG_WS_PROXY,
                    ),
                )
            }
            false -> findings.add(Finding(context.getString(R.string.checker_bypass_mtproto_unreachable)))
            null -> Unit
        }
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

        if (result.activeNetworkIsVpn == false && result.underlyingIp != null) {
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_bypass_default_non_vpn_ip, result.underlyingIp),
                    isInformational = true,
                ),
            )
        }
        val usedTransportOnlyFallback = addTransportOnlyFinding(context, result, findings)
        addDebugTunProbeFindings(context, result, findings)

        if (result.activeNetworkIsVpn == false) {
            when {
                ipsAreDifferent -> {
                    if (usedTransportOnlyFallback) {
                        findings.add(
                            Finding(
                                description = context.getString(
                                    R.string.checker_bypass_vpn_network_binding,
                                    result.vpnIp,
                                    result.underlyingIp,
                                ),
                                needsReview = true,
                                source = EvidenceSource.VPN_NETWORK_BINDING,
                                confidence = EvidenceConfidence.LOW,
                            ),
                        )
                        needsReview = true
                    } else {
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
            if (usedTransportOnlyFallback) {
                findings.add(
                    Finding(
                        description = description,
                        needsReview = true,
                        source = EvidenceSource.VPN_GATEWAY_LEAK,
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
                return UnderlyingEvaluation(detected = false, needsReview = true)
            }
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

    private fun addTransportOnlyFinding(
        context: Context,
        result: UnderlyingNetworkProber.ProbeResult,
        findings: MutableList<Finding>,
    ): Boolean {
        val pathLabels = mutableListOf<String>()
        var usesInjectedResolve = false
        val vpnComparison = result.vpnIpComparison
        if (
            result.vpnIp != null &&
            vpnComparison?.usedCurlCompatibleFallback() == true
        ) {
            pathLabels += context.getString(R.string.checker_bypass_transport_only_vpn_path)
            usesInjectedResolve = usesInjectedResolve ||
                vpnComparison.curlCompatible.transportDiagnostics.resolveStrategy ==
                TunProbeResolveStrategy.KOTLIN_INJECTED
        }
        val underlyingComparison = result.underlyingIpComparison
        if (
            result.underlyingIp != null &&
            underlyingComparison?.usedCurlCompatibleFallback() == true
        ) {
            pathLabels += context.getString(R.string.checker_bypass_transport_only_underlying_path)
            usesInjectedResolve = usesInjectedResolve ||
                underlyingComparison.curlCompatible.transportDiagnostics.resolveStrategy ==
                TunProbeResolveStrategy.KOTLIN_INJECTED
        }
        if (pathLabels.isEmpty()) return false

        findings.add(
            Finding(
                description = context.getString(
                    if (usesInjectedResolve) {
                        R.string.checker_bypass_curl_compatible_used
                    } else {
                        R.string.checker_bypass_transport_only_used
                    },
                    pathLabels.joinToString(", "),
                ),
                isInformational = true,
            ),
        )
        return true
    }

    private fun addDebugTunProbeFindings(
        context: Context,
        result: UnderlyingNetworkProber.ProbeResult,
        findings: MutableList<Finding>,
    ) {
        val diagnostics = result.tunProbeDiagnostics ?: return
        diagnostics.vpnPath?.let { vpnPath ->
            findings.add(
                Finding(
                    description = TunProbeDiagnosticsFormatter.formatUiSummary(
                        context = context,
                        pathLabel = context.getString(R.string.checker_tun_probe_path_vpn),
                        modeOverride = diagnostics.modeOverride,
                        path = vpnPath,
                    ),
                    isInformational = true,
                ),
            )
        }
        diagnostics.underlyingPath?.let { underlyingPath ->
            findings.add(
                Finding(
                    description = TunProbeDiagnosticsFormatter.formatUiSummary(
                        context = context,
                        pathLabel = context.getString(R.string.checker_tun_probe_path_underlying),
                        modeOverride = diagnostics.modeOverride,
                        path = underlyingPath,
                    ),
                    isInformational = true,
                ),
            )
        }
    }

    private fun resolveProxyOwner(context: Context, proxyEndpoint: ProxyEndpoint): ProxyOwnerMatch {
        val listeners = LocalSocketInspector.collect(context, protocols = setOf("tcp", "tcp6"))
        return matchProxyOwner(proxyEndpoint, listeners)
    }

    internal fun matchProxyOwner(proxyEndpoint: ProxyEndpoint, listeners: List<LocalSocketListener>): ProxyOwnerMatch {
        val samePortListeners = listeners.filter { it.port == proxyEndpoint.port }
        val exactMatches = samePortListeners.filter { normalizeHost(it.host) == normalizeHost(proxyEndpoint.host) }
        if (exactMatches.size == 1) {
            return exactMatches.single().owner?.let { ProxyOwnerMatch(it, LocalProxyOwnerStatus.RESOLVED) }
                ?: ProxyOwnerMatch(status = LocalProxyOwnerStatus.UNRESOLVED)
        }
        if (exactMatches.size > 1) {
            return ProxyOwnerMatch(status = LocalProxyOwnerStatus.AMBIGUOUS)
        }

        val fallbackMatches = samePortListeners.filter { listener ->
            isAnyAddress(listener.host) || (isLoopback(listener.host) && isLoopback(proxyEndpoint.host))
        }
        return when (fallbackMatches.size) {
            1 -> fallbackMatches.single().owner?.let { ProxyOwnerMatch(it, LocalProxyOwnerStatus.RESOLVED) }
                ?: ProxyOwnerMatch(status = LocalProxyOwnerStatus.UNRESOLVED)
            0 -> ProxyOwnerMatch(status = LocalProxyOwnerStatus.UNRESOLVED)
            else -> ProxyOwnerMatch(status = LocalProxyOwnerStatus.AMBIGUOUS)
        }
    }

    private fun formatOwnerSuffix(context: Context, proxyOwnerMatch: ProxyOwnerMatch?): String {
        return formatOwnerSuffix(
            context = context,
            owner = proxyOwnerMatch?.owner,
            status = proxyOwnerMatch?.status ?: LocalProxyOwnerStatus.UNRESOLVED,
        )
    }

    private fun formatOwnerSuffix(
        context: Context,
        owner: LocalProxyOwner?,
        status: LocalProxyOwnerStatus,
    ): String {
        val ownerText = when (status) {
            LocalProxyOwnerStatus.RESOLVED -> owner?.let { LocalProxyOwnerFormatter.format(context, it) }
            LocalProxyOwnerStatus.AMBIGUOUS -> context.getString(R.string.checker_proxy_owner_ambiguous)
            LocalProxyOwnerStatus.UNRESOLVED -> context.getString(R.string.checker_proxy_owner_unresolved)
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
}
