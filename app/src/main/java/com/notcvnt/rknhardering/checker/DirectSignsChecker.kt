package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Proxy
import android.net.ProxyInfo
import android.os.Build
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.TunProbeDiagnosticsFormatter
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer
import com.notcvnt.rknhardering.probe.PublicIpProbeMode
import com.notcvnt.rknhardering.probe.TunProbeResolveStrategy
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import com.notcvnt.rknhardering.vpn.InstalledVpnAppDetector

object DirectSignsChecker {

    private data class SignalOutcome(
        val detected: Boolean = false,
        val needsReview: Boolean = false,
    )

    internal data class ProxyProfileSnapshot(
        val interfaceName: String? = null,
        val isDefault: Boolean = false,
        val host: String? = null,
        val port: Int? = null,
        val pacUrl: String? = null,
        val exclusions: List<String> = emptyList(),
        val valid: Boolean = true,
    )

    internal data class ProxyProfileCollection(
        val defaultProfile: ProxyProfileSnapshot? = null,
        val defaultError: String? = null,
        val networkProfiles: List<ProxyProfileSnapshot> = emptyList(),
        val networkError: String? = null,
    )

    private data class ProxyProfileEvaluation(
        val detected: Boolean,
        val needsReview: Boolean,
        val confidence: EvidenceConfidence,
        val hasEndpoint: Boolean,
        val knownPort: Boolean,
    )

    private val KNOWN_PROXY_PORTS = setOf(
        80, 443, 1080, 3127, 3128, 4080, 5555,
        7000, 7044, 8000, 8080, 8081, 8082, 8888,
        9000, 9050, 9051, 9150, 12345,
    )
    private val KNOWN_PROXY_PORT_RANGES = listOf(16000..16100)

    fun check(
        context: Context,
        tunActiveProbeResult: UnderlyingNetworkProber.ProbeResult? = null,
    ): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        val matchedApps = mutableListOf<MatchedVpnApp>()
        var detected = false
        var needsReview = false

        val vpnTransportOutcome = checkVpnTransport(context, findings, evidence)
        detected = detected || vpnTransportOutcome.detected
        needsReview = needsReview || vpnTransportOutcome.needsReview

        val systemProxyOutcome = checkSystemProxy(context, findings, evidence)
        detected = detected || systemProxyOutcome.detected
        needsReview = needsReview || systemProxyOutcome.needsReview

        tunActiveProbeResult
            ?.takeIf { it.vpnActive }
            ?.let { result ->
                addDebugTunProbeFinding(context, result, findings)
                val tunActiveProbeOutcome = reportTunActiveProbe(context, result, findings, evidence)
                detected = detected || tunActiveProbeOutcome.detected
                needsReview = needsReview || tunActiveProbeOutcome.needsReview
            }

        val appDetection = InstalledVpnAppDetector.detect(context)
        findings += appDetection.findings
        evidence += appDetection.evidence
        matchedApps += appDetection.matchedApps

        return CategoryResult(
            name = context.getString(R.string.checker_direct_category_name),
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
            matchedApps = matchedApps,
        )
    }

    private fun checkVpnTransport(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        if (activeNetwork == null) {
            findings.add(Finding(context.getString(R.string.checker_direct_no_active_network)))
            return SignalOutcome()
        }

        val caps = cm.getNetworkCapabilities(activeNetwork)
        if (caps == null) {
            findings.add(Finding(context.getString(R.string.checker_direct_caps_unavailable)))
            return SignalOutcome()
        }

        var detected = false
        val hasVpnTransport = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        findings.add(
            Finding(
                description = context.getString(
                    R.string.checker_direct_transport_vpn,
                    context.getString(
                        if (hasVpnTransport) R.string.checker_direct_detected
                        else R.string.checker_direct_not_detected,
                    ),
                ),
                detected = hasVpnTransport,
                source = EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
                confidence = hasVpnTransport.takeIf { it }?.let { EvidenceConfidence.HIGH },
            ),
        )
        if (hasVpnTransport) {
            detected = true
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "Active network reports TRANSPORT_VPN",
                ),
            )
        }

        val capsString = caps.toString()
        val hasIsVpn = capsString.contains("IS_VPN")
        if (hasIsVpn) {
            detected = true
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_direct_flag_is_vpn),
                    detected = true,
                    source = EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
                    confidence = EvidenceConfidence.HIGH,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "NetworkCapabilities string contains IS_VPN",
                ),
            )
        }

        val hasVpnTransportInfo = capsString.contains("VpnTransportInfo")
        if (hasVpnTransportInfo) {
            detected = true
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_direct_vpn_transport_info),
                    detected = true,
                    source = EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
                    confidence = EvidenceConfidence.HIGH,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "NetworkCapabilities string contains VpnTransportInfo",
                ),
            )
        }

        return SignalOutcome(detected = detected)
    }

    @Suppress("DEPRECATION")
    private fun checkSystemProxy(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val httpHost = System.getProperty("http.proxyHost") ?: Proxy.getDefaultHost()
        val httpPort = System.getProperty("http.proxyPort")
            ?: Proxy.getDefaultPort().takeIf { it > 0 }?.toString()
        val socksHost = System.getProperty("socksProxyHost")
        val socksPort = System.getProperty("socksProxyPort")
        var detected = false
        var needsReview = false

        val httpOutcome = addProxyFinding(
            context = context,
            type = context.getString(R.string.checker_direct_http_proxy),
            host = httpHost,
            port = httpPort,
            findings = findings,
            evidence = evidence,
        )
        detected = detected || httpOutcome.detected
        needsReview = needsReview || httpOutcome.needsReview

        val socksOutcome = addProxyFinding(
            context = context,
            type = context.getString(R.string.checker_direct_socks_proxy),
            host = socksHost,
            port = socksPort,
            findings = findings,
            evidence = evidence,
        )
        detected = detected || socksOutcome.detected
        needsReview = needsReview || socksOutcome.needsReview

        val proxyInfoResult = evaluateProxyProfileCollection(context, collectProxyInfoProfiles(context))
        findings += proxyInfoResult.findings
        evidence += proxyInfoResult.evidence
        detected = detected || proxyInfoResult.detected
        needsReview = needsReview || proxyInfoResult.needsReview

        return SignalOutcome(detected = detected, needsReview = needsReview)
    }

    private fun collectProxyInfoProfiles(context: Context): ProxyProfileCollection {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        var defaultProfile: ProxyProfileSnapshot? = null
        var defaultError: String? = null
        val networkProfiles = mutableListOf<ProxyProfileSnapshot>()
        var networkError: String? = null

        runCatching {
            defaultProfile = cm.defaultProxy?.let { proxyInfo ->
                proxyProfileSnapshot(proxyInfo = proxyInfo, isDefault = true)
            }
        }.onFailure { error ->
            defaultError = error.renderMessage()
        }

        runCatching {
            val activeNetwork = cm.activeNetwork

            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network)
                val isTracked = network == activeNetwork ||
                    caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
                if (!isTracked) continue

                val linkProperties = cm.getLinkProperties(network) ?: continue
                val proxyInfo = linkProperties.httpProxy ?: continue

                networkProfiles += proxyProfileSnapshot(
                    proxyInfo = proxyInfo,
                    interfaceName = NetworkInterfaceNameNormalizer.canonicalName(linkProperties.interfaceName),
                )
            }
        }.onFailure { error ->
            networkError = error.renderMessage()
        }

        return ProxyProfileCollection(
            defaultProfile = defaultProfile,
            defaultError = defaultError,
            networkProfiles = networkProfiles,
            networkError = networkError,
        )
    }

    private fun proxyProfileSnapshot(
        proxyInfo: ProxyInfo,
        isDefault: Boolean = false,
        interfaceName: String? = null,
    ): ProxyProfileSnapshot {
        return ProxyProfileSnapshot(
            interfaceName = interfaceName,
            isDefault = isDefault,
            host = proxyInfo.host?.takeUnless { it.isBlank() },
            port = proxyInfo.port,
            pacUrl = proxyInfo.pacFileUrl
                ?.toString()
                ?.takeUnless { it.isBlank() || it == "null" },
            exclusions = proxyInfo.exclusionList
                ?.map(String::trim)
                ?.filter(String::isNotEmpty)
                .orEmpty(),
            valid = Build.VERSION.SDK_INT < Build.VERSION_CODES.R || proxyInfo.isValid(),
        )
    }

    private fun addProxyFinding(
        context: Context,
        type: String,
        host: String?,
        port: String?,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        if (host.isNullOrBlank()) {
            findings.add(Finding(context.getString(R.string.checker_direct_proxy_not_configured, type)))
            return SignalOutcome()
        }

        val validPort = port?.toIntOrNull()?.takeIf { it > 0 }
        val knownPort = isKnownProxyPort(port)
        val hasEndpoint = validPort != null
        val confidence = when {
            hasEndpoint && knownPort -> EvidenceConfidence.MEDIUM
            hasEndpoint -> EvidenceConfidence.LOW
            else -> EvidenceConfidence.LOW
        }
        val description = context.getString(
            R.string.checker_direct_proxy_endpoint,
            type,
            host,
            port ?: "N/A",
        )

        findings.add(
            Finding(
                description = description,
                detected = hasEndpoint,
                needsReview = !hasEndpoint,
                source = EvidenceSource.SYSTEM_PROXY,
                confidence = confidence,
            ),
        )
        evidence.add(
            EvidenceItem(
                source = EvidenceSource.SYSTEM_PROXY,
                detected = hasEndpoint,
                confidence = confidence,
                description = description,
            ),
        )

        if (hasEndpoint && knownPort) {
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_direct_proxy_known_port, type, port),
                    detected = true,
                    source = EvidenceSource.SYSTEM_PROXY,
                    confidence = EvidenceConfidence.MEDIUM,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.SYSTEM_PROXY,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "$type uses known proxy port $port",
                ),
            )
        }

        if (!hasEndpoint) {
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_direct_proxy_no_valid_port, type),
                    needsReview = true,
                    source = EvidenceSource.SYSTEM_PROXY,
                    confidence = EvidenceConfidence.LOW,
                ),
            )
        }

        return SignalOutcome(detected = hasEndpoint, needsReview = !hasEndpoint)
    }

    internal fun evaluateProxyProfileCollection(
        context: Context,
        collection: ProxyProfileCollection,
    ): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false
        var needsReview = false

        when {
            collection.defaultError != null -> {
                findings += proxyAvailabilityFinding(
                    context = context,
                    label = context.getString(R.string.checker_direct_proxyinfo_default),
                    errorMessage = collection.defaultError,
                )
                needsReview = true
            }
            collection.defaultProfile != null -> {
                val outcome = addProxyProfileFinding(
                    context = context,
                    profile = collection.defaultProfile,
                    findings = findings,
                    evidence = evidence,
                )
                detected = detected || outcome.detected
                needsReview = needsReview || outcome.needsReview
            }
            else -> {
                findings += Finding(
                    context.getString(
                        R.string.checker_direct_proxy_not_configured,
                        context.getString(R.string.checker_direct_proxyinfo_default),
                    ),
                )
            }
        }

        if (collection.networkProfiles.isEmpty() && collection.networkError == null) {
            findings += Finding(context.getString(R.string.checker_direct_proxyinfo_network_none))
        } else {
            for (profile in collection.networkProfiles) {
                val outcome = addProxyProfileFinding(
                    context = context,
                    profile = profile,
                    findings = findings,
                    evidence = evidence,
                )
                detected = detected || outcome.detected
                needsReview = needsReview || outcome.needsReview
            }
        }

        if (collection.networkError != null) {
            findings += proxyAvailabilityFinding(
                context = context,
                label = context.getString(R.string.checker_direct_proxyinfo_network_scan),
                errorMessage = collection.networkError,
            )
            needsReview = true
        }

        return CategoryResult(
            name = context.getString(R.string.checker_direct_category_name),
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    private fun addProxyProfileFinding(
        context: Context,
        profile: ProxyProfileSnapshot,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val label = proxyProfileLabel(context, profile)
        val evaluation = evaluateProxyProfile(profile)
        val details = proxyProfileDetails(profile)
        val description = when {
            !profile.valid -> {
                val base = context.getString(R.string.checker_direct_proxyinfo_invalid, label)
                appendProxyProfileDetails(base, details)
            }
            evaluation.detected || evaluation.needsReview -> context.getString(
                R.string.checker_direct_proxyinfo_details,
                label,
                details,
            )
            else -> context.getString(R.string.checker_direct_proxy_not_configured, label)
        }

        findings += Finding(
            description = description,
            detected = evaluation.detected,
            needsReview = evaluation.needsReview,
            source = EvidenceSource.SYSTEM_PROXY,
            confidence = (evaluation.detected || evaluation.needsReview)
                .takeIf { it }
                ?.let { evaluation.confidence },
        )

        if (evaluation.detected || evaluation.needsReview) {
            evidence += EvidenceItem(
                source = EvidenceSource.SYSTEM_PROXY,
                detected = evaluation.detected,
                confidence = evaluation.confidence,
                description = description,
            )
        }

        if (evaluation.detected && evaluation.hasEndpoint && evaluation.knownPort) {
            val rawPort = profile.port?.toString() ?: return SignalOutcome(
                detected = evaluation.detected,
                needsReview = evaluation.needsReview,
            )
            findings += Finding(
                description = context.getString(R.string.checker_direct_proxy_known_port, label, rawPort),
                detected = true,
                source = EvidenceSource.SYSTEM_PROXY,
                confidence = EvidenceConfidence.MEDIUM,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.SYSTEM_PROXY,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = "$label uses known proxy port $rawPort",
            )
        }

        return SignalOutcome(
            detected = evaluation.detected,
            needsReview = evaluation.needsReview,
        )
    }

    private fun evaluateProxyProfile(profile: ProxyProfileSnapshot): ProxyProfileEvaluation {
        val hasHost = !profile.host.isNullOrBlank()
        val validPort = profile.port?.takeIf { it > 0 }
        val hasPac = !profile.pacUrl.isNullOrBlank()
        val hasEndpoint = hasHost && validPort != null
        val knownPort = hasEndpoint && isKnownProxyPort(validPort.toString())

        return when {
            !profile.valid -> ProxyProfileEvaluation(
                detected = false,
                needsReview = true,
                confidence = EvidenceConfidence.LOW,
                hasEndpoint = hasEndpoint,
                knownPort = false,
            )
            hasPac -> ProxyProfileEvaluation(
                detected = true,
                needsReview = false,
                confidence = EvidenceConfidence.MEDIUM,
                hasEndpoint = hasEndpoint,
                knownPort = knownPort,
            )
            hasEndpoint -> ProxyProfileEvaluation(
                detected = true,
                needsReview = false,
                confidence = if (knownPort) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
                hasEndpoint = true,
                knownPort = knownPort,
            )
            hasHost -> ProxyProfileEvaluation(
                detected = false,
                needsReview = true,
                confidence = EvidenceConfidence.LOW,
                hasEndpoint = false,
                knownPort = false,
            )
            else -> ProxyProfileEvaluation(
                detected = false,
                needsReview = false,
                confidence = EvidenceConfidence.LOW,
                hasEndpoint = false,
                knownPort = false,
            )
        }
    }

    private fun proxyProfileLabel(
        context: Context,
        profile: ProxyProfileSnapshot,
    ): String {
        return if (profile.isDefault) {
            context.getString(R.string.checker_direct_proxyinfo_default)
        } else {
            context.getString(
                R.string.checker_direct_proxyinfo_network,
                profile.interfaceName?.takeUnless { it.isBlank() }
                    ?: context.getString(R.string.checker_direct_proxyinfo_unknown_interface),
            )
        }
    }

    private fun proxyProfileDetails(profile: ProxyProfileSnapshot): String {
        val parts = buildList {
            profile.host?.let { add("host=$it") }
            profile.port
                ?.takeIf { it > 0 || !profile.host.isNullOrBlank() }
                ?.let { add("port=$it") }
            profile.pacUrl?.let { add("pac=$it") }
            if (profile.exclusions.isNotEmpty()) {
                add("excl=${profile.exclusions.joinToString()}")
            }
        }
        return parts.joinToString(" ")
    }

    private fun appendProxyProfileDetails(
        base: String,
        details: String,
    ): String {
        return if (details.isBlank()) base else "$base ($details)"
    }

    private fun proxyAvailabilityFinding(
        context: Context,
        label: String,
        errorMessage: String,
    ): Finding {
        return Finding(
            description = context.getString(
                R.string.checker_direct_proxyinfo_unavailable,
                label,
                errorMessage,
            ),
            needsReview = true,
            source = EvidenceSource.SYSTEM_PROXY,
            confidence = EvidenceConfidence.LOW,
        )
    }

    internal fun evaluateProxyEndpoint(
        context: Context,
        type: String,
        host: String?,
        port: String?,
    ): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        val outcome = addProxyFinding(context, type, host, port, findings, evidence)
        return CategoryResult(
            name = type,
            detected = outcome.detected,
            findings = findings,
            needsReview = outcome.needsReview,
            evidence = evidence,
        )
    }

    private fun reportTunActiveProbe(
        context: Context,
        result: UnderlyingNetworkProber.ProbeResult,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val targets = listOfNotNull(
            result.ruTarget.takeIf { it.vpnIp != null || it.error != null },
            result.nonRuTarget.takeIf { it.vpnIp != null || it.error != null },
        )
        if (targets.isEmpty()) {
            result.vpnError
                ?.takeIf { it.isNotBlank() }
                ?.let { vpnError ->
                    findings.add(
                        Finding(
                            description = context.getString(R.string.checker_bypass_tun_probe_failure_reason, vpnError),
                            needsReview = true,
                            source = EvidenceSource.TUN_ACTIVE_PROBE,
                            confidence = EvidenceConfidence.LOW,
                        ),
                    )
                    return SignalOutcome(needsReview = true)
                }
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_bypass_tun_probe_failure),
                    isInformational = true,
                    source = EvidenceSource.TUN_ACTIVE_PROBE,
                ),
            )
            return SignalOutcome()
        }

        var detected = false
        var needsReview = false

        for (target in targets) {
            val vpnIp = target.vpnIp
            if (vpnIp == null) {
                target.error?.takeIf { it.isNotBlank() }?.let { err ->
                    findings.add(
                        Finding(
                            description = context.getString(
                                R.string.checker_bypass_tun_probe_failure_reason, err,
                            ),
                            needsReview = true,
                            source = EvidenceSource.TUN_ACTIVE_PROBE,
                            confidence = EvidenceConfidence.LOW,
                        ),
                    )
                    needsReview = true
                }
                continue
            }
            val comparison = target.comparison
            val transportOnly = comparison?.usedCurlCompatibleFallback() == true &&
                comparison.curlCompatible.transportDiagnostics.resolveStrategy != TunProbeResolveStrategy.KOTLIN_INJECTED
            findings.add(
                Finding(
                    description = context.getString(
                        when {
                            transportOnly -> R.string.checker_bypass_tun_probe_success_transport_only
                            comparison?.usedCurlCompatibleFallback() == true -> R.string.checker_bypass_tun_probe_success_curl_compatible
                            else -> R.string.checker_bypass_tun_probe_success
                        },
                        vpnIp,
                    ),
                    isInformational = true,
                    source = EvidenceSource.TUN_ACTIVE_PROBE,
                ),
            )

            val hasDnsPathMismatch = comparison?.dnsPathMismatch == true
            if (hasDnsPathMismatch) {
                val confidence = if (transportOnly) EvidenceConfidence.MEDIUM else EvidenceConfidence.HIGH
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.TUN_ACTIVE_PROBE,
                        detected = true,
                        confidence = confidence,
                        description = "DNS path mismatch on TUN probe (${target.targetGroup}): $vpnIp",
                    ),
                )
                detected = true
            } else {
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.TUN_ACTIVE_PROBE,
                        detected = false,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "TUN probe returned $vpnIp (${target.targetGroup}); consensus will decide",
                    ),
                )
                needsReview = true
            }
        }

        return SignalOutcome(detected = detected, needsReview = needsReview)
    }

    private fun addDebugTunProbeFinding(
        context: Context,
        result: UnderlyingNetworkProber.ProbeResult,
        findings: MutableList<Finding>,
    ) {
        val diagnostics = result.tunProbeDiagnostics ?: return
        val vpnPath = diagnostics.vpnPath ?: return
        findings.add(
            Finding(
                description = TunProbeDiagnosticsFormatter.formatUiSummary(
                    context = context,
                    pathLabel = context.getString(R.string.checker_tun_probe_path_vpn),
                    modeOverride = diagnostics.modeOverride,
                    path = vpnPath,
                ),
                isInformational = true,
                source = EvidenceSource.TUN_ACTIVE_PROBE,
            ),
        )
    }

    internal fun isKnownProxyPort(port: String?): Boolean {
        val value = port?.toIntOrNull() ?: return false
        return value in KNOWN_PROXY_PORTS || KNOWN_PROXY_PORT_RANGES.any { value in it }
    }

    private fun Throwable.renderMessage(): String {
        return message?.takeIf { it.isNotBlank() } ?: javaClass.simpleName
    }
}
