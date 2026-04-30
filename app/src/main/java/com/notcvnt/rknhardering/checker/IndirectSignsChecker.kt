package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import com.notcvnt.rknhardering.LocalProxyOwnerFormatter
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer
import com.notcvnt.rknhardering.probe.LocalSocketInspector
import com.notcvnt.rknhardering.probe.LocalSocketListener
import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import com.notcvnt.rknhardering.vpn.VpnAppMetadataScanner
import com.notcvnt.rknhardering.vpn.VpnClientSignal
import com.notcvnt.rknhardering.vpn.VpnDumpsysParser
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetAddress
import java.net.NetworkInterface

object IndirectSignsChecker {

    private data class SignalOutcome(
        val detected: Boolean = false,
        val needsReview: Boolean = false,
    )

    internal enum class DnsClassification {
        LOOPBACK,
        PRIVATE_NETWORK,
        KNOWN_PUBLIC_RESOLVER,
        LINK_LOCAL,
        OTHER_PUBLIC,
    }

    internal data class RouteSnapshot(
        val destination: String,
        val gateway: String?,
        val interfaceName: String?,
        val isDefault: Boolean,
    )

    internal data class InterfaceAddressSnapshot(
        val address: String,
        val prefixLength: Int,
    )

    internal data class NetworkSnapshot(
        val label: String,
        val isActive: Boolean,
        val isVpn: Boolean,
        val interfaceName: String?,
        val hasTransportVpn: Boolean,
        val hasNotVpn: Boolean,
        val hasIms: Boolean,
        val hasEims: Boolean,
        val hasMmtel: Boolean,
        val capsString: String,
        val routes: List<RouteSnapshot>,
        val dnsServers: List<String>,
        val interfaceAddresses: List<InterfaceAddressSnapshot>,
    )

    internal enum class TunnelClass {
        CONFIRMED_VPN,
        CARRIER_IMS_IPSEC,
        UNKNOWN_IPSEC,
        NORMAL,
    }

    internal data class RoutingEvaluation(
        val findings: List<Finding>,
        val evidence: List<EvidenceItem>,
        val detected: Boolean,
        val needsReview: Boolean,
    )

    internal data class DnsEvaluation(
        val findings: List<Finding>,
        val evidence: List<EvidenceItem>,
        val detected: Boolean,
        val needsReview: Boolean,
    )

    internal data class ProxyTechnicalEvaluation(
        val findings: List<Finding>,
        val evidence: List<EvidenceItem>,
        val detected: Boolean,
        val needsReview: Boolean,
    )

    internal data class CallTransportEvaluation(
        val results: List<CallTransportLeakResult> = emptyList(),
        val stunGroups: List<com.notcvnt.rknhardering.model.StunProbeGroupResult> = emptyList(),
        val findings: List<Finding> = emptyList(),
        val evidence: List<EvidenceItem> = emptyList(),
        val needsReview: Boolean = false,
        val diagnostics: CallTransportPerformanceDiagnostics? = null,
    )

    private val VPN_INTERFACE_PATTERNS = listOf(
        Regex("^tun\\d+"),
        Regex("^tap\\d+"),
        Regex("^wg\\d+"),
        Regex("^ppp\\d+"),
    )

    private val IPSEC_INTERFACE_PATTERN = Regex("^ipsec.*")

    private val STANDARD_INTERFACES = listOf(
        Regex("^wlan.*"),
        Regex("^rmnet.*"),
        Regex("^seth.*"),   // LTE interface on select Qualcomm/MediaTek devices (e.g. seth_lte0)
        Regex("^eth.*"),
        Regex("^lo$"),
        Regex("^ccmni.*"),
        Regex("^ccemni.*"),
    )

    private val KNOWN_PUBLIC_RESOLVERS = setOf(
        "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15",
        "77.88.8.8", "77.88.8.1",
        "76.76.19.19",
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2620:fe::fe", "2620:fe::9",
        "2620:119:35::35", "2620:119:53::53",
        "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
    )

    private val PROXY_TOOL_SIGNATURES = VpnAppCatalog.signatures.filter { signature ->
        VpnClientSignal.LOCAL_PROXY in signature.signals && VpnClientSignal.VPN_SERVICE !in signature.signals
    }

    private val KNOWN_LOCAL_PROXY_PORTS = (
        VpnAppCatalog.localhostProxyPorts +
            listOf(80, 443, 1080, 3127, 3128, 4080, 5555, 7000, 7044, 8000, 8080, 8081, 8082, 8888, 9000, 9050, 9051, 9150, 12345)
        ).toSet()

    suspend fun check(
        context: Context,
        networkRequestsEnabled: Boolean = true,
        callTransportProbeEnabled: Boolean = false,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): CategoryResult {
        val startedAtMs = IndirectCheckPerformanceSupport.monotonicNowMs()
        val stepTimings = mutableListOf<DebugStepTiming>()
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        val activeApps = mutableListOf<ActiveVpnApp>()
        val callTransportLeaks = mutableListOf<CallTransportLeakResult>()
        val stunProbeGroups = mutableListOf<com.notcvnt.rknhardering.model.StunProbeGroupResult>()
        var detected = false
        var needsReview = false

        val networkSnapshots = IndirectCheckPerformanceSupport.measureStep("collectNetworkSnapshots", stepTimings) {
            collectNetworkSnapshots(context)
        }
        val snapshotByInterface = buildSnapshotIndex(networkSnapshots)

        findings += networkSnapshots
            .mapNotNull { snapshot ->
                snapshot.interfaceName
                    ?.takeIf(::isIpsecInterface)
                    ?.let { buildIpsecDiagnostics(context, it, snapshot) }
            }
            .flatten()

        val notVpnOutcome = IndirectCheckPerformanceSupport.measureStep("checkNotVpnCapability", stepTimings) {
            checkNotVpnCapability(context, findings, evidence)
        }
        detected = detected || notVpnOutcome.detected
        needsReview = needsReview || notVpnOutcome.needsReview

        detected = IndirectCheckPerformanceSupport.measureStep("checkNetworkInterfaces", stepTimings) {
            checkNetworkInterfaces(context, findings, evidence, snapshotByInterface)
        } || detected
        detected = IndirectCheckPerformanceSupport.measureStep("checkMtu", stepTimings) {
            checkMtu(context, findings, evidence, snapshotByInterface)
        } || detected

        val routingOutcome = IndirectCheckPerformanceSupport.measureStep("checkRoutingTable", stepTimings) {
            checkRoutingTable(context, networkSnapshots)
        }
        findings += routingOutcome.findings
        evidence += routingOutcome.evidence
        detected = detected || routingOutcome.detected
        needsReview = needsReview || routingOutcome.needsReview

        val dnsOutcome = IndirectCheckPerformanceSupport.measureStep("checkDns", stepTimings) {
            checkDns(context, networkSnapshots)
        }
        findings += dnsOutcome.findings
        evidence += dnsOutcome.evidence
        detected = detected || dnsOutcome.detected
        needsReview = needsReview || dnsOutcome.needsReview

        val proxyTechnicalOutcome = IndirectCheckPerformanceSupport.measureStep("checkProxyTechnicalSignals", stepTimings) {
            checkProxyTechnicalSignals(context)
        }
        findings += proxyTechnicalOutcome.findings
        evidence += proxyTechnicalOutcome.evidence
        detected = detected || proxyTechnicalOutcome.detected
        needsReview = needsReview || proxyTechnicalOutcome.needsReview

        val callTransportOutcome = IndirectCheckPerformanceSupport.measureSuspendStep("checkCallTransportSignals", stepTimings) {
            checkCallTransportSignals(
                context = context,
                networkRequestsEnabled = networkRequestsEnabled,
                callTransportProbeEnabled = callTransportProbeEnabled,
                resolverConfig = resolverConfig,
            )
        }
        findings += callTransportOutcome.findings
        evidence += callTransportOutcome.evidence
        callTransportLeaks += callTransportOutcome.results
        stunProbeGroups += callTransportOutcome.stunGroups
        needsReview = needsReview || callTransportOutcome.needsReview

        val dumpsysVpnOutcome = IndirectCheckPerformanceSupport.measureStep("checkDumpsysVpn", stepTimings) {
            checkDumpsysVpn(context, findings, evidence, activeApps)
        }
        detected = detected || dumpsysVpnOutcome.detected
        needsReview = needsReview || dumpsysVpnOutcome.needsReview

        val dumpsysServiceOutcome = IndirectCheckPerformanceSupport.measureStep("checkDumpsysVpnService", stepTimings) {
            checkDumpsysVpnService(context, findings, evidence, activeApps)
        }
        detected = detected || dumpsysServiceOutcome.detected
        needsReview = needsReview || dumpsysServiceOutcome.needsReview

        val result = CategoryResult(
            name = context.getString(R.string.checker_indirect_category_name),
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
            activeApps = activeApps.distinctBy { Triple(it.packageName, it.serviceName, it.source) },
            callTransportLeaks = callTransportLeaks,
            stunProbeGroups = stunProbeGroups,
        )
        IndirectCheckPerformanceRegistry.attach(
            category = result,
            diagnostics = IndirectCheckPerformanceDiagnostics(
                totalDurationMs = IndirectCheckPerformanceSupport.elapsedSince(startedAtMs),
                steps = stepTimings.toList(),
                callTransport = callTransportOutcome.diagnostics,
            ),
        )
        return result
    }

    private suspend fun checkCallTransportSignals(
        context: Context,
        networkRequestsEnabled: Boolean,
        callTransportProbeEnabled: Boolean,
        resolverConfig: DnsResolverConfig,
    ): CallTransportEvaluation {
        if (!networkRequestsEnabled || !callTransportProbeEnabled) {
            return CallTransportEvaluation()
        }

        val evaluation = CallTransportChecker.check(
            context = context,
            resolverConfig = resolverConfig,
            callTransportEnabled = true,
        )
        return CallTransportEvaluation(
            results = evaluation.results,
            stunGroups = evaluation.stunGroups,
            findings = evaluation.findings,
            evidence = evaluation.evidence,
            needsReview = evaluation.needsReview,
            diagnostics = evaluation.diagnostics,
        )
    }

    private fun collectNetworkSnapshots(context: Context): List<NetworkSnapshot> {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = cm.activeNetwork
            allNetworksSnapshot(cm).mapNotNull { network ->
                val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
                val linkProperties = cm.getLinkProperties(network) ?: return@mapNotNull null
                if (!caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    linkProperties.interfaceName.isNullOrBlank() &&
                    linkProperties.linkAddresses.isEmpty() &&
                    linkProperties.routes.isEmpty() &&
                    linkProperties.dnsServers.isEmpty()
                ) {
                    return@mapNotNull null
                }

                val capsString = caps.toString()
                val hasTransportVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                val hasNotVpn = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                val hasIms = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_IMS)
                val hasEims = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_EIMS)
                val hasMmtel = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_MMTEL)

                NetworkSnapshot(
                    label = network.toString(),
                    isActive = network == activeNetwork,
                    isVpn = hasTransportVpn,
                    interfaceName = NetworkInterfaceNameNormalizer.canonicalName(linkProperties.interfaceName),
                    hasTransportVpn = hasTransportVpn,
                    hasNotVpn = hasNotVpn,
                    hasIms = hasIms,
                    hasEims = hasEims,
                    hasMmtel = hasMmtel,
                    capsString = capsString,
                    routes = linkProperties.routes.map { route ->
                        RouteSnapshot(
                            destination = route.destination?.toString()
                                ?: if (route.isDefaultRoute) "0.0.0.0/0" else "unknown",
                            gateway = route.gateway?.hostAddress?.takeUnless { it == "0.0.0.0" || it == "::" },
                            interfaceName = NetworkInterfaceNameNormalizer.canonicalName(
                                route.`interface` ?: linkProperties.interfaceName,
                            ),
                            isDefault = route.isDefaultRoute,
                        )
                    },
                    dnsServers = linkProperties.dnsServers.mapNotNull { it.hostAddress?.let(::normalizeIpAddress) },
                    interfaceAddresses = linkProperties.linkAddresses.mapNotNull { linkAddress ->
                        linkAddress.address?.hostAddress?.let { address ->
                            InterfaceAddressSnapshot(
                                address = normalizeIpAddress(address),
                                prefixLength = linkAddress.prefixLength,
                            )
                        }
                    },
                )
            }.sortedByDescending { it.isActive }
        } catch (_: Exception) {
            emptyList()
        }
    }

    @Suppress("DEPRECATION")
    private fun allNetworksSnapshot(cm: ConnectivityManager): Array<android.net.Network> {
        return cm.allNetworks
    }

    private fun checkNotVpnCapability(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork ?: return SignalOutcome()
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return SignalOutcome()

        val capsString = caps.toString()
        val hasNotVpn = capsString.contains("NOT_VPN")
        findings.add(
            Finding(
                description = context.getString(
                    R.string.checker_indirect_capability_not_vpn,
                    context.getString(
                        if (hasNotVpn) R.string.checker_indirect_present
                        else R.string.checker_indirect_absent_suspicious,
                    ),
                ),
                detected = !hasNotVpn,
                source = EvidenceSource.INDIRECT_NETWORK_CAPABILITIES,
                confidence = (!hasNotVpn).takeIf { it }?.let { EvidenceConfidence.MEDIUM },
            ),
        )
        if (!hasNotVpn) {
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.INDIRECT_NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Active network does not expose NOT_VPN capability",
                ),
            )
        }
        return SignalOutcome(detected = !hasNotVpn)
    }

    private fun checkNetworkInterfaces(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        snapshotByInterface: Map<String, NetworkSnapshot>,
    ): Boolean {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            val vpnInterfaces = interfaces.filter { iface ->
                iface.isUp && classifyTunnel(iface.name, snapshotByInterface.snapshotFor(iface.name)) == TunnelClass.CONFIRMED_VPN
            }

            if (vpnInterfaces.isEmpty()) {
                findings.add(Finding(context.getString(R.string.checker_indirect_no_vpn_interfaces)))
                return false
            }

            for (iface in vpnInterfaces) {
                findings.add(
                    Finding(
                        description = context.getString(R.string.checker_indirect_vpn_interface_found, iface.name),
                        detected = true,
                        source = EvidenceSource.NETWORK_INTERFACE,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.NETWORK_INTERFACE,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Active VPN-like interface ${iface.name}",
                    ),
                )
            }
            true
        } catch (e: Exception) {
            findings.add(Finding(context.getString(R.string.checker_indirect_interface_error, e.message)))
            false
        }
    }

    private fun checkMtu(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        snapshotByInterface: Map<String, NetworkSnapshot>,
    ): Boolean {
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            var detected = false
            for (iface in interfaces) {
                if (!iface.isUp) continue
                if (classifyTunnel(iface.name, snapshotByInterface.snapshotFor(iface.name)) != TunnelClass.CONFIRMED_VPN) continue

                val mtu = iface.mtu
                if (mtu !in 1..1499) continue

                findings.add(
                    Finding(
                        description = context.getString(
                            R.string.checker_indirect_mtu_anomaly,
                            iface.name,
                            mtu,
                        ),
                        detected = true,
                        source = EvidenceSource.NETWORK_INTERFACE,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.NETWORK_INTERFACE,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "VPN-like interface ${iface.name} uses low MTU $mtu",
                    ),
                )
                detected = true
            }

            if (!detected) {
                findings.add(Finding(context.getString(R.string.checker_indirect_mtu_no_anomalies)))
            }

            detected
        } catch (e: Exception) {
            findings.add(Finding(context.getString(R.string.checker_indirect_mtu_error, e.message)))
            false
        }
    }

    internal fun checkRoutingTable(context: Context, networkSnapshots: List<NetworkSnapshot>): RoutingEvaluation {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false
        val snapshotByInterface = buildSnapshotIndex(networkSnapshots)

        val snapshotsWithRoutes = networkSnapshots.filter { it.routes.isNotEmpty() }
        for (snapshot in snapshotsWithRoutes) {
            val snapshotClass = classifyTunnel(snapshot.interfaceName, snapshot)
            val defaultRoutes = snapshot.routes.filter { it.isDefault }
            for (route in defaultRoutes) {
                val iface = route.interfaceName
                val routeClass = classifyTunnel(iface, snapshotByInterface.snapshotFor(iface))
                if ((iface != null && isStandardInterface(iface) && snapshotClass != TunnelClass.CONFIRMED_VPN) ||
                    routeClass == TunnelClass.CARRIER_IMS_IPSEC ||
                    routeClass == TunnelClass.UNKNOWN_IPSEC
                ) {
                    if (iface != null && isStandardInterface(iface)) {
                        findings.add(
                            Finding(
                                context.getString(R.string.checker_indirect_default_route_standard, iface),
                            ),
                        )
                    }
                    continue
                }

                findings.add(
                    Finding(
                        description = context.getString(
                            R.string.checker_indirect_default_route_nonstandard,
                            iface ?: "N/A",
                        ),
                        detected = true,
                        source = EvidenceSource.ROUTING,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ROUTING,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Default route points to non-standard interface ${iface ?: "N/A"}",
                    ),
                )
                detected = true
            }

            val dedicatedRoutes = snapshot.routes.filter { route ->
                !route.isDefault &&
                    route.interfaceName != null &&
                    isSuspiciousRoutingInterface(route.interfaceName, snapshotByInterface)
            }
            if (dedicatedRoutes.isNotEmpty()) {
                val routePreview = dedicatedRoutes.take(3).joinToString { route ->
                    "${route.destination} via ${route.interfaceName ?: "N/A"}"
                }
                findings.add(
                    Finding(
                        description = context.getString(R.string.checker_indirect_dedicated_routes, routePreview),
                        detected = true,
                        source = EvidenceSource.ROUTING,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ROUTING,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Dedicated routes found on VPN/non-standard interfaces",
                    ),
                )
                detected = true
            }
        }

        val procDefaultInterfaces = collectProcDefaultRouteInterfaces()
        if (snapshotsWithRoutes.none { snapshot -> snapshot.routes.any { it.isDefault } } && procDefaultInterfaces.isNotEmpty()) {
            for (iface in procDefaultInterfaces) {
                if (isStandardInterface(iface)) {
                    findings.add(
                        Finding(
                            context.getString(R.string.checker_indirect_proc_default_route_standard, iface),
                        ),
                    )
                    continue
                }
                if (classifyTunnel(iface, snapshotByInterface.snapshotFor(iface)) != TunnelClass.NORMAL && !isSuspiciousRoutingInterface(iface, snapshotByInterface)) {
                    continue
                }

                findings.add(
                    Finding(
                        description = context.getString(
                            R.string.checker_indirect_proc_default_route_nonstandard,
                            iface,
                        ),
                        detected = true,
                        source = EvidenceSource.ROUTING,
                        confidence = EvidenceConfidence.MEDIUM,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ROUTING,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Default route from /proc/net/route points to non-standard interface $iface",
                    ),
                )
                detected = true
            }
        }

        val hasVpnRoutes = snapshotsWithRoutes.any { snapshot ->
            snapshot.routes.any { route ->
                !route.isDefault &&
                    isSuspiciousRoutingInterface(route.interfaceName ?: snapshot.interfaceName, snapshotByInterface)
            }
        }
        val hasUnderlyingDefaultRoute = snapshotsWithRoutes.any { snapshot ->
            classifyTunnel(snapshot.interfaceName, snapshot) != TunnelClass.CONFIRMED_VPN &&
                snapshot.routes.any { route ->
                    route.isDefault && route.interfaceName != null && isStandardInterface(route.interfaceName)
                }
        }
        if (hasVpnRoutes && hasUnderlyingDefaultRoute) {
            findings.add(
                Finding(
                    description = context.getString(R.string.checker_indirect_split_tunnel_routes),
                    detected = true,
                    source = EvidenceSource.ROUTING,
                    confidence = EvidenceConfidence.MEDIUM,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.ROUTING,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Split-tunneling route pattern detected",
                ),
            )
            detected = true
        }

        if (snapshotsWithRoutes.none { snapshot -> snapshot.routes.any { it.gateway != null } }) {
            findings.add(Finding(context.getString(R.string.checker_indirect_gateway_route_unavailable)))
        }

        if (!detected && findings.isEmpty()) {
            findings.add(Finding(context.getString(R.string.checker_indirect_routing_no_anomalies)))
        }

        return RoutingEvaluation(
            findings = findings,
            evidence = evidence,
            detected = detected,
            needsReview = false,
        )
    }

    internal fun checkDns(context: Context, networkSnapshots: List<NetworkSnapshot>): DnsEvaluation {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false
        var needsReview = false
        val snapshotByInterface = buildSnapshotIndex(networkSnapshots)

        val activeSnapshot = networkSnapshots.firstOrNull { it.isActive }
        if (activeSnapshot == null) {
            findings.add(Finding(context.getString(R.string.checker_indirect_dns_no_active_network)))
            return DnsEvaluation(findings, evidence, detected = false, needsReview = false)
        }

        if (activeSnapshot.dnsServers.isEmpty()) {
            findings.add(Finding(context.getString(R.string.checker_indirect_dns_servers_not_found)))
            return DnsEvaluation(findings, evidence, detected = false, needsReview = false)
        }

        val activeVpn = isDnsVpnSnapshot(activeSnapshot, snapshotByInterface)
        val activeRouteInterface = activeSnapshot.routes.firstOrNull { it.isDefault }?.interfaceName ?: activeSnapshot.interfaceName
        val routeViaVpnInterface = classifyTunnel(
            activeRouteInterface,
            snapshotByInterface.snapshotFor(activeRouteInterface),
        ) == TunnelClass.CONFIRMED_VPN
        val underlyingSnapshots = networkSnapshots.filterNot { snapshot ->
            isDnsVpnSnapshot(snapshot, snapshotByInterface)
        }
        val underlyingDns = underlyingSnapshots.flatMapTo(linkedSetOf()) { it.dnsServers }

        for (dns in activeSnapshot.dnsServers.distinct()) {
            val changedFromUnderlying = underlyingDns.isNotEmpty() && dns !in underlyingDns
            when (classifyDnsAddress(dns)) {
                DnsClassification.LOOPBACK -> {
                    findings.add(
                        Finding(
                            description = context.getString(R.string.checker_indirect_dns_localhost, dns),
                            detected = true,
                            source = EvidenceSource.DNS,
                            confidence = EvidenceConfidence.HIGH,
                        ),
                    )
                    evidence.add(
                        EvidenceItem(
                            source = EvidenceSource.DNS,
                            detected = true,
                            confidence = EvidenceConfidence.HIGH,
                            description = "DNS resolver uses loopback address $dns",
                        ),
                    )
                    detected = true
                }

                DnsClassification.PRIVATE_NETWORK -> {
                    if (isInheritedPrivateDns(dns, activeSnapshot, underlyingSnapshots, activeVpn)) {
                        findings.add(Finding(context.getString(R.string.checker_indirect_dns_inherited_private, dns)))
                        continue
                    }

                    val vpnAssigned = activeVpn && (changedFromUnderlying || routeViaVpnInterface)
                    val privateDnsDescription = if (changedFromUnderlying) {
                        context.getString(R.string.checker_indirect_dns_private_changed, dns)
                    } else {
                        context.getString(R.string.checker_indirect_dns_private, dns)
                    }
                    findings.add(
                        Finding(
                            description = privateDnsDescription,
                            detected = vpnAssigned,
                            needsReview = !vpnAssigned,
                            source = EvidenceSource.DNS,
                            confidence = if (vpnAssigned) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
                        ),
                    )
                    evidence.add(
                        EvidenceItem(
                            source = EvidenceSource.DNS,
                            detected = true,
                            confidence = if (vpnAssigned) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW,
                            description = "DNS resolver uses private network address $dns",
                        ),
                    )
                    detected = detected || vpnAssigned
                    needsReview = needsReview || !vpnAssigned
                }

                DnsClassification.KNOWN_PUBLIC_RESOLVER,
                DnsClassification.OTHER_PUBLIC,
                -> {
                    if (activeVpn && changedFromUnderlying) {
                        findings.add(
                            Finding(
                                description = context.getString(R.string.checker_indirect_dns_replaced_vpn, dns),
                                needsReview = true,
                                source = EvidenceSource.DNS,
                                confidence = EvidenceConfidence.LOW,
                            ),
                        )
                        evidence.add(
                            EvidenceItem(
                                source = EvidenceSource.DNS,
                                detected = true,
                                confidence = EvidenceConfidence.LOW,
                                description = "DNS differs from underlying network while VPN is active: $dns",
                            ),
                        )
                        needsReview = true
                    } else if (activeVpn && underlyingDns.isEmpty()) {
                        findings.add(Finding(context.getString(R.string.checker_indirect_dns_source_unknown, dns)))
                    } else {
                        findings.add(Finding(context.getString(R.string.checker_indirect_dns_plain, dns)))
                    }
                }

                DnsClassification.LINK_LOCAL -> {
                    findings.add(Finding(context.getString(R.string.checker_indirect_dns_link_local, dns)))
                }
            }
        }

        return DnsEvaluation(findings, evidence, detected, needsReview)
    }

    private fun checkProxyTechnicalSignals(context: Context): ProxyTechnicalEvaluation {
        val installedProxyTools = detectInstalledProxyTools(context)
        val listeners = collectLocalListeners(context)
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false
        var needsReview = false

        for (packageName in installedProxyTools) {
            val signature = PROXY_TOOL_SIGNATURES.firstOrNull { it.packageName == packageName } ?: continue
            val description = context.getString(
                R.string.checker_indirect_proxy_tool_installed,
                signature.appName,
                signature.packageName,
            )
            findings.add(
                Finding(
                    description = description,
                    needsReview = true,
                    source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                    confidence = EvidenceConfidence.LOW,
                    family = signature.family,
                    packageName = signature.packageName,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                    detected = true,
                    confidence = EvidenceConfidence.LOW,
                    description = description,
                    family = signature.family,
                    packageName = signature.packageName,
                    kind = signature.kind,
                ),
            )
            needsReview = true
        }

        val loopbackListeners = listeners.filter { listener ->
            isLoopbackOrAnyAddress(listener.host) && listener.port in KNOWN_LOCAL_PROXY_PORTS
        }
        if (loopbackListeners.isNotEmpty()) {
            for (listener in loopbackListeners.distinctBy { Triple(it.protocol, it.host, it.port) }) {
                val baseDescription = context.getString(
                    R.string.checker_indirect_local_listener,
                    listener.host,
                    listener.port,
                    listener.protocol,
                )
                val ownerSuffix = formatOwnerSuffix(context, listener.owner)
                val description = baseDescription + ownerSuffix
                findings.add(
                    Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                        confidence = EvidenceConfidence.MEDIUM,
                        packageName = LocalProxyOwnerFormatter.packageName(listener.owner),
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = description,
                        packageName = LocalProxyOwnerFormatter.packageName(listener.owner),
                    ),
                )
            }
            detected = true
        } else if (listeners.isNotEmpty()) {
            val localhostHighPorts = listeners.count { listener ->
                isLoopbackOrAnyAddress(listener.host) && listener.port >= 1024
            }
            if (localhostHighPorts >= 3) {
                findings.add(
                    Finding(
                        description = context.getString(
                            R.string.checker_indirect_many_localhost_listeners,
                            localhostHighPorts,
                        ),
                        needsReview = true,
                        source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                        confidence = EvidenceConfidence.LOW,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.PROXY_TECHNICAL_SIGNAL,
                        detected = true,
                        confidence = EvidenceConfidence.LOW,
                        description = "Multiple localhost listeners detected on high ports",
                    ),
                )
                needsReview = true
            }
        }

        if (installedProxyTools.isEmpty() && listeners.isEmpty()) {
            findings.add(Finding(context.getString(R.string.checker_indirect_no_proxy_technical)))
        }

        findings.add(
            Finding(
                description = context.getString(R.string.checker_indirect_limited_checks),
            ),
        )

        return ProxyTechnicalEvaluation(
            findings = findings,
            evidence = evidence,
            detected = detected,
            needsReview = needsReview,
        )
    }

    internal fun parseProcNetListeners(lines: List<String>, protocol: String): List<LocalSocketListener> =
        LocalSocketInspector.parseProcNetListeners(lines, protocol)

    private fun detectInstalledProxyTools(context: Context): Set<String> {
        val pm = context.packageManager
        return PROXY_TOOL_SIGNATURES.mapNotNullTo(linkedSetOf()) { signature ->
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(signature.packageName, android.content.pm.PackageManager.PackageInfoFlags.of(0L))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(signature.packageName, 0)
                }
                signature.packageName
            } catch (_: Exception) {
                null
            }
        }
    }

    private fun collectLocalListeners(context: Context): List<LocalSocketListener> = LocalSocketInspector.collect(context)

    private fun collectProcDefaultRouteInterfaces(): List<String> {
        return try {
            val routeFile = File("/proc/net/route")
            if (!routeFile.exists()) return emptyList()
            BufferedReader(FileReader(routeFile)).use { reader ->
                reader.readLines()
                    .drop(1)
                    .mapNotNull { line ->
                        val parts = line.trim().split("\\s+".toRegex())
                        parts.takeIf { it.size >= 2 && it[1] == "00000000" }?.get(0)
                    }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun isStandardInterface(name: String?): Boolean {
        val canonicalName = NetworkInterfaceNameNormalizer.canonicalName(name)
        if (canonicalName.isNullOrBlank()) return false
        return STANDARD_INTERFACES.any { it.matches(canonicalName) }
    }

    private fun isVpnInterface(name: String?): Boolean {
        val canonicalName = NetworkInterfaceNameNormalizer.canonicalName(name)
        if (canonicalName.isNullOrBlank()) return false
        return VPN_INTERFACE_PATTERNS.any { it.matches(canonicalName) }
    }

    private fun isIpsecInterface(name: String?): Boolean {
        val canonicalName = NetworkInterfaceNameNormalizer.canonicalName(name)
        if (canonicalName.isNullOrBlank()) return false
        return IPSEC_INTERFACE_PATTERN.matches(canonicalName)
    }

    internal fun classifyTunnel(interfaceName: String?, snapshot: NetworkSnapshot?): TunnelClass {
        if (snapshot?.hasTransportVpn == true) return TunnelClass.CONFIRMED_VPN

        val canonicalName = NetworkInterfaceNameNormalizer.canonicalName(interfaceName)
        if (canonicalName.isNullOrBlank()) return TunnelClass.NORMAL
        if (isVpnInterface(canonicalName)) return TunnelClass.CONFIRMED_VPN
        if (!isIpsecInterface(canonicalName)) return TunnelClass.NORMAL
        if (snapshot == null) return TunnelClass.UNKNOWN_IPSEC

        val hasVpnMarkers = !snapshot.hasNotVpn ||
            snapshot.capsString.contains("IS_VPN") ||
            snapshot.capsString.contains("VpnTransportInfo")
        val hasCarrierImsMarkers = snapshot.hasNotVpn &&
            !snapshot.hasTransportVpn &&
            (snapshot.hasIms || snapshot.hasEims || snapshot.hasMmtel)

        return when {
            hasVpnMarkers -> TunnelClass.CONFIRMED_VPN
            hasCarrierImsMarkers -> TunnelClass.CARRIER_IMS_IPSEC
            else -> TunnelClass.UNKNOWN_IPSEC
        }
    }

    internal fun buildIpsecDiagnostics(
        context: Context,
        interfaceName: String,
        snapshot: NetworkSnapshot,
    ): List<Finding> {
        val classificationText = when (classifyTunnel(interfaceName, snapshot)) {
            TunnelClass.CONFIRMED_VPN -> context.getString(R.string.checker_indirect_ipsec_class_confirmed_vpn)
            TunnelClass.CARRIER_IMS_IPSEC -> context.getString(R.string.checker_indirect_ipsec_class_carrier_ims)
            TunnelClass.UNKNOWN_IPSEC -> context.getString(R.string.checker_indirect_ipsec_class_unknown)
            TunnelClass.NORMAL -> return emptyList()
        }
        return listOf(
            Finding(
                description = context.getString(
                    R.string.checker_indirect_ipsec_classification,
                    interfaceName,
                    classificationText,
                ),
            ),
            Finding(
                description = context.getString(
                    R.string.checker_indirect_ipsec_capabilities,
                    interfaceName,
                    yesNo(context, snapshot.hasNotVpn),
                    yesNo(context, snapshot.hasTransportVpn),
                    yesNo(context, snapshot.hasIms),
                    yesNo(context, snapshot.hasEims),
                    yesNo(context, snapshot.hasMmtel),
                ),
            ),
        )
    }

    private fun isSuspiciousRoutingInterface(
        name: String?,
        snapshotByInterface: Map<String, NetworkSnapshot>,
    ): Boolean {
        return when (classifyTunnel(name, snapshotByInterface.snapshotFor(name))) {
            TunnelClass.CONFIRMED_VPN -> true
            TunnelClass.CARRIER_IMS_IPSEC, TunnelClass.UNKNOWN_IPSEC -> false
            TunnelClass.NORMAL -> !isStandardInterface(name)
        }
    }

    private fun isDnsVpnSnapshot(
        snapshot: NetworkSnapshot,
        snapshotByInterface: Map<String, NetworkSnapshot>,
    ): Boolean {
        val defaultRouteInterface = snapshot.routes.firstOrNull { it.isDefault }?.interfaceName
        return classifyTunnel(snapshot.interfaceName, snapshot) == TunnelClass.CONFIRMED_VPN ||
            classifyTunnel(defaultRouteInterface, snapshotByInterface.snapshotFor(defaultRouteInterface)) == TunnelClass.CONFIRMED_VPN
    }

    private fun isLoopbackOrAnyAddress(host: String): Boolean {
        return host == "0.0.0.0" || host == "::" || host == ":::" ||
            host == "::1" || host.startsWith("127.")
    }

    private fun formatOwnerSuffix(context: Context, owner: com.notcvnt.rknhardering.model.LocalProxyOwner?): String {
        val ownerText = owner?.let { LocalProxyOwnerFormatter.format(context, it) }
            ?: context.getString(R.string.checker_proxy_owner_unresolved)
        return context.getString(R.string.checker_proxy_owner_suffix, ownerText)
    }

    private fun normalizeIpAddress(addr: String): String = addr.substringBefore('%').lowercase()

    private fun parseInetAddressOrNull(addr: String): InetAddress? {
        return runCatching { InetAddress.getByName(normalizeIpAddress(addr)) }.getOrNull()
    }

    private fun isPrivateDnsAddress(address: InetAddress): Boolean {
        val bytes = address.address
        return when (bytes.size) {
            4 -> isPrivateIpv4Address(bytes)
            16 -> (bytes[0].toInt() and 0xFE) == 0xFC
            else -> false
        }
    }

    private fun isPrivateIpv4Address(bytes: ByteArray): Boolean {
        val first = bytes[0].toInt() and 0xFF
        val second = bytes[1].toInt() and 0xFF
        return when {
            first == 10 -> true
            first == 172 && second in 16..31 -> true
            first == 192 && second == 168 -> true
            first == 100 && second in 64..127 -> true
            else -> false
        }
    }

    private fun isInheritedPrivateDns(
        dns: String,
        activeSnapshot: NetworkSnapshot,
        underlyingSnapshots: List<NetworkSnapshot>,
        activeVpn: Boolean,
    ): Boolean {
        val dnsAddress = parseInetAddressOrNull(dns) ?: return false
        if (!isPrivateDnsAddress(dnsAddress)) return false
        if (!matchesPrivatePrefix(dnsAddress, activeSnapshot)) return false
        return !activeVpn || underlyingSnapshots.any { matchesPrivatePrefix(dnsAddress, it) }
    }

    private fun matchesPrivatePrefix(
        dnsAddress: InetAddress,
        snapshot: NetworkSnapshot,
    ): Boolean {
        return snapshot.interfaceAddresses.any { linkAddress ->
            val interfaceAddress = parseInetAddressOrNull(linkAddress.address) ?: return@any false
            isPrivateDnsAddress(interfaceAddress) &&
                interfaceAddress.address.size == dnsAddress.address.size &&
                linkAddress.prefixLength in 0..(dnsAddress.address.size * 8) &&
                isAddressInPrefix(dnsAddress, interfaceAddress, linkAddress.prefixLength)
        }
    }

    private fun isAddressInPrefix(
        address: InetAddress,
        prefixAddress: InetAddress,
        prefixLength: Int,
    ): Boolean {
        val addressBytes = address.address
        val prefixBytes = prefixAddress.address
        if (addressBytes.size != prefixBytes.size) return false
        if (prefixLength == 0) return true

        val fullBytes = prefixLength / 8
        val remainingBits = prefixLength % 8
        for (index in 0 until fullBytes) {
            if (addressBytes[index] != prefixBytes[index]) return false
        }
        if (remainingBits == 0) return true

        val mask = (0xFF shl (8 - remainingBits)) and 0xFF
        return ((addressBytes[fullBytes].toInt() xor prefixBytes[fullBytes].toInt()) and mask) == 0
    }

    private fun checkDumpsysVpn(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        activeApps: MutableList<ActiveVpnApp>,
    ): SignalOutcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return SignalOutcome()
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "vpn_management"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (VpnDumpsysParser.isUnavailable(output)) {
                findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_vpn_unavailable)))
                return SignalOutcome()
            }

            val records = VpnDumpsysParser.parseVpnManagement(output)
                .filter { it.packageName != null || it.serviceName != null }
            if (records.isEmpty()) {
                findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_vpn_none)))
                return SignalOutcome()
            }

            var detected = false
            var needsReview = false
            for (record in records) {
                val signature = record.packageName?.let { VpnAppCatalog.findByPackageName(it) }
                val metadata = VpnAppMetadataScanner.scan(
                    context = context,
                    packageName = record.packageName,
                    serviceNames = listOfNotNull(record.serviceName),
                )
                val appLabel = VpnAppMetadataScanner.resolveAppLabel(context, record.packageName)
                val confidence = when {
                    signature != null -> EvidenceConfidence.HIGH
                    record.packageName != null -> EvidenceConfidence.MEDIUM
                    else -> EvidenceConfidence.LOW
                }
                val familySuffix = signature?.family?.let { " [$it]" }.orEmpty()
                val description = buildString {
                    append(context.getString(R.string.checker_indirect_dumpsys_vpn_line, record.rawLine))
                    appLabel?.let { append(" ($it)") }
                    append(familySuffix)
                    append(VpnAppMetadataScanner.formatMetadataSuffix(metadata))
                }
                findings.add(
                    Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                        family = signature?.family,
                        packageName = record.packageName,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ACTIVE_VPN,
                        detected = true,
                        confidence = confidence,
                        description = record.rawLine,
                        family = signature?.family,
                        packageName = record.packageName,
                        kind = signature?.kind,
                    ),
                )
                activeApps.add(
                    ActiveVpnApp(
                        packageName = record.packageName,
                        serviceName = record.serviceName,
                        family = signature?.family,
                        kind = signature?.kind,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                        technicalMetadata = metadata,
                    ),
                )
                detected = true
                needsReview = needsReview || signature == null
            }

            SignalOutcome(detected = detected, needsReview = needsReview)
        } catch (e: Exception) {
            findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_vpn_error, e.message)))
            SignalOutcome()
        }
    }

    private fun checkDumpsysVpnService(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        activeApps: MutableList<ActiveVpnApp>,
    ): SignalOutcome {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "activity", "services", "android.net.VpnService"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (VpnDumpsysParser.isUnavailable(output)) {
                findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_service_unavailable)))
                return SignalOutcome()
            }

            val records = VpnDumpsysParser.parseVpnServices(output)
            if (records.isEmpty()) {
                findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_service_none)))
                return SignalOutcome()
            }

            var detected = false
            var needsReview = false
            for (record in records) {
                val signature = record.packageName?.let { VpnAppCatalog.findByPackageName(it) }
                val metadata = VpnAppMetadataScanner.scan(
                    context = context,
                    packageName = record.packageName,
                    serviceNames = listOfNotNull(record.serviceName),
                )
                val appLabel = VpnAppMetadataScanner.resolveAppLabel(context, record.packageName)
                val confidence = when {
                    signature != null -> EvidenceConfidence.HIGH
                    record.packageName != null -> EvidenceConfidence.MEDIUM
                    else -> EvidenceConfidence.LOW
                }
                val serviceDisplay = if (record.packageName != null && record.serviceName != null) {
                    "${record.packageName}/${record.serviceName}"
                } else {
                    record.rawLine
                }
                val familySuffix = signature?.family?.let { " [$it]" }.orEmpty()
                val description = buildString {
                    append(context.getString(R.string.checker_indirect_dumpsys_service_active, serviceDisplay))
                    appLabel?.let { append(" ($it)") }
                    append(familySuffix)
                    append(VpnAppMetadataScanner.formatMetadataSuffix(metadata))
                }
                findings.add(
                    Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                        family = signature?.family,
                        packageName = record.packageName,
                    ),
                )
                evidence.add(
                    EvidenceItem(
                        source = EvidenceSource.ACTIVE_VPN,
                        detected = true,
                        confidence = confidence,
                        description = serviceDisplay,
                        family = signature?.family,
                        packageName = record.packageName,
                        kind = signature?.kind,
                    ),
                )
                activeApps.add(
                    ActiveVpnApp(
                        packageName = record.packageName,
                        serviceName = record.serviceName,
                        family = signature?.family,
                        kind = signature?.kind,
                        source = EvidenceSource.ACTIVE_VPN,
                        confidence = confidence,
                        technicalMetadata = metadata,
                    ),
                )
                detected = true
                needsReview = needsReview || signature == null
            }

            SignalOutcome(detected = detected, needsReview = needsReview)
        } catch (e: Exception) {
            findings.add(Finding(context.getString(R.string.checker_indirect_dumpsys_service_error, e.message)))
            SignalOutcome()
        }
    }

    internal fun classifyDnsAddress(addr: String): DnsClassification {
        val normalized = normalizeIpAddress(addr)
        val parsedAddress = parseInetAddressOrNull(normalized)
        if (parsedAddress?.isLoopbackAddress == true) return DnsClassification.LOOPBACK
        if (parsedAddress?.isLinkLocalAddress == true) return DnsClassification.LINK_LOCAL
        if (parsedAddress != null && isPrivateDnsAddress(parsedAddress)) return DnsClassification.PRIVATE_NETWORK
        if (normalized in KNOWN_PUBLIC_RESOLVERS) return DnsClassification.KNOWN_PUBLIC_RESOLVER
        return DnsClassification.OTHER_PUBLIC
    }

    private fun buildSnapshotIndex(networkSnapshots: List<NetworkSnapshot>): Map<String, NetworkSnapshot> {
        val snapshotsByInterface = LinkedHashMap<String, NetworkSnapshot>()
        for (snapshot in networkSnapshots) {
            val interfaceName = snapshot.interfaceName ?: continue
            snapshotsByInterface.putIfAbsent(interfaceName, snapshot)
        }
        return snapshotsByInterface
    }

    private fun Map<String, NetworkSnapshot>.snapshotFor(name: String?): NetworkSnapshot? {
        val canonicalName = NetworkInterfaceNameNormalizer.canonicalName(name) ?: return null
        return this[canonicalName]
    }

    private fun yesNo(context: Context, value: Boolean): String {
        return context.getString(if (value) R.string.checker_yes else R.string.checker_no)
    }
}
