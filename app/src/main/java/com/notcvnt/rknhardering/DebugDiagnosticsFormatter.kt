package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.LocalProxyCheckResult
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.probe.NativeInterfaceProbe
import com.notcvnt.rknhardering.probe.NativeSignsBridge
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayOutboundSummary
import java.net.NetworkInterface
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DebugDiagnosticsFormatter {

    fun format(
        result: CheckResult,
        settings: CheckSettings,
        privacyMode: Boolean,
        timestampMillis: Long = System.currentTimeMillis(),
        appVersionName: String = BuildConfig.VERSION_NAME,
        buildType: String = BuildConfig.BUILD_TYPE,
    ): String {
        val builder = StringBuilder()
        builder.appendLine("timestamp: ${formatTimestamp(timestampMillis)}")
        builder.appendLine("app: $appVersionName ($buildType)")
        builder.appendLine("debugDiagnosticsEnabled: ${settings.tunProbeDebugEnabled}")
        builder.appendLine("privacyMode: $privacyMode")
        builder.appendLine("splitTunnelEnabled: ${settings.splitTunnelEnabled}")
        builder.appendLine("proxyScanEnabled: ${settings.proxyScanEnabled}")
        builder.appendLine("xrayApiScanEnabled: ${settings.xrayApiScanEnabled}")
        builder.appendLine("networkRequestsEnabled: ${settings.networkRequestsEnabled}")
        builder.appendLine("cdnPullingEnabled: ${settings.cdnPullingEnabled}")
        builder.appendLine("callTransportProbeEnabled: ${settings.callTransportProbeEnabled}")
        builder.appendLine("tunProbeModeOverride: ${settings.tunProbeModeOverride.name}")
        appendResolver(builder, settings)
        builder.appendLine("verdict: ${result.verdict}")

        appendCategory(builder, "geoIp", result.geoIp)
        appendIpComparison(builder, result.ipComparison)
        appendCdnPulling(builder, result.cdnPulling)
        appendCategory(builder, "directSigns", result.directSigns)
        appendCategory(builder, "indirectSigns", result.indirectSigns)
        appendCategory(builder, "locationSignals", result.locationSignals)
        appendBypass(builder, result.bypassResult)
        appendCategory(builder, "nativeSigns", result.nativeSigns)
        appendNativeSignsRaw(builder, privacyMode)

        builder.appendLine()
        builder.appendLine("[tunProbe]")
        val tunDiagnostics = result.tunProbeDiagnostics
        if (tunDiagnostics == null) {
            builder.appendLine("collected: false")
        } else {
            builder.appendLine("collected: true")
            builder.append(TunProbeDiagnosticsFormatter.formatSection(tunDiagnostics, settings))
            builder.appendLine()
        }
        return builder.toString().trimEnd()
    }

    private fun appendNativeSignsRaw(builder: StringBuilder, privacyMode: Boolean) {
        builder.appendLine()
        builder.appendLine("[nativeSigns.raw]")
        val loaded = runCatching { NativeSignsBridge.isLibraryLoaded() }.getOrDefault(false)
        builder.appendLine("libraryLoaded: $loaded")
        if (!loaded) {
            return
        }

        builder.appendLine("-- ifconfig-like dump (getifaddrs + /sys/class/net) --")
        val dump = runCatching { NativeSignsBridge.interfaceDump() }.getOrDefault(emptyArray())
        if (dump.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            dump.forEach { block ->
                builder.appendLine(maskInterfaceDumpBlock(block.trimEnd()))
                builder.appendLine()
            }
        }

        builder.appendLine("-- getifaddrs() rows (pipe-delimited) --")
        val rows = runCatching { NativeSignsBridge.getIfAddrs() }.getOrDefault(emptyArray())
        if (rows.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            rows.forEach { row -> builder.appendLine(maskIfAddrsRow(row)) }
        }

        builder.appendLine()
        builder.appendLine("-- Routes via AF_NETLINK NETLINK_ROUTE RTM_GETROUTE (IPv4+IPv6) --")
        val nlRoutes = runCatching { NativeSignsBridge.netlinkRouteDump(0) }.getOrDefault(emptyArray())
        if (nlRoutes.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            nlRoutes.forEach { builder.appendLine(maskNetlinkPipeRow(it)) }
        }

        builder.appendLine()
        builder.appendLine("-- TCP sockets via AF_NETLINK NETLINK_SOCK_DIAG (IPv4) --")
        val nlTcp4 = runCatching { NativeSignsBridge.netlinkSockDiag(2, 6) }.getOrDefault(emptyArray())
        if (nlTcp4.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            nlTcp4.take(60).forEach { builder.appendLine(maskNetlinkPipeRow(it)) }
            if (nlTcp4.size > 60) builder.appendLine("... (${nlTcp4.size - 60} more truncated)")
        }

        builder.appendLine()
        builder.appendLine("-- TCP sockets via AF_NETLINK NETLINK_SOCK_DIAG (IPv6) --")
        val nlTcp6 = runCatching { NativeSignsBridge.netlinkSockDiag(10, 6) }.getOrDefault(emptyArray())
        if (nlTcp6.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            nlTcp6.take(60).forEach { builder.appendLine(maskNetlinkPipeRow(it)) }
            if (nlTcp6.size > 60) builder.appendLine("... (${nlTcp6.size - 60} more truncated)")
        }

        builder.appendLine()
        builder.appendLine("-- UDP sockets via AF_NETLINK NETLINK_SOCK_DIAG (IPv4) --")
        val nlUdp4 = runCatching { NativeSignsBridge.netlinkSockDiag(2, 17) }.getOrDefault(emptyArray())
        if (nlUdp4.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            nlUdp4.take(60).forEach { builder.appendLine(maskNetlinkPipeRow(it)) }
            if (nlUdp4.size > 60) builder.appendLine("... (${nlUdp4.size - 60} more truncated)")
        }

        builder.appendLine()
        builder.appendLine("-- /proc/net/route (native fopen, fallback) --")
        val routeContent = runCatching { NativeSignsBridge.readProcFile("/proc/net/route") }.getOrNull()
            ?: runCatching { NativeSignsBridge.readProcFile("/proc/self/net/route") }.getOrNull()
        builder.appendLine(renderProcContent(routeContent))

        builder.appendLine()
        builder.appendLine("-- /proc/net/ipv6_route (native fopen, fallback) --")
        val v6Route = runCatching { NativeSignsBridge.readProcFile("/proc/net/ipv6_route") }.getOrNull()
            ?: runCatching { NativeSignsBridge.readProcFile("/proc/self/net/ipv6_route") }.getOrNull()
        builder.appendLine(renderProcContent(v6Route))

        builder.appendLine()
        builder.appendLine("-- /proc/net/dev (native fopen, fallback) --")
        val devContent = runCatching { NativeSignsBridge.readProcFile("/proc/net/dev") }.getOrNull()
        builder.appendLine(renderProcContent(devContent))

        builder.appendLine()
        builder.appendLine("-- /proc/self/maps markers (native classification) --")
        val mapsFindings = runCatching { NativeInterfaceProbe.collectMapsFindings() }.getOrDefault(emptyList())
        if (mapsFindings.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            mapsFindings.forEach { f ->
                builder.appendLine("kind=${f.kind} marker=${f.marker ?: "<none>"} detail=${f.detail ?: "<none>"}")
            }
        }

        builder.appendLine()
        builder.appendLine("-- libraryIntegrity (dlsym+dladdr) --")
        val integrity = runCatching { NativeInterfaceProbe.collectLibraryIntegrity() }.getOrDefault(emptyList())
        if (integrity.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            integrity.forEach { sym ->
                builder.appendLine(
                    "symbol=${sym.symbol} missing=${sym.missing} addr=${sym.address ?: "<none>"} lib=${sym.library ?: "<none>"}",
                )
            }
        }

        builder.appendLine()
        builder.appendLine("-- probeFeatureFlags --")
        val flags = runCatching { NativeSignsBridge.probeFeatureFlags() }.getOrDefault(emptyArray())
        if (flags.isEmpty()) {
            builder.appendLine("<empty>")
        } else {
            flags.forEach { builder.appendLine(it) }
        }

        builder.appendLine()
        builder.appendLine("-- JVM NetworkInterface.getNetworkInterfaces() --")
        val jvmDump = runCatching { renderJvmInterfaces(privacyMode) }.getOrDefault("<error>")
        builder.appendLine(jvmDump)
    }

    private fun maskInterfaceDumpBlock(block: String): String {
        return block.lines().joinToString("\n") { line ->
            val trimmed = line.trimStart()
            val leading = line.substring(0, line.length - trimmed.length)
            when {
                trimmed.startsWith("inet ") -> {
                    val rest = trimmed.removePrefix("inet ")
                    val addr = rest.substringBefore(' ')
                    val tail = rest.substringAfter(' ', missingDelimiterValue = "")
                    val maskedAddr = maskIp(addr)
                    val maskedTail = maskBroadcastOrDestinationToken(tail)
                    if (tail.isBlank()) "${leading}inet $maskedAddr" else "${leading}inet $maskedAddr $maskedTail"
                }
                trimmed.startsWith("inet6 ") -> {
                    val rest = trimmed.removePrefix("inet6 ")
                    val addr = rest.substringBefore(' ')
                    val tail = rest.substringAfter(' ', missingDelimiterValue = "")
                    val maskedAddr = maskIp(addr)
                    val maskedTail = maskBroadcastOrDestinationToken(tail)
                    if (tail.isBlank()) "${leading}inet6 $maskedAddr" else "${leading}inet6 $maskedAddr $maskedTail"
                }
                else -> line
            }
        }
    }

    private fun maskBroadcastOrDestinationToken(tail: String): String {
        if (tail.isBlank()) return tail
        val tokens = tail.split(' ').toMutableList()
        var i = 0
        while (i < tokens.size - 1) {
            val key = tokens[i]
            if (key == "broadcast" || key == "destination") {
                tokens[i + 1] = maskIp(tokens[i + 1])
                i += 2
            } else {
                i += 1
            }
        }
        return tokens.joinToString(" ")
    }

    private fun maskNetlinkPipeRow(row: String): String {
        if (!row.contains('|')) return row
        val ipKeys = setOf("dst", "via", "src", "prefsrc")
        val endpointKeys = setOf("src", "dst")
        val parts = row.split('|').toMutableList()
        for (i in parts.indices) {
            val token = parts[i]
            val eq = token.indexOf('=')
            if (eq <= 0) continue
            val key = token.substring(0, eq)
            val value = token.substring(eq + 1)
            if (key !in ipKeys && key !in endpointKeys) continue

            if (key in endpointKeys && value.count { it == ':' } >= 1) {
                val lastColon = value.lastIndexOf(':')
                if (lastColon > 0) {
                    val port = value.substring(lastColon + 1)
                    if (port.all(Char::isDigit)) {
                        val addr = value.substring(0, lastColon)
                        parts[i] = "$key=${maskIp(addr)}:$port"
                        continue
                    }
                }
            }
            val slash = value.indexOf('/')
            if (slash > 0) {
                val addr = value.substring(0, slash)
                val suffix = value.substring(slash)
                parts[i] = "$key=${maskIp(addr)}$suffix"
            } else if (value.equals("default", ignoreCase = true)) {
                parts[i] = token
            } else {
                parts[i] = "$key=${maskIp(value)}"
            }
        }
        return parts.joinToString("|")
    }

    private fun maskIfAddrsRow(row: String): String {
        val parts = row.split('|').toMutableList()
        if (parts.size < 7) return row
        val addr = parts[4]
        if (addr.isNotBlank()) parts[4] = maskIp(addr)
        return parts.joinToString("|")
    }

    private fun renderProcContent(content: String?, maxLines: Int = 0): String {
        if (content == null) return "<unavailable (null)>"
        if (content.isEmpty()) return "<empty>"
        val masked = maskIpsInText(content).trimEnd()
        if (maxLines <= 0) return masked
        val lines = masked.lines()
        if (lines.size <= maxLines) return masked
        return (lines.take(maxLines).joinToString("\n")) + "\n... (${lines.size - maxLines} more lines truncated)"
    }

    private fun renderJvmInterfaces(privacyMode: Boolean): String {
        val ifaces = NetworkInterface.getNetworkInterfaces() ?: return "<none>"
        val sb = StringBuilder()
        while (ifaces.hasMoreElements()) {
            val iface = ifaces.nextElement() ?: continue
            val name = iface.name ?: "?"
            val index = runCatching { iface.index }.getOrDefault(0)
            val mtu = runCatching { iface.mtu }.getOrDefault(-1)
            val up = runCatching { iface.isUp }.getOrDefault(false)
            val loop = runCatching { iface.isLoopback }.getOrDefault(false)
            val p2p = runCatching { iface.isPointToPoint }.getOrDefault(false)
            val virt = runCatching { iface.isVirtual }.getOrDefault(false)
            sb.append(name)
            sb.append(": index=").append(index)
            sb.append(" mtu=").append(mtu)
            sb.append(" up=").append(up)
            sb.append(" loopback=").append(loop)
            sb.append(" p2p=").append(p2p)
            sb.append(" virtual=").append(virt)
            sb.append('\n')
            val addrs = iface.inetAddresses
            while (addrs.hasMoreElements()) {
                val addr = addrs.nextElement() ?: continue
                val host = addr.hostAddress?.substringBefore('%') ?: continue
                val rendered = if (privacyMode) maskIp(host) else host
                sb.append("  addr ").append(rendered).append('\n')
            }
        }
        if (sb.isEmpty()) return "<none>"
        return sb.toString().trimEnd()
    }

    private fun appendCategory(
        builder: StringBuilder,
        key: String,
        category: CategoryResult,
    ) {
        builder.appendLine()
        builder.appendLine("[$key]")
        builder.appendLine("name: ${category.name}")
        builder.appendLine("detected: ${category.detected}")
        builder.appendLine("needsReview: ${category.needsReview}")
        builder.appendLine("hasError: ${category.hasError}")
        builder.appendLine("findingsCount: ${category.findings.size}")
        builder.appendLine("evidenceCount: ${category.evidence.size}")
        builder.appendLine("matchedAppsCount: ${category.matchedApps.size}")
        builder.appendLine("activeAppsCount: ${category.activeApps.size}")
        builder.appendLine("callTransportCount: ${category.callTransportLeaks.size}")
        builder.appendLine("findings:")
        if (category.findings.isEmpty()) {
            builder.appendLine("- <none>")
        } else {
            category.findings.forEach { finding ->
                builder.appendLine("- ${formatFinding(finding)}")
            }
        }

        appendNamedCollection(builder, "evidence", category.evidence, ::formatEvidence)
        appendNamedCollection(builder, "matchedApps", category.matchedApps, ::formatMatchedVpnApp)
        appendNamedCollection(builder, "activeApps", category.activeApps, ::formatActiveVpnApp)
        appendNamedCollection(builder, "callTransport", category.callTransportLeaks, ::formatCallTransportLeak)
    }

    private fun appendIpComparison(
        builder: StringBuilder,
        ipComparison: IpComparisonResult,
    ) {
        builder.appendLine()
        builder.appendLine("[ipComparison]")
        builder.appendLine("detected: ${ipComparison.detected}")
        builder.appendLine("needsReview: ${ipComparison.needsReview}")
        builder.appendLine("summary: ${maskIpsInText(ipComparison.summary)}")
        appendIpCheckerGroup(builder, "ru", ipComparison.ruGroup)
        appendIpCheckerGroup(builder, "nonRu", ipComparison.nonRuGroup)
    }

    private fun appendBypass(
        builder: StringBuilder,
        bypass: BypassResult,
    ) {
        builder.appendLine()
        builder.appendLine("[bypass]")
        builder.appendLine("detected: ${bypass.detected}")
        builder.appendLine("needsReview: ${bypass.needsReview}")
        builder.appendLine("directIp: ${bypass.directIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("proxyIp: ${bypass.proxyIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("vpnNetworkIp: ${bypass.vpnNetworkIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("underlyingIp: ${bypass.underlyingIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("proxyEndpoint: ${formatProxyEndpoint(bypass)}")
        builder.appendLine("proxyOwner: ${formatProxyOwner(bypass.proxyOwner)}")
        builder.appendLine("xrayApi: ${formatXrayApiHeader(bypass.xrayApiScanResult)}")
        builder.appendLine("findings:")
        if (bypass.findings.isEmpty()) {
            builder.appendLine("- <none>")
        } else {
            bypass.findings.forEach { finding ->
                builder.appendLine("- ${formatFinding(finding)}")
            }
        }
        appendNamedCollection(
            builder = builder,
            label = "evidence",
            items = bypass.evidence,
            formatter = ::formatEvidence,
        )
        appendNamedCollection(
            builder = builder,
            label = "proxyChecks",
            items = bypass.proxyChecks,
            formatter = ::formatProxyCheck,
        )
        appendNamedCollection(
            builder = builder,
            label = "xrayOutbounds",
            items = bypass.xrayApiScanResult?.outbounds.orEmpty(),
            formatter = ::formatXrayOutbound,
        )
    }

    private fun appendCdnPulling(
        builder: StringBuilder,
        result: CdnPullingResult,
    ) {
        builder.appendLine()
        builder.appendLine("[cdnPulling]")
        builder.appendLine("detected: ${result.detected}")
        builder.appendLine("needsReview: ${result.needsReview}")
        builder.appendLine("hasError: ${result.hasError}")
        builder.appendLine("summary: ${maskIpsInText(result.summary)}")
        builder.appendLine("findings:")
        if (result.findings.isEmpty()) {
            builder.appendLine("- <none>")
        } else {
            result.findings.forEach { finding ->
                builder.appendLine("- ${formatFinding(finding)}")
            }
        }
        builder.appendLine("responses:")
        if (result.responses.isEmpty()) {
            builder.appendLine("- <none>")
            return
        }
        result.responses.forEach { response ->
            builder.appendLine("- ${formatCdnPullingResponse(response)}")
        }
    }

    private fun appendResolver(
        builder: StringBuilder,
        settings: CheckSettings,
    ) {
        val resolver = settings.resolverConfig
        builder.appendLine("resolverMode: ${resolver.mode}")
        builder.appendLine("resolverPreset: ${resolver.preset}")
        builder.appendLine(
            "resolverDirectServers: ${
                resolver.effectiveDirectServers().joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
            }",
        )
        builder.appendLine("resolverDohUrl: ${resolver.effectiveDohUrl() ?: "<none>"}")
        builder.appendLine(
            "resolverDohBootstrap: ${
                resolver.effectiveDohBootstrapHosts().joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
            }",
        )
    }

    private fun appendIpCheckerGroup(
        builder: StringBuilder,
        label: String,
        group: IpCheckerGroupResult,
    ) {
        builder.appendLine("$label.title: ${group.title}")
        builder.appendLine("$label.detected: ${group.detected}")
        builder.appendLine("$label.needsReview: ${group.needsReview}")
        builder.appendLine("$label.statusLabel: ${group.statusLabel}")
        builder.appendLine("$label.summary: ${maskIpsInText(group.summary)}")
        builder.appendLine("$label.canonicalIp: ${group.canonicalIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("$label.ignoredIpv6ErrorCount: ${group.ignoredIpv6ErrorCount}")
        builder.appendLine("$label.responses:")
        if (group.responses.isEmpty()) {
            builder.appendLine("- <none>")
            return
        }
        group.responses.forEach { response ->
            builder.appendLine("- ${formatIpCheckerResponse(response)}")
        }
    }

    private fun <T> appendNamedCollection(
        builder: StringBuilder,
        label: String,
        items: List<T>,
        formatter: (T) -> String,
    ) {
        builder.appendLine("$label:")
        if (items.isEmpty()) {
            builder.appendLine("- <none>")
            return
        }
        items.forEach { item ->
            builder.appendLine("- ${formatter(item)}")
        }
    }

    private fun formatFinding(finding: Finding): String {
        return buildList {
            add("description=${maskIpsInText(finding.description)}")
            add("detected=${finding.detected}")
            add("needsReview=${finding.needsReview}")
            add("error=${finding.isError}")
            add("informational=${finding.isInformational}")
            finding.source?.let { add("source=$it") }
            finding.confidence?.let { add("confidence=$it") }
            finding.family?.let { add("family=$it") }
            finding.packageName?.let { add("package=$it") }
        }.joinToString(" ")
    }

    private fun formatEvidence(item: EvidenceItem): String {
        return buildList {
            add("source=${item.source}")
            add("detected=${item.detected}")
            add("confidence=${item.confidence}")
            item.kind?.let { add("kind=$it") }
            item.family?.let { add("family=$it") }
            item.packageName?.let { add("package=$it") }
            add("description=${maskIpsInText(item.description)}")
        }.joinToString(" ")
    }

    private fun formatMatchedVpnApp(app: MatchedVpnApp): String {
        return buildList {
            add("appName=${app.appName}")
            add("package=${app.packageName}")
            app.family?.let { add("family=$it") }
            add("kind=${app.kind}")
            add("source=${app.source}")
            add("active=${app.active}")
            add("confidence=${app.confidence}")
        }.joinToString(" ")
    }

    private fun formatActiveVpnApp(app: ActiveVpnApp): String {
        return buildList {
            add("package=${app.packageName ?: "<none>"}")
            add("serviceName=${app.serviceName ?: "<none>"}")
            add("family=${app.family ?: "<none>"}")
            add("kind=${app.kind ?: "<none>"}")
            add("source=${app.source}")
            add("confidence=${app.confidence}")
        }.joinToString(" ")
    }

    private fun formatCallTransportLeak(leak: CallTransportLeakResult): String {
        return buildList {
            add("service=${leak.service}")
            add("probeKind=${leak.probeKind}")
            add("networkPath=${leak.networkPath}")
            add("status=${leak.status}")
            leak.targetHost?.let { add("targetHost=${maskHostOrIp(it)}") }
            leak.targetPort?.let { add("targetPort=$it") }
            add(
                "resolvedIps=${
                    leak.resolvedIps.joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
                }",
            )
            leak.mappedIp?.let { add("mappedIp=${maskIp(it)}") }
            leak.observedPublicIp?.let { add("observedPublicIp=${maskIp(it)}") }
            leak.confidence?.let { add("confidence=$it") }
            add("experimental=${leak.experimental}")
            add("summary=${maskIpsInText(leak.summary)}")
        }.joinToString(" ")
    }

    private fun formatProxyCheck(proxyCheck: LocalProxyCheckResult): String {
        return buildList {
            add("endpoint=${formatHostPort(proxyCheck.endpoint.host, proxyCheck.endpoint.port)}")
            add("type=${proxyCheck.endpoint.type}")
            add("ownerStatus=${proxyCheck.ownerStatus}")
            add("owner=${formatProxyOwner(proxyCheck.owner)}")
            add("proxyIp=${proxyCheck.proxyIp?.let(::maskIp) ?: "<none>"}")
            add("status=${proxyCheck.status}")
            add("mtProtoReachable=${proxyCheck.mtProtoReachable?.toString() ?: "<not-run>"}")
            add("mtProtoTarget=${proxyCheck.mtProtoTarget?.let(::maskHostPort) ?: "<none>"}")
            add("summaryReason=${proxyCheck.summaryReason ?: "<none>"}")
        }.joinToString(" ")
    }

    private fun formatIpCheckerResponse(response: IpCheckerResponse): String {
        return buildList {
            add("label=${response.label}")
            add("scope=${response.scope}")
            add("url=${response.url}")
            add("ip=${response.ip?.let(::maskIp) ?: "<none>"}")
            add("error=${response.error?.let(::maskIpsInText) ?: "<none>"}")
            add(
                "ipv4Records=${
                    response.ipv4Records.joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
                }",
            )
            add(
                "ipv6Records=${
                    response.ipv6Records.joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
                }",
            )
            add("ignoredIpv6Error=${response.ignoredIpv6Error}")
        }.joinToString(" ")
    }

    private fun formatCdnPullingResponse(response: CdnPullingResponse): String {
        return buildList {
            add("target=${response.targetLabel}")
            add("url=${response.url}")
            add("ip=${response.ip?.let(::maskIp) ?: "<none>"}")
            add("error=${response.error?.let(::maskIpsInText) ?: "<none>"}")
            add(
                "importantFields=${
                    response.importantFields.entries.joinToString(", ") { entry ->
                        "${entry.key}=${maskIpsInText(entry.value)}"
                    }.ifBlank { "<none>" }
                }",
            )
            add("rawBody=${formatRawBody(response.rawBody)}")
        }.joinToString(" ")
    }

    private fun formatProxyEndpoint(bypass: BypassResult): String {
        val proxyEndpoint = bypass.proxyEndpoint ?: return "<none>"
        return "${maskHostOrIp(proxyEndpoint.host)}:${proxyEndpoint.port} (${proxyEndpoint.type})"
    }

    private fun formatRawBody(rawBody: String?): String {
        val normalized = rawBody?.trim().orEmpty()
        if (normalized.isBlank()) return "<none>"
        return maskIpsInText(normalized).replace("\n", "\\n")
    }

    private fun formatProxyOwner(owner: LocalProxyOwner?): String {
        if (owner == null) return "<none>"
        return buildList {
            add("uid=${owner.uid}")
            add("confidence=${owner.confidence}")
            add("apps=${owner.appLabels.joinToString(", ").ifBlank { "<none>" }}")
            add("packages=${owner.packageNames.joinToString(", ").ifBlank { "<none>" }}")
        }.joinToString(" ")
    }

    private fun formatXrayApiHeader(scanResult: XrayApiScanResult?): String {
        if (scanResult == null) return "<none>"
        return "endpoint=${maskHostOrIp(scanResult.endpoint.host)}:${scanResult.endpoint.port} outboundCount=${scanResult.outbounds.size}"
    }

    private fun formatHostPort(host: String, port: Int): String {
        return if (host.contains(':')) "[${maskHostOrIp(host)}]:$port" else "${maskHostOrIp(host)}:$port"
    }

    private fun maskHostPort(value: String): String {
        val separatorIndex = value.lastIndexOf(':')
        if (separatorIndex <= 0 || separatorIndex == value.lastIndex) {
            return maskHostOrIp(value)
        }
        val port = value.substring(separatorIndex + 1)
        if (!port.all(Char::isDigit)) {
            return maskHostOrIp(value)
        }
        val host = value.substring(0, separatorIndex)
        return "${maskHostOrIp(host)}:$port"
    }

    private fun formatXrayOutbound(outbound: XrayOutboundSummary): String {
        return buildList {
            add("tag=${outbound.tag}")
            add("protocol=${outbound.protocolName ?: "<none>"}")
            add("address=${outbound.address?.let(::maskHostOrIp) ?: "<none>"}")
            add("port=${outbound.port ?: "<none>"}")
            add("sni=${outbound.sni ?: "<none>"}")
            add("senderSettingsType=${outbound.senderSettingsType ?: "<none>"}")
            add("proxySettingsType=${outbound.proxySettingsType ?: "<none>"}")
            add("uuidPresent=${!outbound.uuid.isNullOrBlank()}")
            add("publicKeyPresent=${!outbound.publicKey.isNullOrBlank()}")
        }.joinToString(" ")
    }

    private fun maskHostOrIp(value: String): String {
        return if (isIpLiteral(value)) maskIp(value) else value
    }

    private fun isIpLiteral(value: String): Boolean {
        if (value.matches(IPV4_LITERAL)) return true
        return value.contains(':') && value.all { char ->
            char.isDigit() || char.lowercaseChar() in 'a'..'f' || char == ':' || char == '%'
        }
    }

    private fun formatTimestamp(timestampMillis: Long): String {
        return SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date(timestampMillis))
    }

    private val IPV4_LITERAL = Regex("""^(?:\d{1,3}\.){3}\d{1,3}$""")
}
