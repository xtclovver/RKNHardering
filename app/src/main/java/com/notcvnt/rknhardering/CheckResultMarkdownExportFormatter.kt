package com.notcvnt.rknhardering

import android.content.Context
import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.LocalProxyCheckResult
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VpnAppTechnicalMetadata
import com.notcvnt.rknhardering.probe.XrayOutboundSummary

internal object CheckResultMarkdownExportFormatter {

    fun format(
        context: Context,
        snapshot: CompletedExportSnapshot,
        appVersionName: String = BuildConfig.VERSION_NAME,
        buildType: String = BuildConfig.BUILD_TYPE,
    ): String {
        val narrative = VerdictNarrativeBuilder.build(context, snapshot.result, snapshot.privacyMode)
        val result = snapshot.result
        val builder = StringBuilder()

        builder.appendLine("# RKNHardering Scan Report")
        builder.appendLine()
        appendSummaryBlock(builder, narrative, snapshot)
        builder.appendLine()
        appendVerdictSection(builder, narrative, snapshot.result.verdict)
        builder.appendLine()
        appendSectionSummary(builder, context, snapshot)
        builder.appendLine()
        appendCategorySection(builder, context.getString(R.string.main_card_geo_ip), result.geoIp, snapshot.privacyMode)
        appendIpComparisonSection(builder, context, result.ipComparison, snapshot.privacyMode)
        appendCdnPullingSection(builder, context, result.cdnPulling, snapshot.privacyMode)
        appendCategorySection(builder, context.getString(R.string.main_card_direct_signs), result.directSigns, snapshot.privacyMode)
        appendCategorySection(builder, context.getString(R.string.main_card_indirect_signs), result.indirectSigns, snapshot.privacyMode)
        appendCategorySection(builder, context.getString(R.string.main_card_icmp_spoofing), result.icmpSpoofing, snapshot.privacyMode)
        appendCategorySection(builder, context.getString(R.string.main_card_location_signals), result.locationSignals, snapshot.privacyMode)
        appendIpChannelsSection(builder, result.ipConsensus, snapshot.privacyMode)
        appendBypassSection(builder, context, result.bypassResult, snapshot.privacyMode)
        builder.appendLine("## Footer")
        builder.appendLine("- Timestamp: ${formatExportTimestamp(snapshot.finishedAtMillis)}")
        builder.appendLine("- App version: $appVersionName")
        builder.appendLine("- Build type: $buildType")
        builder.appendLine("- Privacy mode: ${if (snapshot.privacyMode) "ON" else "OFF"}")
        return builder.toString().trimEnd()
    }

    private fun appendSummaryBlock(
        builder: StringBuilder,
        narrative: VerdictNarrative,
        snapshot: CompletedExportSnapshot,
    ) {
        builder.appendLine("```text")
        builder.appendLine("RKNHardering Scan Report")
        builder.appendLine("=======================")
        builder.appendLine("VERDICT      : ${verdictStatusTag(snapshot.result.verdict)}")
        builder.appendLine("EXPOSURE     : ${narrative.exposureStatus.name}")
        builder.appendLine("PRIVACY MODE : ${if (snapshot.privacyMode) "ON" else "OFF"}")
        builder.appendLine("TIMESTAMP    : ${formatExportTimestamp(snapshot.finishedAtMillis)}")
        builder.appendLine("```")
    }

    private fun appendVerdictSection(
        builder: StringBuilder,
        narrative: VerdictNarrative,
        verdict: Verdict,
    ) {
        builder.appendLine("## Verdict")
        builder.appendLine("- Status: ${verdictStatusTag(verdict)}")
        builder.appendLine("- Explanation: ${narrative.explanation}")
        builder.appendLine()
        builder.appendLine("### What this means")
        appendStringList(builder, narrative.meaningRows)
        builder.appendLine()
        builder.appendLine("### What was discovered")
        if (narrative.discoveredRows.isEmpty()) {
            builder.appendLine("- <none>")
        } else {
            narrative.discoveredRows.forEach { row ->
                builder.appendLine("- ${row.label}: ${row.value}")
            }
        }
        builder.appendLine()
        builder.appendLine("### Why this verdict was reached")
        appendStringList(builder, narrative.reasonRows)
        builder.appendLine()
    }

    private fun appendSectionSummary(
        builder: StringBuilder,
        context: Context,
        snapshot: CompletedExportSnapshot,
    ) {
        val result = snapshot.result
        builder.appendLine("## Section Summary")
        builder.appendLine("| Section | Status | Summary |")
        builder.appendLine("| --- | --- | --- |")
        appendSectionSummaryRow(
            builder,
            title = context.getString(R.string.main_card_geo_ip),
            status = sectionStatusTag(result.geoIp.detected, result.geoIp.needsReview, result.geoIp.hasError),
            summary = buildCategorySummary(result.geoIp, snapshot.privacyMode),
        )
        appendSectionSummaryRow(
            builder,
            title = context.getString(R.string.main_card_ip_comparison),
            status = sectionStatusTag(result.ipComparison.detected, result.ipComparison.needsReview),
            summary = buildSummary(result.ipComparison.summary, snapshot.privacyMode),
        )
        appendSectionSummaryRow(
            builder,
            title = context.getString(R.string.main_card_cdn_pulling),
            status = sectionStatusTag(result.cdnPulling.detected, result.cdnPulling.needsReview, result.cdnPulling.hasError),
            summary = buildSummary(result.cdnPulling.summary, snapshot.privacyMode),
        )
        appendSectionSummaryRow(
            builder,
            title = context.getString(R.string.main_card_direct_signs),
            status = sectionStatusTag(result.directSigns.detected, result.directSigns.needsReview, result.directSigns.hasError),
            summary = buildCategorySummary(result.directSigns, snapshot.privacyMode),
        )
        appendSectionSummaryRow(
            builder,
            title = context.getString(R.string.main_card_indirect_signs),
            status = sectionStatusTag(result.indirectSigns.detected, result.indirectSigns.needsReview, result.indirectSigns.hasError),
            summary = buildCategorySummary(result.indirectSigns, snapshot.privacyMode),
        )
        appendSectionSummaryRow(
            builder,
            title = context.getString(R.string.main_card_icmp_spoofing),
            status = sectionStatusTag(result.icmpSpoofing.detected, result.icmpSpoofing.needsReview, result.icmpSpoofing.hasError),
            summary = buildCategorySummary(result.icmpSpoofing, snapshot.privacyMode),
        )
        appendSectionSummaryRow(
            builder,
            title = context.getString(R.string.main_card_location_signals),
            status = sectionStatusTag(result.locationSignals.detected, result.locationSignals.needsReview, result.locationSignals.hasError),
            summary = buildCategorySummary(result.locationSignals, snapshot.privacyMode),
        )
        appendSectionSummaryRow(
            builder,
            title = context.getString(R.string.settings_split_tunnel),
            status = sectionStatusTag(result.bypassResult.detected, result.bypassResult.needsReview),
            summary = buildBypassSummary(result.bypassResult, snapshot.privacyMode),
        )
    }

    private fun appendSectionSummaryRow(
        builder: StringBuilder,
        title: String,
        status: String,
        summary: String,
    ) {
        builder.appendLine("| ${escapeTableCell(title)} | ${escapeTableCell(status)} | ${escapeTableCell(summary)} |")
    }

    private fun appendCategorySection(
        builder: StringBuilder,
        title: String,
        category: CategoryResult,
        privacyMode: Boolean,
    ) {
        builder.appendLine("## $title")
        builder.appendLine("- Status: ${sectionStatusTag(category.detected, category.needsReview, category.hasError)}")
        builder.appendLine("- Name: ${maskExportValue(category.name, privacyMode)}")
        builder.appendLine("- Findings count: ${category.findings.size}")
        builder.appendLine("- Evidence count: ${category.evidence.size}")
        builder.appendLine("- Matched apps: ${category.matchedApps.size}")
        builder.appendLine("- Active apps: ${category.activeApps.size}")
        builder.appendLine("- Call transport signals: ${category.callTransportLeaks.size}")
        builder.appendLine()
        builder.appendLine("### Findings")
        appendStringList(builder, category.findings.map { formatFinding(it, privacyMode) })
        builder.appendLine()
        builder.appendLine("### Evidence")
        appendStringList(builder, category.evidence.map { formatEvidence(it, privacyMode) })
        builder.appendLine()
        builder.appendLine("### Matched apps")
        appendStringList(builder, category.matchedApps.map(::formatMatchedApp))
        builder.appendLine()
        builder.appendLine("### Active apps")
        appendStringList(builder, category.activeApps.map(::formatActiveApp))
        builder.appendLine()
        builder.appendLine("### Call transport")
        appendStringList(builder, category.callTransportLeaks.map { formatCallTransportLeak(it, privacyMode) })
        builder.appendLine()
    }

    private fun appendIpComparisonSection(
        builder: StringBuilder,
        context: Context,
        result: IpComparisonResult,
        privacyMode: Boolean,
    ) {
        builder.appendLine("## ${context.getString(R.string.main_card_ip_comparison)}")
        builder.appendLine("- Status: ${sectionStatusTag(result.detected, result.needsReview)}")
        builder.appendLine("- Summary: ${buildSummary(result.summary, privacyMode)}")
        builder.appendLine()
        appendIpCheckerGroupSection(builder, "RU", result.ruGroup, privacyMode)
        appendIpCheckerGroupSection(builder, "NON_RU", result.nonRuGroup, privacyMode)
    }

    private fun appendIpCheckerGroupSection(
        builder: StringBuilder,
        label: String,
        group: IpCheckerGroupResult,
        privacyMode: Boolean,
    ) {
        builder.appendLine("### $label")
        builder.appendLine("- Status: ${sectionStatusTag(group.detected, group.needsReview)}")
        builder.appendLine("- Title: ${maskExportValue(group.title, privacyMode)}")
        builder.appendLine("- Status label: ${maskExportValue(group.statusLabel, privacyMode)}")
        builder.appendLine("- Summary: ${buildSummary(group.summary, privacyMode)}")
        builder.appendLine("- Canonical IP: ${maskExportIp(group.canonicalIp, privacyMode) ?: "<none>"}")
        builder.appendLine("- Ignored IPv6 errors: ${group.ignoredIpv6ErrorCount}")
        builder.appendLine("- Responses:")
        if (group.responses.isEmpty()) {
            builder.appendLine("  - <none>")
        } else {
            group.responses.forEach { response ->
                builder.appendLine("  - ${formatIpCheckerResponse(response, privacyMode)}")
            }
        }
        builder.appendLine()
    }

    private fun appendCdnPullingSection(
        builder: StringBuilder,
        context: Context,
        result: CdnPullingResult,
        privacyMode: Boolean,
    ) {
        builder.appendLine("## ${context.getString(R.string.main_card_cdn_pulling)}")
        builder.appendLine("- Status: ${sectionStatusTag(result.detected, result.needsReview, result.hasError)}")
        builder.appendLine("- Summary: ${buildSummary(result.summary, privacyMode)}")
        builder.appendLine()
        builder.appendLine("### Findings")
        appendStringList(builder, result.findings.map { formatFinding(it, privacyMode) })
        builder.appendLine()
        builder.appendLine("### Responses")
        if (result.responses.isEmpty()) {
            builder.appendLine("- <none>")
        } else {
            result.responses.forEachIndexed { index, response ->
                appendCdnPullingResponse(builder, index + 1, response, privacyMode)
            }
        }
        builder.appendLine()
    }

    private fun appendCdnPullingResponse(
        builder: StringBuilder,
        index: Int,
        response: CdnPullingResponse,
        privacyMode: Boolean,
    ) {
        builder.appendLine("#### Response $index: ${maskExportValue(response.targetLabel, privacyMode)}")
        builder.appendLine("- URL: ${maskExportValue(response.url, privacyMode)}")
        builder.appendLine("- IP: ${maskExportIp(response.ip, privacyMode) ?: "<none>"}")
        builder.appendLine("- Error: ${response.error?.let { maskExportValue(it, privacyMode) } ?: "<none>"}")
        builder.appendLine("- Important fields:")
        if (response.importantFields.isEmpty()) {
            builder.appendLine("  - <none>")
        } else {
            response.importantFields.forEach { (key, value) ->
                builder.appendLine("  - $key: ${maskExportValue(value, privacyMode)}")
            }
        }
        val rawBody = response.rawBody?.trim().orEmpty()
        if (rawBody.isNotBlank()) {
            builder.appendLine("- Raw body:")
            builder.appendLine("```text")
            builder.appendLine(maskExportValue(rawBody, privacyMode))
            builder.appendLine("```")
        }
    }

    private fun appendBypassSection(
        builder: StringBuilder,
        context: Context,
        bypass: BypassResult,
        privacyMode: Boolean,
    ) {
        builder.appendLine("## ${context.getString(R.string.settings_split_tunnel)}")
        builder.appendLine("- Status: ${sectionStatusTag(bypass.detected, bypass.needsReview)}")
        builder.appendLine("- Local proxy: ${bypass.proxyEndpoint?.let { formatExportHostPort(it.host, it.port, privacyMode) + " (${it.type})" } ?: "<none>"}")
        builder.appendLine("- Owner app: ${bypass.proxyOwner?.let { LocalProxyOwnerFormatter.format(context, it) } ?: "<none>"}")
        builder.appendLine("- Direct IP: ${maskExportIp(bypass.directIp, privacyMode) ?: "<none>"}")
        builder.appendLine("- Proxy IP: ${maskExportIp(bypass.proxyIp, privacyMode) ?: "<none>"}")
        builder.appendLine("- VPN network IP: ${maskExportIp(bypass.vpnNetworkIp, privacyMode) ?: "<none>"}")
        builder.appendLine("- Underlying IP: ${maskExportIp(bypass.underlyingIp, privacyMode) ?: "<none>"}")
        builder.appendLine("- Xray API: ${bypass.xrayApiScanResult?.let { formatExportHostPort(it.endpoint.host, it.endpoint.port, privacyMode) } ?: "<none>"}")
        builder.appendLine()
        builder.appendLine("### Findings")
        appendStringList(builder, bypass.findings.map { formatFinding(it, privacyMode) })
        builder.appendLine()
        builder.appendLine("### Evidence")
        appendStringList(builder, bypass.evidence.map { formatEvidence(it, privacyMode) })
        builder.appendLine()
        builder.appendLine("### Proxy checks")
        appendStringList(builder, bypass.proxyChecks.map { formatProxyCheck(it, privacyMode) })
        builder.appendLine()
        builder.appendLine("### Xray outbounds")
        appendStringList(builder, bypass.xrayApiScanResult?.outbounds.orEmpty().map { formatXrayOutbound(it, privacyMode) })
        builder.appendLine()
    }

    private fun formatFinding(finding: Finding, privacyMode: Boolean): String {
        return buildList {
            add(maskExportValue(finding.description, privacyMode))
            if (finding.detected) add("detected=true")
            if (finding.needsReview) add("needsReview=true")
            if (finding.isError) add("error=true")
            if (finding.isInformational) add("informational=true")
            finding.source?.let { add("source=$it") }
            finding.confidence?.let { add("confidence=$it") }
            finding.family?.let { add("family=$it") }
            finding.packageName?.let { add("package=$it") }
        }.joinToString(" | ")
    }

    private fun formatEvidence(item: EvidenceItem, privacyMode: Boolean): String {
        return buildList {
            add("source=${item.source}")
            add("detected=${item.detected}")
            add("confidence=${item.confidence}")
            item.kind?.let { add("kind=$it") }
            item.family?.let { add("family=$it") }
            item.packageName?.let { add("package=$it") }
            add("description=${maskExportValue(item.description, privacyMode)}")
        }.joinToString(" | ")
    }

    private fun formatMatchedApp(app: MatchedVpnApp): String {
        return buildList {
            add(app.appName)
            add("package=${app.packageName}")
            app.family?.let { add("family=$it") }
            add("kind=${app.kind}")
            add("source=${app.source}")
            add("active=${app.active}")
            add("confidence=${app.confidence}")
            addAll(formatTechnicalMetadata(app.technicalMetadata))
        }.joinToString(" | ")
    }

    private fun formatActiveApp(app: ActiveVpnApp): String {
        return buildList {
            add("package=${app.packageName ?: "<none>"}")
            add("service=${app.serviceName ?: "<none>"}")
            add("family=${app.family ?: "<none>"}")
            add("kind=${app.kind ?: "<none>"}")
            add("source=${app.source}")
            add("confidence=${app.confidence}")
            addAll(formatTechnicalMetadata(app.technicalMetadata))
        }.joinToString(" | ")
    }

    private fun formatTechnicalMetadata(metadata: VpnAppTechnicalMetadata?): List<String> {
        if (metadata == null) return emptyList()
        return buildList {
            metadata.versionName?.let { add("version=$it") }
            metadata.appType?.let { add("appType=$it") }
            metadata.coreType?.let { add("coreType=$it") }
            metadata.corePath?.let { add("corePath=$it") }
            metadata.goVersion?.let { add("goVersion=$it") }
            if (metadata.serviceNames.isNotEmpty()) add("services=${metadata.serviceNames.joinToString()}")
            if (metadata.systemApp) add("systemApp=true")
            if (metadata.matchedByNameHeuristic) add("matchedByName=true")
        }
    }

    private fun formatCallTransportLeak(
        leak: CallTransportLeakResult,
        privacyMode: Boolean,
    ): String {
        return buildList {
            add("service=${leak.service}")
            add("probeKind=${leak.probeKind}")
            add("path=${leak.networkPath}")
            add("status=${leak.status}")
            leak.targetHost?.let { add("target=${maskExportHostOrIp(it, privacyMode)}") }
            leak.targetPort?.let { add("targetPort=$it") }
            if (leak.resolvedIps.isNotEmpty()) {
                add("resolvedIps=${leak.resolvedIps.joinToString(", ") { maskExportIp(it, privacyMode) ?: it }}")
            }
            leak.mappedIp?.let { add("mappedIp=${maskExportIp(it, privacyMode)}") }
            leak.observedPublicIp?.let { add("observedPublicIp=${maskExportIp(it, privacyMode)}") }
            leak.confidence?.let { add("confidence=$it") }
            add("experimental=${leak.experimental}")
            add("summary=${maskExportValue(leak.summary, privacyMode)}")
        }.joinToString(" | ")
    }

    private fun formatIpCheckerResponse(
        response: IpCheckerResponse,
        privacyMode: Boolean,
    ): String {
        return buildList {
            add("label=${maskExportValue(response.label, privacyMode)}")
            add("scope=${response.scope}")
            add("url=${maskExportValue(response.url, privacyMode)}")
            add("ip=${maskExportIp(response.ip, privacyMode) ?: "<none>"}")
            add("error=${response.error?.let { maskExportValue(it, privacyMode) } ?: "<none>"}")
            add(
                "ipv4Records=${
                    response.ipv4Records.joinToString(", ") { maskExportIp(it, privacyMode) ?: it }.ifBlank { "<none>" }
                }",
            )
            add(
                "ipv6Records=${
                    response.ipv6Records.joinToString(", ") { maskExportIp(it, privacyMode) ?: it }.ifBlank { "<none>" }
                }",
            )
            add("ignoredIpv6Error=${response.ignoredIpv6Error}")
        }.joinToString(" | ")
    }

    private fun formatProxyCheck(
        proxyCheck: LocalProxyCheckResult,
        privacyMode: Boolean,
    ): String {
        return buildList {
            add("endpoint=${formatExportHostPort(proxyCheck.endpoint.host, proxyCheck.endpoint.port, privacyMode)}")
            add("type=${proxyCheck.endpoint.type}")
            add("ownerStatus=${proxyCheck.ownerStatus}")
            add("proxyIp=${maskExportIp(proxyCheck.proxyIp, privacyMode) ?: "<none>"}")
            add("status=${proxyCheck.status}")
            add("mtProtoReachable=${proxyCheck.mtProtoReachable?.toString() ?: "<not-run>"}")
            add("mtProtoTarget=${proxyCheck.mtProtoTarget?.let { maskExportHostPort(it, privacyMode) } ?: "<none>"}")
            add("summaryReason=${proxyCheck.summaryReason ?: "<none>"}")
        }.joinToString(" | ")
    }

    private fun formatXrayOutbound(
        outbound: XrayOutboundSummary,
        privacyMode: Boolean,
    ): String {
        return buildList {
            add("tag=${outbound.tag}")
            add("protocol=${outbound.protocolName ?: "<none>"}")
            add("address=${outbound.address?.let { maskExportHostOrIp(it, privacyMode) } ?: "<none>"}")
            add("port=${outbound.port ?: "<none>"}")
            add("sni=${outbound.sni ?: "<none>"}")
            add("senderSettingsType=${outbound.senderSettingsType ?: "<none>"}")
            add("proxySettingsType=${outbound.proxySettingsType ?: "<none>"}")
            add("uuidPresent=${!outbound.uuid.isNullOrBlank()}")
            add("publicKeyPresent=${!outbound.publicKey.isNullOrBlank()}")
        }.joinToString(" | ")
    }

    private fun buildCategorySummary(category: CategoryResult, privacyMode: Boolean): String {
        val primaryFinding = category.findings.firstOrNull()?.description
            ?: category.callTransportLeaks.firstOrNull()?.summary
        return buildSummary(primaryFinding, privacyMode)
    }

    private fun buildBypassSummary(bypass: BypassResult, privacyMode: Boolean): String {
        val finding = bypass.findings.firstOrNull()?.description
        if (!finding.isNullOrBlank()) {
            return buildSummary(finding, privacyMode)
        }
        val xray = bypass.xrayApiScanResult
            ?.let { formatExportHostPort(it.endpoint.host, it.endpoint.port, privacyMode) }
        return xray ?: "<none>"
    }

    private fun buildSummary(summary: String?, privacyMode: Boolean): String {
        val normalized = summary?.trim().orEmpty()
        if (normalized.isBlank()) return "<none>"
        return maskExportValue(normalized, privacyMode)
    }

    private fun appendStringList(builder: StringBuilder, items: List<String>) {
        if (items.isEmpty()) {
            builder.appendLine("- <none>")
            return
        }
        items.forEach { item -> builder.appendLine("- $item") }
    }

    private fun appendIpChannelsSection(
        builder: StringBuilder,
        consensus: IpConsensusResult,
        privacyMode: Boolean,
    ) {
        if (consensus.observedIps.isEmpty()) {
            return
        }
        builder.appendLine("## IP каналы")
        builder.appendLine("| Канал | Target | IP | Family | Страна | ASN | Источники |")
        builder.appendLine("| --- | --- | --- | --- | --- | --- | --- |")
        consensus.observedIps.forEach { ip ->
            val channel = escapeTableCell(ip.channel.name)
            val target = escapeTableCell(ip.targetGroup?.name ?: "-")
            val value = escapeTableCell(maskExportIp(ip.value, privacyMode) ?: ip.value)
            val family = escapeTableCell(ip.family.name)
            val country = escapeTableCell(ip.countryCode ?: "-")
            val asn = escapeTableCell(ip.asn ?: "-")
            val sources = escapeTableCell(ip.sources.joinToString(", "))
            builder.appendLine("| $channel | $target | $value | $family | $country | $asn | $sources |")
        }
        builder.appendLine()
        val flags = buildList {
            if (consensus.crossChannelMismatch) add("crossChannelMismatch=true")
            if (consensus.warpLikeIndicator) add("warpLikeIndicator=true")
            if (consensus.probeTargetDivergence) add("probeTargetDivergence=true")
            if (consensus.probeTargetDirectDivergence) add("probeTargetDirectDivergence=true")
            if (consensus.geoCountryMismatch) add("geoCountryMismatch=true")
            if (consensus.channelConflict.isNotEmpty()) add("channelConflict=${consensus.channelConflict.joinToString(", ")}")
            if (consensus.needsReview) add("needsReview=true")
        }
        if (flags.isNotEmpty()) {
            builder.appendLine("Флаги: ${flags.joinToString(", ")}")
        }
        builder.appendLine()
    }

    private fun escapeTableCell(value: String): String {
        return value.replace("|", "\\|").replace("\n", "<br>")
    }
}
