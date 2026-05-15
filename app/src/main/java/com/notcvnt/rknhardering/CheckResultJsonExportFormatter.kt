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
import com.notcvnt.rknhardering.model.GeoIpFacts
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.LocationSignalsFacts
import com.notcvnt.rknhardering.model.LocalProxyCheckResult
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.model.StunProbeGroupResult
import com.notcvnt.rknhardering.model.StunProbeResult
import com.notcvnt.rknhardering.model.VpnAppTechnicalMetadata
import com.notcvnt.rknhardering.probe.OperatorWhitelistProbeResult
import com.notcvnt.rknhardering.probe.PublicIpTransportDiagnostics
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.TunEndpointAttempt
import com.notcvnt.rknhardering.probe.TunProbeAttemptDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeDiagnostics
import com.notcvnt.rknhardering.probe.TunProbePathDiagnostics
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayOutboundSummary
import com.notcvnt.rknhardering.probe.XrayStatsSummary
import org.json.JSONArray
import org.json.JSONObject

internal object CheckResultJsonExportFormatter {

    fun format(
        context: Context,
        snapshot: CompletedExportSnapshot,
        appVersionName: String = BuildConfig.VERSION_NAME,
        buildType: String = BuildConfig.BUILD_TYPE,
    ): String {
        val narrative = VerdictNarrativeBuilder.build(context, snapshot.result, snapshot.privacyMode)
        val root = JSONObject()
        root.put(
            "meta",
            JSONObject().apply {
                put("formatVersion", 1)
                put("timestamp", formatExportTimestamp(snapshot.finishedAtMillis))
                put("appVersion", appVersionName)
                put("buildType", buildType)
                put("privacyMode", snapshot.privacyMode)
            },
        )
        root.put(
            "verdict",
            JSONObject().apply {
                put("value", snapshot.result.verdict.name)
                put("status", verdictStatusTag(snapshot.result.verdict))
                put("explanation", narrative.explanation)
                put("exposureStatus", narrative.exposureStatus.name)
                put("meaning", jsonArray(narrative.meaningRows))
                put(
                    "discovered",
                    JSONArray().apply {
                        narrative.discoveredRows.forEach { row ->
                            put(
                                JSONObject().apply {
                                    put("label", row.label)
                                    put("value", row.value)
                                },
                            )
                        }
                    },
                )
                put("reasons", jsonArray(narrative.reasonRows))
                narrative.homeRoutedRoamingNote?.let { put("homeRoutedRoamingNote", it) }
                narrative.whitelistNote?.let { put("whitelistNote", it) }
                val locationFacts = snapshot.result.locationSignals.locationFacts
                if (locationFacts != null) {
                    put("homeRoutedRoaming", locationFacts.homeRoutedRoaming)
                    put(
                        "roamingDiagnostics",
                        JSONObject().apply {
                            put("networkMcc", locationFacts.networkMcc)
                            put("networkMnc", locationFacts.networkMnc)
                            put("networkCountryIso", locationFacts.networkCountryIso)
                            put("networkIsRussia", locationFacts.networkIsRussia)
                            put("homeSimMcc", locationFacts.homeSimMcc)
                            put("homeSimMnc", locationFacts.homeSimMnc)
                            put("homeSimCountryIso", locationFacts.homeSimCountryIso)
                            put("homeSimCountryIsRussia", locationFacts.homeSimCountryIsRussia)
                            put("homeSimOperatorName", locationFacts.homeSimOperatorName?.let {
                                maskExportValue(it, snapshot.privacyMode)
                            })
                            put("anySimReportedRoaming", locationFacts.anySimReportedRoaming)
                            put("homeRoutedRoamingReason", locationFacts.homeRoutedRoamingReason)
                            val expectedExit = snapshot.result.geoIp.geoFacts?.expectedRoamingExit == true
                            put("expectedRoamingExit", expectedExit)
                            put(
                                "expectedRoamingExitReason",
                                snapshot.result.geoIp.geoFacts?.expectedRoamingExitReason,
                            )
                        },
                    )
                }
            },
        )
        root.put(
            "results",
            JSONObject().apply {
                put("geoIp", categoryToJson(snapshot.result.geoIp, snapshot.privacyMode))
                put("ipComparison", ipComparisonToJson(snapshot.result.ipComparison, snapshot.privacyMode))
                put("cdnPulling", cdnPullingToJson(snapshot.result.cdnPulling, snapshot.privacyMode))
                put("directSigns", categoryToJson(snapshot.result.directSigns, snapshot.privacyMode))
                put("indirectSigns", categoryToJson(snapshot.result.indirectSigns, snapshot.privacyMode))
                put("nativeSigns", categoryToJson(snapshot.result.nativeSigns, snapshot.privacyMode))
                put("icmpSpoofing", categoryToJson(snapshot.result.icmpSpoofing, snapshot.privacyMode))
                put("rttTriangulation", categoryToJson(snapshot.result.rttTriangulation, snapshot.privacyMode))
                put("locationSignals", categoryToJson(snapshot.result.locationSignals, snapshot.privacyMode))
                put("bypass", bypassToJson(context, snapshot.result.bypassResult, snapshot.privacyMode))
            },
        )
        root.put("ipConsensus", buildIpConsensusJson(snapshot.result.ipConsensus, snapshot.privacyMode))
        snapshot.result.tunProbeDiagnostics?.let {
            root.put("tunProbeDiagnostics", tunProbeDiagnosticsToJson(it, snapshot.privacyMode))
        }
        snapshot.result.operatorWhitelistProbe?.let {
            root.put("operator_whitelist", operatorWhitelistProbeToJson(it))
        }
        return root.toString(2)
    }

    private fun categoryToJson(category: CategoryResult, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("name", maskExportValue(category.name, privacyMode))
            put("detected", category.detected)
            put("needsReview", category.needsReview)
            put("hasError", category.hasError)
            put("status", sectionStatusTag(category.detected, category.needsReview, category.hasError))
            put("findings", JSONArray().apply { category.findings.forEach { put(findingToJson(it, privacyMode)) } })
            put("evidence", JSONArray().apply { category.evidence.forEach { put(evidenceToJson(it, privacyMode)) } })
            put("matchedApps", JSONArray().apply { category.matchedApps.forEach { put(matchedAppToJson(it)) } })
            put("activeApps", JSONArray().apply { category.activeApps.forEach { put(activeAppToJson(it)) } })
            put("callTransportLeaks", JSONArray().apply { category.callTransportLeaks.forEach { put(callTransportLeakToJson(it, privacyMode)) } })
            put("stunProbeGroups", JSONArray().apply { category.stunProbeGroups.forEach { put(stunProbeGroupToJson(it, privacyMode)) } })
            category.geoFacts?.let { put("geoFacts", geoFactsToJson(it, privacyMode)) }
            category.locationFacts?.let { put("locationFacts", locationFactsToJson(it, privacyMode)) }
        }
    }

    private fun geoFactsToJson(facts: GeoIpFacts, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("ip", maskExportIp(facts.ip, privacyMode))
            put("countryCode", facts.countryCode)
            put("asn", facts.asn?.let { maskExportValue(it, privacyMode) })
            put("asnCode", facts.asnCode)
            put("isp", facts.isp?.let { maskExportValue(it, privacyMode) })
            put("org", facts.org?.let { maskExportValue(it, privacyMode) })
            put("outsideRu", facts.outsideRu)
            put("hosting", facts.hosting)
            put("proxyDb", facts.proxyDb)
            put("fetchError", facts.fetchError)
            put("expectedRoamingExit", facts.expectedRoamingExit)
            put("expectedRoamingExitReason", facts.expectedRoamingExitReason)
        }
    }

    private fun locationFactsToJson(facts: LocationSignalsFacts, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("networkMcc", facts.networkMcc)
            put("networkMnc", facts.networkMnc)
            put("networkCountryIso", facts.networkCountryIso)
            put("networkOperatorName", facts.networkOperatorName?.let { maskExportValue(it, privacyMode) })
            put("networkIsRussia", facts.networkIsRussia)
            put("homeSimMcc", facts.homeSimMcc)
            put("homeSimMnc", facts.homeSimMnc)
            put("homeSimCountryIso", facts.homeSimCountryIso)
            put("homeSimCountryIsRussia", facts.homeSimCountryIsRussia)
            put("homeSimOperatorName", facts.homeSimOperatorName?.let { maskExportValue(it, privacyMode) })
            put("anySimReportedRoaming", facts.anySimReportedRoaming)
            put("homeRoutedRoaming", facts.homeRoutedRoaming)
            put("homeRoutedRoamingReason", facts.homeRoutedRoamingReason)
        }
    }

    private fun stunProbeGroupToJson(group: StunProbeGroupResult, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("scope", group.scope.name)
            put("respondedCount", group.respondedCount)
            put("totalCount", group.totalCount)
            put("results", JSONArray().apply { group.results.forEach { put(stunProbeResultToJson(it, privacyMode)) } })
        }
    }

    private fun stunProbeResultToJson(result: StunProbeResult, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("host", maskExportHostOrIp(result.host, privacyMode))
            put("port", result.port)
            put("scope", result.scope.name)
            put("mappedIpv4", maskExportIp(result.mappedIpv4, privacyMode))
            put("mappedIpv6", maskExportIp(result.mappedIpv6, privacyMode))
            put("mappedIpDisplay", result.mappedIpDisplay?.let { maskExportValue(it, privacyMode) })
            put("error", result.error?.let { maskExportValue(it, privacyMode) })
            put("hasResponse", result.hasResponse)
        }
    }

    private fun ipComparisonToJson(result: IpComparisonResult, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("detected", result.detected)
            put("needsReview", result.needsReview)
            put("hasError", result.hasError)
            put("status", sectionStatusTag(result.detected, result.needsReview, result.hasError))
            put("summary", maskExportValue(result.summary, privacyMode))
            put("ruGroup", ipCheckerGroupToJson(result.ruGroup, privacyMode))
            put("nonRuGroup", ipCheckerGroupToJson(result.nonRuGroup, privacyMode))
        }
    }

    private fun ipCheckerGroupToJson(group: IpCheckerGroupResult, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("title", maskExportValue(group.title, privacyMode))
            put("detected", group.detected)
            put("needsReview", group.needsReview)
            put("status", sectionStatusTag(group.detected, group.needsReview))
            put("statusLabel", maskExportValue(group.statusLabel, privacyMode))
            put("summary", maskExportValue(group.summary, privacyMode))
            put("canonicalIp", maskExportIp(group.canonicalIp, privacyMode))
            put("ignoredIpv6ErrorCount", group.ignoredIpv6ErrorCount)
            put("responses", JSONArray().apply { group.responses.forEach { put(ipCheckerResponseToJson(it, privacyMode)) } })
        }
    }

    private fun cdnPullingToJson(result: CdnPullingResult, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("detected", result.detected)
            put("needsReview", result.needsReview)
            put("hasError", result.hasError)
            put("status", sectionStatusTag(result.detected, result.needsReview, result.hasError))
            put("summary", maskExportValue(result.summary, privacyMode))
            put("findings", JSONArray().apply { result.findings.forEach { put(findingToJson(it, privacyMode)) } })
            put("responses", JSONArray().apply { result.responses.forEach { put(cdnResponseToJson(it, privacyMode)) } })
        }
    }

    private fun bypassToJson(
        context: Context,
        bypass: BypassResult,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("detected", bypass.detected)
            put("needsReview", bypass.needsReview)
            put("hasError", bypass.hasError)
            put("status", sectionStatusTag(bypass.detected, bypass.needsReview, bypass.hasError))
            put("proxyEndpoint", bypass.proxyEndpoint?.let { proxyEndpointToJson(it, privacyMode) })
            put("proxyOwner", bypass.proxyOwner?.let { proxyOwnerToJson(it) })
            put("proxyOwnerText", bypass.proxyOwner?.let { LocalProxyOwnerFormatter.format(context, it) })
            put("directIp", maskExportIp(bypass.directIp, privacyMode))
            put("proxyIp", maskExportIp(bypass.proxyIp, privacyMode))
            put("vpnNetworkIp", maskExportIp(bypass.vpnNetworkIp, privacyMode))
            put("underlyingIp", maskExportIp(bypass.underlyingIp, privacyMode))
            put("xrayApiScanResult", bypass.xrayApiScanResult?.let { xrayApiToJson(it, privacyMode) })
            put("proxyChecks", JSONArray().apply { bypass.proxyChecks.forEach { put(proxyCheckToJson(it, privacyMode)) } })
            put("findings", JSONArray().apply { bypass.findings.forEach { put(findingToJson(it, privacyMode)) } })
            put("evidence", JSONArray().apply { bypass.evidence.forEach { put(evidenceToJson(it, privacyMode)) } })
        }
    }

    private fun findingToJson(finding: Finding, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("description", maskExportValue(finding.description, privacyMode))
            put("detected", finding.detected)
            put("needsReview", finding.needsReview)
            put("isInformational", finding.isInformational)
            put("isError", finding.isError)
            put("source", finding.source?.name)
            put("confidence", finding.confidence?.name)
            put("family", finding.family)
            put("packageName", finding.packageName)
        }
    }

    private fun evidenceToJson(item: EvidenceItem, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put("source", item.source.name)
            put("detected", item.detected)
            put("confidence", item.confidence.name)
            put("description", maskExportValue(item.description, privacyMode))
            put("family", item.family)
            put("packageName", item.packageName)
            put("kind", item.kind?.name)
        }
    }

    private fun matchedAppToJson(app: MatchedVpnApp): JSONObject {
        return JSONObject().apply {
            put("packageName", app.packageName)
            put("appName", app.appName)
            put("family", app.family)
            put("kind", app.kind.name)
            put("source", app.source.name)
            put("active", app.active)
            put("confidence", app.confidence.name)
            app.technicalMetadata?.let { put("technicalMetadata", technicalMetadataToJson(it)) }
        }
    }

    private fun activeAppToJson(app: ActiveVpnApp): JSONObject {
        return JSONObject().apply {
            put("packageName", app.packageName)
            put("serviceName", app.serviceName)
            put("family", app.family)
            put("kind", app.kind?.name)
            put("source", app.source.name)
            put("confidence", app.confidence.name)
            app.technicalMetadata?.let { put("technicalMetadata", technicalMetadataToJson(it)) }
        }
    }

    private fun technicalMetadataToJson(metadata: VpnAppTechnicalMetadata): JSONObject {
        return JSONObject().apply {
            put("versionName", metadata.versionName)
            put("serviceNames", JSONArray().apply { metadata.serviceNames.forEach { put(it) } })
            put("appType", metadata.appType)
            put("coreType", metadata.coreType)
            put("corePath", metadata.corePath)
            put("goVersion", metadata.goVersion)
            put("systemApp", metadata.systemApp)
            put("matchedByNameHeuristic", metadata.matchedByNameHeuristic)
        }
    }

    private fun callTransportLeakToJson(
        leak: CallTransportLeakResult,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("service", leak.service.name)
            put("probeKind", leak.probeKind.name)
            put("networkPath", leak.networkPath.name)
            put("status", leak.status.name)
            put("targetHost", leak.targetHost?.let { maskExportHostOrIp(it, privacyMode) })
            put("targetPort", leak.targetPort)
            put("resolvedIps", JSONArray().apply { leak.resolvedIps.forEach { put(maskExportIp(it, privacyMode)) } })
            put("mappedIp", maskExportIp(leak.mappedIp, privacyMode))
            put("observedPublicIp", maskExportIp(leak.observedPublicIp, privacyMode))
            put("summary", maskExportValue(leak.summary, privacyMode))
            put("confidence", leak.confidence?.name)
            put("experimental", leak.experimental)
        }
    }

    private fun ipCheckerResponseToJson(
        response: IpCheckerResponse,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("label", maskExportValue(response.label, privacyMode))
            put("url", maskExportValue(response.url, privacyMode))
            put("scope", response.scope.name)
            put("ip", maskExportIp(response.ip, privacyMode))
            put("error", response.error?.let { maskExportValue(it, privacyMode) })
            put("ipv4Records", JSONArray().apply { response.ipv4Records.forEach { put(maskExportIp(it, privacyMode)) } })
            put("ipv6Records", JSONArray().apply { response.ipv6Records.forEach { put(maskExportIp(it, privacyMode)) } })
            put("ignoredIpv6Error", response.ignoredIpv6Error)
        }
    }

    private fun cdnResponseToJson(
        response: CdnPullingResponse,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("targetLabel", maskExportValue(response.targetLabel, privacyMode))
            put("url", maskExportValue(response.url, privacyMode))
            put("ip", maskExportIp(response.ip, privacyMode))
            put("ipv4", maskExportIp(response.ipv4, privacyMode))
            put("ipv6", maskExportIp(response.ipv6, privacyMode))
            put("ipv4Unavailable", response.ipv4Unavailable)
            put("ipv4Error", response.ipv4Error?.let { maskExportValue(it, privacyMode) })
            put("ipv6Error", response.ipv6Error?.let { maskExportValue(it, privacyMode) })
            put(
                "importantFields",
                JSONObject().apply {
                    response.importantFields.forEach { (key, value) ->
                        put(key, maskExportValue(value, privacyMode))
                    }
                },
            )
            put("rawBody", response.rawBody?.let { maskExportValue(it, privacyMode) })
            put("error", response.error?.let { maskExportValue(it, privacyMode) })
        }
    }

    private fun proxyEndpointToJson(
        endpoint: ProxyEndpoint,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("host", maskExportHostOrIp(endpoint.host, privacyMode))
            put("port", endpoint.port)
            put("type", endpoint.type.name)
            put("authRequired", endpoint.authRequired)
        }
    }

    private fun proxyOwnerToJson(owner: LocalProxyOwner): JSONObject {
        return JSONObject().apply {
            put("uid", owner.uid)
            put("packageNames", jsonArray(owner.packageNames))
            put("appLabels", jsonArray(owner.appLabels))
            put("confidence", owner.confidence.name)
        }
    }

    private fun proxyCheckToJson(
        proxyCheck: LocalProxyCheckResult,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("endpoint", proxyEndpointToJson(proxyCheck.endpoint, privacyMode))
            put("owner", proxyCheck.owner?.let { proxyOwnerToJson(it) })
            put("ownerStatus", proxyCheck.ownerStatus.name)
            put("proxyIp", maskExportIp(proxyCheck.proxyIp, privacyMode))
            put("status", proxyCheck.status.name)
            put("mtProtoReachable", proxyCheck.mtProtoReachable)
            put("mtProtoTarget", proxyCheck.mtProtoTarget?.let { maskExportHostPort(it, privacyMode) })
            put("summaryReason", proxyCheck.summaryReason?.name)
        }
    }

    private fun xrayApiToJson(
        scanResult: XrayApiScanResult,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put(
                "endpoint",
                JSONObject().apply {
                    put("host", maskExportHostOrIp(scanResult.endpoint.host, privacyMode))
                    put("port", scanResult.endpoint.port)
                },
            )
            put(
                "outbounds",
                JSONArray().apply {
                    scanResult.outbounds.forEach { outbound ->
                        put(xrayOutboundToJson(outbound, privacyMode))
                    }
                },
            )
            put("handlerAvailable", scanResult.handlerAvailable)
            scanResult.stats?.let { put("stats", xrayStatsToJson(it)) }
        }
    }

    private fun xrayStatsToJson(stats: XrayStatsSummary): JSONObject {
        return JSONObject().apply {
            put("statCount", stats.statCount)
            put("sampleNames", jsonArray(stats.sampleNames))
        }
    }

    private fun xrayOutboundToJson(
        outbound: XrayOutboundSummary,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("tag", outbound.tag)
            put("protocolName", outbound.protocolName)
            put("address", outbound.address?.let { maskExportHostOrIp(it, privacyMode) })
            put("port", outbound.port)
            put("sni", outbound.sni)
            put("senderSettingsType", outbound.senderSettingsType)
            put("proxySettingsType", outbound.proxySettingsType)
            put("uuidPresent", !outbound.uuid.isNullOrBlank())
            put("publicKeyPresent", !outbound.publicKey.isNullOrBlank())
        }
    }

    private fun buildIpConsensusJson(consensus: IpConsensusResult, privacyMode: Boolean): JSONObject {
        return JSONObject().apply {
            put(
                "observedIps",
                JSONArray().apply {
                    consensus.observedIps.forEach { ip ->
                        put(
                            JSONObject().apply {
                                put("value", maskExportIp(ip.value, privacyMode))
                                put("family", ip.family.name)
                                put("channel", ip.channel.name)
                                put("sources", jsonArray(ip.sources.toList()))
                                put("countryCode", ip.countryCode)
                                put("asn", ip.asn)
                                put("targetGroup", ip.targetGroup?.name)
                            },
                        )
                    }
                },
            )
            put(
                "unparsedIps",
                JSONArray().apply {
                    consensus.unparsedIps.forEach { item ->
                        put(
                            JSONObject().apply {
                                put("raw", maskExportValue(item.raw, privacyMode))
                                put("source", item.source)
                            },
                        )
                    }
                },
            )
            put(
                "channelIps",
                JSONObject().apply {
                    consensus.channelIps.toSortedMap(compareBy { it.name }).forEach { (channel, ips) ->
                        put(channel.name, jsonArray(ips.toList().sorted().map { maskExportIp(it, privacyMode) ?: it }))
                    }
                },
            )
            put("crossChannelMismatch", consensus.crossChannelMismatch)
            put("dualStackObserved", consensus.dualStackObserved)
            put("warpLikeIndicator", consensus.warpLikeIndicator)
            put("probeTargetDivergence", consensus.probeTargetDivergence)
            put("probeTargetDirectDivergence", consensus.probeTargetDirectDivergence)
            put("geoCountryMismatch", consensus.geoCountryMismatch)
            put("sameAsnAcrossChannels", consensus.sameAsnAcrossChannels)
            put("channelConflict", jsonArray(consensus.channelConflict.map { it.name }))
            put("foreignIps", jsonArray(consensus.foreignIps.toList().map { maskExportIp(it, privacyMode) ?: it }))
            put("needsReview", consensus.needsReview)
        }
    }

    private fun tunProbeDiagnosticsToJson(
        diagnostics: TunProbeDiagnostics,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("enabled", diagnostics.enabled)
            put("modeOverride", diagnostics.modeOverride.name)
            put("activeNetworkIsVpn", diagnostics.activeNetworkIsVpn)
            put("vpnNetworkPresent", diagnostics.vpnNetworkPresent)
            put("underlyingNetworkPresent", diagnostics.underlyingNetworkPresent)
            diagnostics.vpnPath?.let { put("vpnPath", tunProbePathToJson(it, privacyMode)) }
            diagnostics.underlyingPath?.let { put("underlyingPath", tunProbePathToJson(it, privacyMode)) }
        }
    }

    private fun tunProbePathToJson(
        path: TunProbePathDiagnostics,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("interfaceName", path.interfaceName)
            put("selectedMode", path.selectedMode?.name)
            put("selectedIp", maskExportIp(path.selectedIp, privacyMode))
            put("selectedError", path.selectedError?.let { maskExportValue(it, privacyMode) })
            put("dnsPathMismatch", path.dnsPathMismatch)
            put("strict", tunProbeAttemptToJson(path.strict, privacyMode))
            put("curlCompatible", tunProbeAttemptToJson(path.curlCompatible, privacyMode))
        }
    }

    private fun tunProbeAttemptToJson(
        attempt: TunProbeAttemptDiagnostics,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("mode", attempt.mode.name)
            put("status", attempt.status.name)
            put("ip", maskExportIp(attempt.ip, privacyMode))
            put("error", attempt.error?.let { maskExportValue(it, privacyMode) })
            put("endpointAttempts", JSONArray().apply { attempt.endpointAttempts.forEach { put(tunEndpointAttemptToJson(it, privacyMode)) } })
            put("transportDiagnostics", transportDiagnosticsToJson(attempt.transportDiagnostics, privacyMode))
        }
    }

    private fun tunEndpointAttemptToJson(
        attempt: TunEndpointAttempt,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("endpoint", maskExportValue(attempt.endpoint, privacyMode))
            put("familyHint", attempt.familyHint)
            put("status", attempt.status.name)
            put("ip", maskExportIp(attempt.ip, privacyMode))
            put("error", attempt.error?.let { maskExportValue(it, privacyMode) })
        }
    }

    private fun transportDiagnosticsToJson(
        diagnostics: PublicIpTransportDiagnostics,
        privacyMode: Boolean,
    ): JSONObject {
        return JSONObject().apply {
            put("engine", diagnostics.engine?.name)
            put("engineDebugName", diagnostics.engine?.debugName)
            put("resolveStrategy", diagnostics.resolveStrategy?.name)
            put("resolveStrategyDebugName", diagnostics.resolveStrategy?.debugName)
            put("curlCode", diagnostics.curlCode)
            put("httpCode", diagnostics.httpCode)
            put("nativeLibraryLoaded", diagnostics.nativeLibraryLoaded)
            put("caBundleVersion", diagnostics.caBundleVersion)
            put("resolvedAddressesUsed", jsonArray(diagnostics.resolvedAddressesUsed.map { maskExportIp(it, privacyMode) ?: it }))
        }
    }

    private fun operatorWhitelistProbeToJson(probe: OperatorWhitelistProbeResult): JSONObject {
        return JSONObject().apply {
            put("detected", probe.whitelistDetected)
            put("google_reachable", probe.googleReachable)
            put("apple_reachable", probe.appleReachable)
            put("firefox_reachable", probe.firefoxReachable)
            put("russian_control_reachable", probe.russianControlReachable)
            put("duration_ms", probe.durationMs)
            put(
                "errors",
                JSONObject().apply {
                    probe.errors.forEach { (key, value) -> put(key, value) }
                },
            )
        }
    }

    private fun jsonArray(items: List<String>): JSONArray {
        return JSONArray().apply {
            items.forEach(::put)
        }
    }
}
