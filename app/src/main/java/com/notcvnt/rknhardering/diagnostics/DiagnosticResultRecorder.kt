package com.notcvnt.rknhardering.diagnostics

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.DomainReachabilityResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.VerdictDecision

object DiagnosticResultRecorder {
    fun recordCategory(
        collector: DiagnosticTraceCollector?,
        category: String,
        source: String,
        result: CategoryResult,
    ) {
        collector ?: return
        collector.record(
            category = category,
            source = source,
            status = status(result.detected, result.needsReview, result.hasError),
            body = buildString {
                appendLine("name=${result.name}")
                appendLine("detected=${result.detected}")
                appendLine("needsReview=${result.needsReview}")
                appendLine("hasError=${result.hasError}")
                result.geoFacts?.let { appendLine("geoFacts=$it") }
                result.locationFacts?.let { appendLine("locationFacts=$it") }
                result.evidence.forEachIndexed { index, item ->
                    appendLine(
                        "evidence[$index]=source:${item.source},detected:${item.detected}," +
                            "confidence:${item.confidence},description:${item.description}",
                    )
                }
                result.findings.forEachIndexed { index, finding ->
                    appendLine(
                        "finding[$index]=detected:${finding.detected},needsReview:${finding.needsReview}," +
                            "informational:${finding.isInformational},error:${finding.isError}," +
                            "source:${finding.source},description:${finding.description}",
                    )
                }
                result.stunProbeGroups.flatMap { it.results }.forEachIndexed { index, item ->
                    appendLine(
                        "stun[$index]=host:${item.host},port:${item.port},scope:${item.scope}," +
                            "mappedIpv4:${item.mappedIpv4},mappedIpv6:${item.mappedIpv6},error:${item.error}",
                    )
                }
                result.callTransportLeaks.forEachIndexed { index, item ->
                    appendLine(
                        "callTransport[$index]=service:${item.service},kind:${item.probeKind}," +
                            "path:${item.networkPath},status:${item.status},target:${item.targetHost}:${item.targetPort}," +
                            "resolved:${item.resolvedIps},mapped:${item.mappedIp},public:${item.observedPublicIp}," +
                            "summary:${item.summary}",
                    )
                }
            },
        )
        result.geoIpResponses.forEach { response ->
            collector.record(
                category = category,
                source = "${response.provider} HTTP",
                status = if (response.error == null) "completed" else "error",
                body = buildString {
                    appendLine("ip=${response.ip}")
                    appendLine("error=${response.error}")
                    append(response.rawBody.orEmpty())
                },
            )
        }
    }

    fun recordIpComparison(
        collector: DiagnosticTraceCollector?,
        result: IpComparisonResult,
    ) {
        collector ?: return
        collector.record(
            category = "ipc",
            source = "IpComparisonChecker",
            status = status(result.detected, result.needsReview, result.hasError),
            body = buildString {
                appendLine("summary=${result.summary}")
                (result.ruGroup.responses + result.nonRuGroup.responses).forEachIndexed { index, response ->
                    appendLine(
                        "response[$index]=label:${response.label},url:${response.url},scope:${response.scope}," +
                            "ip:${response.ip},ipv4Records:${response.ipv4Records}," +
                            "ipv6Records:${response.ipv6Records},error:${response.error}",
                    )
                }
            },
        )
    }

    fun recordCdn(collector: DiagnosticTraceCollector?, result: CdnPullingResult) {
        collector ?: return
        collector.record(
            category = "cdn",
            source = "CdnPullingChecker",
            status = status(result.detected, result.needsReview, result.hasError),
            body = "summary=${result.summary}",
        )
        result.responses.forEach { response ->
            collector.record(
                category = "cdn",
                source = response.targetLabel,
                target = response.url,
                status = if (response.error == null) "completed" else "error",
                body = buildString {
                    appendLine("ip=${response.ip}")
                    appendLine("ipv4=${response.ipv4}")
                    appendLine("ipv6=${response.ipv6}")
                    appendLine("importantFields=${response.importantFields}")
                    appendLine("error=${response.error}")
                    append(response.rawBody.orEmpty())
                },
            )
        }
    }

    fun recordBypass(collector: DiagnosticTraceCollector?, result: BypassResult) {
        collector ?: return
        collector.record(
            category = "byp",
            source = "BypassChecker",
            status = status(result.detected, result.needsReview, result.hasError),
            body = buildString {
                appendLine("proxyEndpoint=${result.proxyEndpoint}")
                appendLine("directIp=${result.directIp}")
                appendLine("proxyIp=${result.proxyIp}")
                appendLine("vpnNetworkIp=${result.vpnNetworkIp}")
                appendLine("underlyingIp=${result.underlyingIp}")
                appendLine("proxyChecks=${result.proxyChecks}")
                result.evidence.forEachIndexed { index, item ->
                    appendLine("evidence[$index]=source:${item.source},detected:${item.detected},confidence:${item.confidence},description:${item.description}")
                }
                result.findings.forEachIndexed { index, item ->
                    appendLine("finding[$index]=detected:${item.detected},review:${item.needsReview},error:${item.isError},description:${item.description}")
                }
            },
        )
        result.xrayApiScanResult?.let { xray ->
            collector.record(
                category = "byp",
                source = "Xray API",
                target = "${xray.endpoint.host}:${xray.endpoint.port}",
                status = if (xray.handlerAvailable) "available" else "unavailable",
                body = buildString {
                    appendLine("outboundCount=${xray.outbounds.size}")
                    xray.outbounds.forEachIndexed { index, outbound ->
                        appendLine(
                            "outbound[$index]=tag:${outbound.tag},protocol:${outbound.protocolName}," +
                                "address:${outbound.address},port:${outbound.port},sni:${outbound.sni}," +
                                "uuidPresent:${!outbound.uuid.isNullOrBlank()}," +
                                "publicKeyPresent:${!outbound.publicKey.isNullOrBlank()}," +
                                "senderType:${outbound.senderSettingsType},proxyType:${outbound.proxySettingsType}",
                        )
                    }
                },
            )
        }
        result.clashApiScanResult?.let { clash ->
            collector.record(
                category = "byp",
                source = "Clash API",
                target = "${clash.endpoint.host}:${clash.endpoint.port}",
                status = if (clash.configAvailable) "available" else "unavailable",
                body = buildString {
                    appendLine("configAvailable=${clash.configAvailable}")
                    appendLine("destinationIpCount=${clash.leakedDestIps.size}")
                    appendLine("proxyNodeCount=${clash.proxyNodes.size}")
                },
            )
        }
    }

    fun recordDomainReachability(
        collector: DiagnosticTraceCollector?,
        result: DomainReachabilityResult,
    ) {
        collector ?: return
        result.responses.forEach { response ->
            collector.record(
                category = "rea",
                source = "DomainReachabilityChecker",
                target = response.domain,
                status = if (response.matchesExpectation) "expected" else "mismatch",
                body = buildString {
                    appendLine("label=${response.label}")
                    appendLine("dns=${response.dnsStatus},error=${response.dnsError},resolved=${response.resolvedIps}")
                    appendLine("tcp=${response.tcpStatus},error=${response.tcpError}")
                    appendLine("tls=${response.tlsStatus},error=${response.tlsError}")
                    appendLine(
                        "expectedDns=${response.expectedDnsAvailable}," +
                            "expectedTcp=${response.expectedTcpAvailable},expectedTls=${response.expectedTlsAvailable}",
                    )
                },
            )
        }
    }

    fun recordConsensus(collector: DiagnosticTraceCollector?, result: IpConsensusResult) {
        collector?.record(
            category = "ipc",
            source = "IpConsensusBuilder",
            status = if (result.needsReview) "review" else "completed",
            body = buildString {
                appendLine("observedIps=${result.observedIps}")
                appendLine("unparsedIps=${result.unparsedIps}")
                appendLine("channelIps=${result.channelIps}")
                appendLine("channelConflict=${result.channelConflict}")
                appendLine("crossChannelMismatch=${result.crossChannelMismatch}")
                appendLine("foreignIps=${result.foreignIps}")
                appendLine("geoCountryMismatch=${result.geoCountryMismatch}")
                appendLine("warpLikeIndicator=${result.warpLikeIndicator}")
                appendLine("probeTargetDivergence=${result.probeTargetDivergence}")
                appendLine("probeTargetDirectDivergence=${result.probeTargetDirectDivergence}")
            },
        )
    }

    fun recordVerdict(collector: DiagnosticTraceCollector?, decision: VerdictDecision) {
        collector?.record(
            category = "geo",
            source = "VerdictEngine",
            status = decision.verdict.name,
            body = buildString {
                appendLine("rule=${decision.ruleCode}")
                decision.participants.forEachIndexed { index, participant ->
                    appendLine("participant[$index]=factor:${participant.factor},sources:${participant.evidenceSources}")
                }
            },
        )
    }

    private fun status(detected: Boolean, review: Boolean, error: Boolean): String = when {
        error -> "error"
        detected -> "detected"
        review -> "review"
        else -> "clean"
    }
}
