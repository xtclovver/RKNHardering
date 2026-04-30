package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.IpFamily
import com.notcvnt.rknhardering.model.LocalProxyCheckResult
import com.notcvnt.rknhardering.model.LocalProxyCheckStatus
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.LocalProxyOwnerStatus
import com.notcvnt.rknhardering.model.LocalProxySummaryReason
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.model.ObservedIp
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VpnAppKind
import com.notcvnt.rknhardering.model.VpnAppTechnicalMetadata
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.XrayApiEndpoint
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayOutboundSummary

internal fun exportEmptyCheckResult(): CheckResult {
    val emptyCategory = CategoryResult(
        name = "empty",
        detected = false,
        findings = emptyList(),
    )
    return CheckResult(
        geoIp = emptyCategory,
        ipComparison = IpComparisonResult(
            detected = false,
            summary = "",
            ruGroup = IpCheckerGroupResult(
                title = "RU",
                detected = false,
                statusLabel = "",
                summary = "",
                responses = emptyList(),
            ),
            nonRuGroup = IpCheckerGroupResult(
                title = "NON_RU",
                detected = false,
                statusLabel = "",
                summary = "",
                responses = emptyList(),
            ),
        ),
        directSigns = emptyCategory,
        indirectSigns = emptyCategory,
        icmpSpoofing = emptyCategory,
        locationSignals = emptyCategory,
        bypassResult = BypassResult(
            proxyEndpoint = null,
            directIp = null,
            proxyIp = null,
            xrayApiScanResult = null,
            findings = emptyList(),
            detected = false,
        ),
        verdict = Verdict.NOT_DETECTED,
    )
}

internal fun exportRichCheckResult(): CheckResult {
    return CheckResult(
        geoIp = CategoryResult(
            name = "GeoIP",
            detected = true,
            findings = listOf(
                Finding(
                    description = "GeoIP says 203.0.113.64",
                    isInformational = true,
                    source = EvidenceSource.GEO_IP,
                ),
            ),
            evidence = listOf(
                EvidenceItem(
                    source = EvidenceSource.GEO_IP,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "Hosting signal for 203.0.113.64",
                ),
            ),
        ),
        ipComparison = IpComparisonResult(
            detected = true,
            needsReview = true,
            summary = "Mismatch between 198.51.100.7 and 203.0.113.64",
            ruGroup = IpCheckerGroupResult(
                title = "RU",
                detected = true,
                needsReview = true,
                statusLabel = "mismatch",
                summary = "RU checker returned 198.51.100.7",
                canonicalIp = "198.51.100.7",
                responses = listOf(
                    IpCheckerResponse(
                        label = "ru-main",
                        url = "https://ru.example/check",
                        scope = IpCheckerScope.RU,
                        ip = "198.51.100.7",
                    ),
                ),
                ignoredIpv6ErrorCount = 1,
            ),
            nonRuGroup = IpCheckerGroupResult(
                title = "NON_RU",
                detected = true,
                statusLabel = "ok",
                summary = "NON_RU checker returned 203.0.113.64",
                canonicalIp = "203.0.113.64",
                responses = listOf(
                    IpCheckerResponse(
                        label = "non-ru-main",
                        url = "https://non-ru.example/check",
                        scope = IpCheckerScope.NON_RU,
                        ip = "203.0.113.64",
                    ),
                ),
            ),
        ),
        cdnPulling = CdnPullingResult(
            detected = true,
            needsReview = true,
            summary = "rutracker.org exposed 203.0.113.64",
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "rutracker.org",
                    url = "https://rutracker.org/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    importantFields = linkedMapOf("ip" to "203.0.113.64", "loc" to "FI"),
                    rawBody = "ip=203.0.113.64\nloc=FI",
                ),
            ),
            findings = listOf(
                Finding(
                    description = "CDN trace matched 203.0.113.64",
                    detected = true,
                    source = EvidenceSource.SPLIT_TUNNEL_BYPASS,
                ),
            ),
        ),
        directSigns = CategoryResult(
            name = "Direct",
            detected = true,
            findings = listOf(
                Finding(
                    description = "Installed app com.example.vpn at 198.51.100.7",
                    detected = true,
                    source = EvidenceSource.INSTALLED_APP,
                    confidence = EvidenceConfidence.HIGH,
                    family = "v2ray",
                    packageName = "com.example.vpn",
                ),
            ),
            evidence = listOf(
                EvidenceItem(
                    source = EvidenceSource.ACTIVE_VPN,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "VPN service active",
                    packageName = "com.example.vpn",
                    family = "v2ray",
                    kind = VpnAppKind.TARGETED_BYPASS,
                ),
            ),
            matchedApps = listOf(
                MatchedVpnApp(
                    packageName = "com.example.vpn",
                    appName = "Example VPN",
                    family = "v2ray",
                    kind = VpnAppKind.TARGETED_BYPASS,
                    source = EvidenceSource.INSTALLED_APP,
                    active = true,
                    confidence = EvidenceConfidence.HIGH,
                    technicalMetadata = VpnAppTechnicalMetadata(
                        versionName = "1.2.3",
                        serviceNames = listOf("ExampleService"),
                        appType = "V2RayNG",
                        coreType = "Xray/V2Ray",
                        corePath = "lib/arm64-v8a/libxray.so",
                        goVersion = "go1.24.1",
                    ),
                ),
            ),
            activeApps = listOf(
                ActiveVpnApp(
                    packageName = "com.example.vpn",
                    serviceName = "ExampleService",
                    family = "v2ray",
                    kind = VpnAppKind.TARGETED_BYPASS,
                    source = EvidenceSource.ACTIVE_VPN,
                    confidence = EvidenceConfidence.HIGH,
                    technicalMetadata = VpnAppTechnicalMetadata(
                        versionName = "1.2.3",
                        serviceNames = listOf("ExampleService"),
                        appType = "V2RayNG",
                        coreType = "Xray/V2Ray",
                        corePath = "lib/arm64-v8a/libxray.so",
                        goVersion = "go1.24.1",
                    ),
                ),
            ),
        ),
        indirectSigns = CategoryResult(
            name = "Indirect",
            detected = true,
            findings = listOf(
                Finding(
                    description = "Indirect route mismatch 198.51.100.7",
                    detected = true,
                    source = EvidenceSource.ROUTING,
                ),
            ),
            callTransportLeaks = listOf(
                CallTransportLeakResult(
                    service = CallTransportService.TELEGRAM,
                    probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                    networkPath = CallTransportNetworkPath.UNDERLYING,
                    status = CallTransportStatus.ERROR,
                    targetHost = "198.51.100.7",
                    targetPort = 3478,
                    resolvedIps = listOf("198.51.100.7"),
                    mappedIp = "198.51.100.9",
                    observedPublicIp = "203.0.113.64",
                    summary = "STUN error from 198.51.100.7",
                    confidence = EvidenceConfidence.MEDIUM,
                    experimental = true,
                ),
            ),
        ),
        icmpSpoofing = CategoryResult(
            name = "ICMP spoofing",
            detected = false,
            needsReview = true,
            findings = listOf(
                Finding(
                    description = "instagram.com replied and google.com was too fast",
                    needsReview = true,
                    source = EvidenceSource.ICMP_SPOOFING,
                ),
                Finding(
                    description = "Blocked target instagram.com (157.240.22.174): 3/3 replies",
                    isInformational = true,
                ),
            ),
            evidence = listOf(
                EvidenceItem(
                    source = EvidenceSource.ICMP_SPOOFING,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "ICMP route behavior looked inconsistent",
                ),
            ),
        ),
        locationSignals = CategoryResult(
            name = "Location",
            detected = false,
            findings = emptyList(),
        ),
        bypassResult = BypassResult(
            proxyEndpoint = ProxyEndpoint(
                host = "127.0.0.1",
                port = 1080,
                type = ProxyType.SOCKS5,
            ),
            proxyOwner = LocalProxyOwner(
                uid = 10123,
                packageNames = listOf("com.example.vpn"),
                appLabels = listOf("Example VPN"),
                confidence = EvidenceConfidence.HIGH,
            ),
            directIp = "198.51.100.7",
            proxyIp = "203.0.113.64",
            vpnNetworkIp = "198.51.100.9",
            underlyingIp = "192.168.1.55",
            xrayApiScanResult = XrayApiScanResult(
                endpoint = XrayApiEndpoint(host = "127.0.0.1", port = 8080),
                outbounds = listOf(
                    XrayOutboundSummary(
                        tag = "proxy",
                        protocolName = "vless",
                        address = "198.51.100.7",
                        port = 443,
                        uuid = "secret-uuid",
                        sni = "example.org",
                        publicKey = "secret-public-key",
                        senderSettingsType = "tcp",
                        proxySettingsType = "none",
                    ),
                ),
            ),
            proxyChecks = listOf(
                LocalProxyCheckResult(
                    endpoint = ProxyEndpoint(
                        host = "127.0.0.1",
                        port = 1080,
                        type = ProxyType.SOCKS5,
                    ),
                    owner = LocalProxyOwner(
                        uid = 10123,
                        packageNames = listOf("com.example.vpn"),
                        appLabels = listOf("Example VPN"),
                        confidence = EvidenceConfidence.HIGH,
                    ),
                    ownerStatus = LocalProxyOwnerStatus.RESOLVED,
                    proxyIp = "203.0.113.64",
                    status = LocalProxyCheckStatus.CONFIRMED_BYPASS,
                    mtProtoReachable = true,
                    mtProtoTarget = "149.154.167.51:443",
                    summaryReason = LocalProxySummaryReason.CONFIRMED_BYPASS,
                ),
            ),
            findings = listOf(
                Finding(
                    description = "Bypass via 198.51.100.7",
                    detected = true,
                    source = EvidenceSource.SPLIT_TUNNEL_BYPASS,
                    confidence = EvidenceConfidence.HIGH,
                ),
            ),
            detected = true,
            needsReview = true,
            evidence = listOf(
                EvidenceItem(
                    source = EvidenceSource.XRAY_API,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "Xray exposed 198.51.100.7",
                ),
            ),
        ),
        ipConsensus = IpConsensusResult(
            observedIps = listOf(
                ObservedIp(
                    value = "198.51.100.7",
                    family = IpFamily.V4,
                    channel = Channel.DIRECT,
                    sources = setOf("geoip", "ipcomp:ru:ru-main"),
                    countryCode = "RU",
                    asn = "AS64501 Example Direct",
                    targetGroup = TargetGroup.RU,
                ),
                ObservedIp(
                    value = "203.0.113.64",
                    family = IpFamily.V4,
                    channel = Channel.VPN,
                    sources = setOf("underlying-prober.non-ru.vpn", "bypass.vpn"),
                    countryCode = "FI",
                    asn = "AS64502 Example VPN",
                    targetGroup = TargetGroup.NON_RU,
                ),
            ),
            crossChannelMismatch = true,
            foreignIps = setOf("203.0.113.64"),
            geoCountryMismatch = true,
            probeTargetDivergence = true,
            needsReview = true,
        ),
        verdict = Verdict.DETECTED,
    )
}
