package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.model.*
import com.notcvnt.rknhardering.probe.PublicIpProbeMode
import com.notcvnt.rknhardering.probe.PublicIpProbeStatus
import com.notcvnt.rknhardering.probe.PublicIpTransportDiagnostics
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.TunEndpointAttempt
import com.notcvnt.rknhardering.probe.TunProbeAttemptDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeEngine
import com.notcvnt.rknhardering.probe.TunProbeModeOverride
import com.notcvnt.rknhardering.probe.TunProbePathDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeResolveStrategy
import com.notcvnt.rknhardering.probe.XrayApiEndpoint
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayOutboundSummary
import com.notcvnt.rknhardering.probe.XrayStatsSummary

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

private fun exportTunProbeDiagnostics(): TunProbeDiagnostics {
    val transport = PublicIpTransportDiagnostics(
        engine = TunProbeEngine.NATIVE_LIBCURL,
        resolveStrategy = TunProbeResolveStrategy.NATIVE_DEFAULT,
        curlCode = 0,
        httpCode = 200,
        nativeLibraryLoaded = true,
        caBundleVersion = "test-ca",
        resolvedAddressesUsed = listOf("203.0.113.64"),
    )
    return TunProbeDiagnostics(
        enabled = true,
        modeOverride = TunProbeModeOverride.CURL_COMPATIBLE,
        activeNetworkIsVpn = true,
        vpnNetworkPresent = true,
        underlyingNetworkPresent = true,
        vpnPath = TunProbePathDiagnostics(
            interfaceName = "tun0",
            selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
            selectedIp = "203.0.113.64",
            selectedError = null,
            dnsPathMismatch = true,
            strict = TunProbeAttemptDiagnostics(
                mode = PublicIpProbeMode.STRICT_SAME_PATH,
                status = PublicIpProbeStatus.FAILED,
                error = "timeout from 198.51.100.7",
                endpointAttempts = listOf(
                    TunEndpointAttempt(
                        endpoint = "https://198.51.100.7/ip",
                        familyHint = "ipv4",
                        status = PublicIpProbeStatus.FAILED,
                        error = "timeout from 198.51.100.7",
                    ),
                ),
                transportDiagnostics = transport,
            ),
            curlCompatible = TunProbeAttemptDiagnostics(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                status = PublicIpProbeStatus.SUCCEEDED,
                ip = "203.0.113.64",
                endpointAttempts = listOf(
                    TunEndpointAttempt(
                        endpoint = "https://203.0.113.64/ip",
                        familyHint = "ipv4",
                        status = PublicIpProbeStatus.SUCCEEDED,
                        ip = "203.0.113.64",
                    ),
                ),
                transportDiagnostics = transport,
            ),
        ),
        underlyingPath = null,
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
            geoFacts = GeoIpFacts(
                ip = "203.0.113.64",
                countryCode = "FI",
                asn = "AS64502 Example VPN",
                outsideRu = true,
                hosting = true,
                proxyDb = true,
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
                    ipv4 = "203.0.113.64",
                    ipv6 = "2001:db8::64",
                    ipv4Unavailable = false,
                    ipv4Error = "IPv4 retry saw 198.51.100.7",
                    ipv6Error = "IPv6 timeout 2001:db8::64",
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
            stunProbeGroups = listOf(
                StunProbeGroupResult(
                    scope = StunScope.GLOBAL,
                    results = listOf(
                        StunProbeResult(
                            host = "stun.example.org",
                            port = 3478,
                            scope = StunScope.GLOBAL,
                            mappedIpv4 = "203.0.113.64",
                            mappedIpv6 = "2001:db8::64",
                        ),
                        StunProbeResult(
                            host = "198.51.100.7",
                            port = 3478,
                            scope = StunScope.GLOBAL,
                            error = "timeout from 198.51.100.7",
                        ),
                    ),
                ),
            ),
        ),
        nativeSigns = CategoryResult(
            name = "Native signs",
            detected = true,
            findings = listOf(
                Finding(
                    description = "Native getifaddrs() reports tun0",
                    detected = true,
                    source = EvidenceSource.NATIVE_INTERFACE,
                    confidence = EvidenceConfidence.HIGH,
                ),
            ),
            evidence = listOf(
                EvidenceItem(
                    source = EvidenceSource.NATIVE_INTERFACE,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "native interface tun0 is visible",
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
        rttTriangulation = CategoryResult(
            name = "RTT triangulation",
            detected = false,
            needsReview = true,
            findings = listOf(
                Finding(
                    description = "RTT target mix needs review",
                    needsReview = true,
                    source = EvidenceSource.RTT_TRIANGULATION,
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
                authRequired = true,
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
                stats = XrayStatsSummary(
                    statCount = 2,
                    sampleNames = listOf("outbound>>>proxy>>>traffic>>>uplink"),
                ),
                handlerAvailable = true,
            ),
            proxyChecks = listOf(
                LocalProxyCheckResult(
                    endpoint = ProxyEndpoint(
                        host = "127.0.0.1",
                        port = 1080,
                        type = ProxyType.SOCKS5,
                        authRequired = true,
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
        tunProbeDiagnostics = exportTunProbeDiagnostics(),
        betaChecks = BetaCheckResult(
            category = CategoryResult(
                name = "β Бета-проверки",
                detected = true,
                needsReview = false,
                findings = listOf(
                    Finding(
                        description = "β Exact socket cookie confirmed",
                        detected = false,
                        needsReview = false,
                        isInformational = true,
                        isError = false,
                        source = EvidenceSource.BETA_SOCKET_DIAG,
                        confidence = EvidenceConfidence.LOW,
                        maturity = EvidenceMaturity.BETA,
                        checkId = "beta.inet_diag_cookie",
                        availability = ProbeAvailability.AVAILABLE,
                        rawConfidence = EvidenceConfidence.LOW,
                        facts = mapOf(
                            "cookie" to "12345678",
                            "cookie_match" to "true",
                            "matched" to "true"
                        ),
                        independenceGroup = "socket_diag",
                        detectionDomain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
                    ),
                    Finding(
                        description = "β WireGuard Genl failure",
                        detected = false,
                        needsReview = false,
                        isInformational = false,
                        isError = true,
                        source = EvidenceSource.BETA_WIREGUARD_GENL,
                        confidence = EvidenceConfidence.LOW,
                        maturity = EvidenceMaturity.BETA,
                        checkId = "beta.wireguard_genl",
                        availability = ProbeAvailability.ERROR,
                        rawConfidence = EvidenceConfidence.LOW,
                        facts = mapOf(
                            "errno" to "13",
                            "stage" to "family",
                            "error" to "Permission denied"
                        ),
                        independenceGroup = "kernel_vpn",
                        detectionDomain = DetectionDomain.VPN_OR_PROXY,
                    ),
                    Finding(
                        description = "β Check skipped or not executed",
                        detected = false,
                        needsReview = false,
                        isInformational = true,
                        isError = false,
                        source = EvidenceSource.BETA_USER_PROFILE,
                        confidence = EvidenceConfidence.LOW,
                        maturity = EvidenceMaturity.BETA,
                        checkId = "beta.user_profile",
                        availability = ProbeAvailability.SKIPPED,
                        rawConfidence = EvidenceConfidence.LOW,
                        facts = emptyMap(),
                        independenceGroup = "android_user_manager",
                        detectionDomain = DetectionDomain.ISOLATED_PROFILE,
                    )
                ),
                evidence = listOf(
                    EvidenceItem(
                        source = EvidenceSource.BETA_SOCKET_DIAG,
                        detected = true,
                        confidence = EvidenceConfidence.LOW,
                        description = "β Exact socket cookie confirmed",
                        maturity = EvidenceMaturity.BETA,
                        checkId = "beta.inet_diag_cookie",
                        independenceGroup = "socket_diag",
                        detectionDomain = DetectionDomain.NETWORK_PATH_DIVERGENCE,
                    )
                ),
                maturity = EvidenceMaturity.BETA,
            ),
            executionContext = ExecutionContextFacts(
                uid = 10123,
                appId = 10123,
                uidDerivedUserId = 0,
                packageUidConsistent = true,
                mountNamespaceId = "mnt:[123]",
                selinuxContext = "u:r:untrusted_app:s0:c1,c2",
                kind = ExecutionContextKind.MAIN_USER,
                confidence = EvidenceConfidence.LOW,
            ),
            availabilitySummary = mapOf(
                ProbeAvailability.AVAILABLE to 1,
                ProbeAvailability.ERROR to 1,
                ProbeAvailability.SKIPPED to 1
            ),
            networkEpochChanges = emptySet(),
            networkEpochRetryCount = 0,
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
            unparsedIps = listOf(
                UnparsedIp(
                    raw = "bad field 203.0.113.64",
                    source = "fixture.raw",
                ),
            ),
            channelIps = mapOf(
                Channel.DIRECT to setOf("198.51.100.7"),
                Channel.VPN to setOf("203.0.113.64"),
            ),
            channelConflict = setOf(Channel.DIRECT, Channel.VPN),
            crossChannelMismatch = true,
            dualStackObserved = true,
            foreignIps = setOf("203.0.113.64"),
            geoCountryMismatch = true,
            sameAsnAcrossChannels = true,
            probeTargetDivergence = true,
            probeTargetDirectDivergence = true,
            needsReview = true,
        ),
        verdict = Verdict.DETECTED,
    )
}
