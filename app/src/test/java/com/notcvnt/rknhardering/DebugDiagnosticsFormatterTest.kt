package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.checker.CallTransportPerformanceDiagnostics
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.checker.DebugStepTiming
import com.notcvnt.rknhardering.checker.IndirectCheckPerformanceDiagnostics
import com.notcvnt.rknhardering.checker.IndirectCheckPerformanceRegistry
import com.notcvnt.rknhardering.checker.LocationSignalsDiagnostics
import com.notcvnt.rknhardering.checker.LocationSignalsDiagnosticsRegistry
import com.notcvnt.rknhardering.checker.StunScopeTiming
import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.LocalProxyCheckResult
import com.notcvnt.rknhardering.model.LocalProxyCheckStatus
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.LocalProxyOwnerStatus
import com.notcvnt.rknhardering.model.LocalProxySummaryReason
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.model.VpnAppKind
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.DnsResolverMode
import com.notcvnt.rknhardering.model.StunScope
import com.notcvnt.rknhardering.probe.OperatorWhitelistProbeResult
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.XrayApiEndpoint
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayOutboundSummary
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DebugDiagnosticsFormatterTest {

    @Test
    fun `formatter builds general report even without tun diagnostics`() {
        val result = CheckResult(
            geoIp = CategoryResult(
                name = "GeoIP",
                detected = false,
                findings = listOf(Finding("GeoIP says 203.0.113.64")),
            ),
            ipComparison = IpComparisonResult(
                detected = false,
                summary = "All checkers returned 203.0.113.64",
                ruGroup = IpCheckerGroupResult(
                    title = "RU",
                    detected = false,
                    statusLabel = "clean",
                    summary = "RU sees 203.0.113.64",
                    canonicalIp = "203.0.113.64",
                    responses = listOf(
                        IpCheckerResponse(
                            label = "ru",
                            url = "https://ru.example",
                            scope = IpCheckerScope.RU,
                            ip = "203.0.113.64",
                        ),
                    ),
                ),
                nonRuGroup = IpCheckerGroupResult(
                    title = "NON_RU",
                    detected = false,
                    statusLabel = "clean",
                    summary = "NON_RU sees 203.0.113.64",
                    canonicalIp = "203.0.113.64",
                    responses = listOf(
                        IpCheckerResponse(
                            label = "non-ru",
                            url = "https://non-ru.example",
                            scope = IpCheckerScope.NON_RU,
                            ip = "203.0.113.64",
                        ),
                    ),
                ),
            ),
            directSigns = CategoryResult(
                name = "Direct",
                detected = false,
                findings = listOf(Finding("No direct signs")),
            ),
            indirectSigns = CategoryResult(
                name = "Indirect",
                detected = false,
                findings = listOf(Finding("No indirect signs")),
            ),
            locationSignals = CategoryResult(
                name = "Location",
                detected = false,
                findings = listOf(Finding("No location conflict")),
            ),
            bypassResult = BypassResult(
                proxyEndpoint = null,
                directIp = "203.0.113.64",
                proxyIp = null,
                vpnNetworkIp = null,
                underlyingIp = null,
                xrayApiScanResult = null,
                proxyChecks = emptyList(),
                findings = listOf(Finding("No bypass for 203.0.113.64")),
                detected = false,
            ),
            verdict = Verdict.NOT_DETECTED,
            tunProbeDiagnostics = null,
        )

        val report = DebugDiagnosticsFormatter.format(
            result = result,
            settings = CheckSettings(tunProbeDebugEnabled = true),
            privacyMode = true,
            timestampMillis = 0L,
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(report.contains("debugDiagnosticsEnabled: true"))
        assertTrue(report.contains("[geoIp]"))
        assertTrue(report.contains("[icmpSpoofing]"))
        assertTrue(report.contains("[bypass]"))
        assertTrue(report.contains("[tunProbe]"))
        assertTrue(report.contains("collected: false"))
        assertTrue(report.contains("proxyChecks:"))
        assertTrue(report.contains("203.0.*.*"))
        assertFalse(report.contains("203.0.113.64"))
    }

    @Test
    fun `formatter includes masked cdn pulling responses and raw body`() {
        val result = CheckResult(
            geoIp = CategoryResult(name = "GeoIP", detected = false, findings = emptyList()),
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
            cdnPulling = CdnPullingResult(
                detected = true,
                summary = "rutracker.org exposed 203.0.113.64",
                responses = listOf(
                    CdnPullingResponse(
                        targetLabel = "rutracker.org",
                        url = "https://rutracker.org/cdn-cgi/trace",
                        ip = "203.0.113.64",
                        importantFields = linkedMapOf("IP" to "203.0.113.64", "LOC" to "FI"),
                        rawBody = "ip=203.0.113.64\nloc=FI",
                    ),
                ),
            ),
            directSigns = CategoryResult(name = "Direct", detected = false, findings = emptyList()),
            indirectSigns = CategoryResult(name = "Indirect", detected = false, findings = emptyList()),
            locationSignals = CategoryResult(name = "Location", detected = false, findings = emptyList()),
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

        val report = DebugDiagnosticsFormatter.format(
            result = result,
            settings = CheckSettings(tunProbeDebugEnabled = true, cdnPullingEnabled = true),
            privacyMode = true,
            timestampMillis = 0L,
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(report.contains("[cdnPulling]"))
        assertTrue(report.contains("cdnPullingEnabled: true"))
        assertTrue(report.contains("target=rutracker.org"))
        assertTrue(report.contains("rawBody=ip=203.0.*.*\\nloc=FI"))
        assertFalse(report.contains("203.0.113.64"))
    }

    @Test
    fun `formatter prints location diagnostics outside findings`() {
        val emptyCategory = CategoryResult(name = "empty", detected = false, findings = emptyList())
        val location = LocationSignalsDiagnosticsRegistry.attach(
            CategoryResult(
                name = "Location",
                detected = false,
                findings = listOf(Finding("Cell lookup candidates: 1")),
            ),
            LocationSignalsDiagnostics(
                fineLocationPermissionGranted = true,
                nearbyWifiPermissionGranted = true,
                locationServicesEnabled = true,
                telephonyRadioAccessAvailable = true,
                wifiFeatureAvailable = true,
                networkRequestsEnabled = true,
                cellRawInfoCount = 2,
                cellRawInfoTypes = listOf("nr"),
                cellCandidateRadios = listOf("nr"),
                beaconDbCellCandidatesUsedCount = 0,
                beaconDbUnsupportedCellRadios = listOf("nr"),
                beaconDbWifiCandidatesUsedCount = 0,
                wifiAccessPointCandidatesCount = 1,
                wifiCachedScanCandidatesCount = 1,
                wifiFreshScanCandidatesCount = null,
                wifiConnectedCandidateAvailable = false,
                bssidSource = "single Wi-Fi scan candidate",
                bssidUnavailableReason = "connected Wi-Fi info is redacted by Android",
            ),
        )
        val result = CheckResult(
            geoIp = emptyCategory,
            ipComparison = IpComparisonResult(
                detected = false,
                summary = "",
                ruGroup = IpCheckerGroupResult(title = "RU", detected = false, statusLabel = "", summary = "", responses = emptyList()),
                nonRuGroup = IpCheckerGroupResult(title = "NON_RU", detected = false, statusLabel = "", summary = "", responses = emptyList()),
            ),
            directSigns = emptyCategory,
            indirectSigns = emptyCategory,
            locationSignals = location,
            bypassResult = BypassResult(
                proxyEndpoint = null,
                directIp = null,
                proxyIp = null,
                vpnNetworkIp = null,
                underlyingIp = null,
                xrayApiScanResult = null,
                proxyChecks = emptyList(),
                findings = emptyList(),
                detected = false,
            ),
            verdict = Verdict.NOT_DETECTED,
        )

        val report = DebugDiagnosticsFormatter.format(
            result = result,
            settings = CheckSettings(),
            privacyMode = true,
        )

        assertTrue(report.contains("[locationSignals.debug]"))
        assertTrue(report.contains("cellRawInfoCount: 2"))
        assertTrue(report.contains("cellRawInfoTypes: nr"))
        assertTrue(report.contains("beaconDbUnsupportedCellRadios: nr"))
        assertTrue(report.contains("wifiFreshScanCandidatesCount: <timeout>"))
        assertFalse(report.contains("- description=Cell raw info:"))
    }

    @Test
    fun `formatter includes detailed errors evidence and network sources`() {
        val result = CheckResult(
            geoIp = CategoryResult(
                name = "GeoIP",
                detected = true,
                findings = listOf(
                    Finding(
                        description = "GeoIP fetch failed for 198.51.100.7",
                        isError = true,
                        source = EvidenceSource.GEO_IP,
                        confidence = EvidenceConfidence.LOW,
                    ),
                ),
                evidence = listOf(
                    EvidenceItem(
                        source = EvidenceSource.GEO_IP,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Resolver used 8.8.8.8",
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
                    statusLabel = "error",
                    summary = "RU checker failed for 198.51.100.7",
                    canonicalIp = "198.51.100.7",
                    responses = listOf(
                        IpCheckerResponse(
                            label = "ru-main",
                            url = "https://ru.example/check",
                            scope = IpCheckerScope.RU,
                            error = "timeout 198.51.100.7",
                            ipv4Records = listOf("198.51.100.7"),
                            ipv6Records = listOf("2001:db8:85a3:8d3:1319:8a2e:370:7348"),
                            ignoredIpv6Error = true,
                        ),
                    ),
                    ignoredIpv6ErrorCount = 1,
                ),
                nonRuGroup = IpCheckerGroupResult(
                    title = "NON_RU",
                    detected = true,
                    statusLabel = "ok",
                    summary = "NON_RU returned 203.0.113.64",
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
            directSigns = CategoryResult(
                name = "Direct",
                detected = true,
                findings = listOf(
                    Finding(
                        description = "Detected app com.example.vpn at 198.51.100.7",
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
                    ),
                ),
            ),
            indirectSigns = CategoryResult(
                name = "Indirect",
                detected = true,
                findings = listOf(Finding("Indirect route mismatch 198.51.100.7")),
                callTransportLeaks = listOf(
                    CallTransportLeakResult(
                        service = com.notcvnt.rknhardering.model.CallTransportService.TELEGRAM,
                        probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                        networkPath = CallTransportNetworkPath.UNDERLYING,
                        status = CallTransportStatus.ERROR,
                        targetHost = "198.51.100.7",
                        targetPort = 3478,
                        resolvedIps = listOf("198.51.100.7"),
                        mappedIp = "203.0.113.64",
                        observedPublicIp = "198.51.100.8",
                        summary = "STUN error from 198.51.100.7",
                        confidence = EvidenceConfidence.MEDIUM,
                        experimental = true,
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
            verdict = Verdict.DETECTED,
            tunProbeDiagnostics = null,
        )

        val report = DebugDiagnosticsFormatter.format(
            result = result,
            settings = CheckSettings(
                tunProbeDebugEnabled = true,
                resolverConfig = DnsResolverConfig(
                    mode = DnsResolverMode.DIRECT,
                    customDirectServers = listOf("8.8.8.8"),
                ),
            ),
            privacyMode = false,
            timestampMillis = 0L,
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(report.contains("resolverMode: DIRECT"))
        assertTrue(report.contains("error=true"))
        assertTrue(report.contains("source=GEO_IP"))
        assertTrue(report.contains("matchedApps:"))
        assertTrue(report.contains("activeApps:"))
        assertTrue(report.contains("callTransport:"))
        assertTrue(report.contains("service=TELEGRAM"))
        assertTrue(report.contains("ignoredIpv6Error=true"))
        assertTrue(report.contains("proxyEndpoint: 127.0.0.1:1080 (SOCKS5)"))
        assertTrue(report.contains("proxyChecks:"))
        assertTrue(report.contains("ownerStatus=RESOLVED"))
        assertTrue(report.contains("status=CONFIRMED_BYPASS"))
        assertTrue(report.contains("summaryReason=CONFIRMED_BYPASS"))
        assertTrue(report.contains("endpoint=127.0.0.1:8080 outboundCount=1"))
        assertTrue(report.contains("uuidPresent=true"))
        assertTrue(report.contains("publicKeyPresent=true"))
        assertTrue(report.contains("198.51.*.*"))
        assertFalse(report.contains("198.51.100.7"))
        assertFalse(report.contains("secret-uuid"))
        assertFalse(report.contains("secret-public-key"))
    }

    @Test
    fun `formatter marks section errors explicitly`() {
        val base = exportEmptyCheckResult()
        val result = base.copy(
            ipComparison = base.ipComparison.copy(
                needsReview = true,
                hasError = true,
                summary = "ip comparison failed",
            ),
            cdnPulling = CdnPullingResult(
                detected = false,
                needsReview = true,
                hasError = true,
                summary = "cdn failed",
                findings = listOf(Finding("cdn failed", isError = true)),
            ),
            directSigns = CategoryResult(
                name = "Direct",
                detected = false,
                needsReview = true,
                findings = listOf(Finding("direct failed", isError = true)),
            ),
            bypassResult = base.bypassResult.copy(
                needsReview = true,
                findings = listOf(Finding("bypass failed", isError = true)),
            ),
        )

        val report = DebugDiagnosticsFormatter.format(
            result = result,
            settings = CheckSettings(),
            privacyMode = false,
        )

        assertTrue(report.contains("[ipComparison]\ndetected: false\nneedsReview: true\nhasError: true\nstatus: [ERROR]"))
        assertTrue(report.contains("[cdnPulling]\ndetected: false\nneedsReview: true\nhasError: true\nstatus: [ERROR]"))
        assertTrue(report.contains("[directSigns]\nname: Direct\ndetected: false\nneedsReview: true\nhasError: true\nstatus: [ERROR]"))
        assertTrue(report.contains("[bypass]\ndetected: false\nneedsReview: true\nhasError: true\nstatus: [ERROR]"))
    }

    @Test
    fun `formatter prints indirect performance diagnostics`() {
        val indirect = CategoryResult(
            name = "Indirect",
            detected = false,
            findings = listOf(Finding("No indirect signs")),
        )
        val result = CheckResult(
            geoIp = CategoryResult(name = "GeoIP", detected = false, findings = emptyList()),
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
            directSigns = CategoryResult(name = "Direct", detected = false, findings = emptyList()),
            indirectSigns = indirect,
            locationSignals = CategoryResult(name = "Location", detected = false, findings = emptyList()),
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
        IndirectCheckPerformanceRegistry.attach(
            category = indirect,
            diagnostics = IndirectCheckPerformanceDiagnostics(
                totalDurationMs = 34_500L,
                steps = listOf(
                    DebugStepTiming(name = "collectNetworkSnapshots", durationMs = 50L),
                    DebugStepTiming(name = "checkCallTransportSignals", durationMs = 31_000L),
                    DebugStepTiming(name = "checkDumpsysVpn", durationMs = 1_200L),
                    DebugStepTiming(name = "checkDumpsysVpnService", durationMs = 800L),
                ),
                callTransport = CallTransportPerformanceDiagnostics(
                    totalDurationMs = 31_000L,
                    steps = listOf(
                        DebugStepTiming(name = "probeDirect", durationMs = 500L),
                        DebugStepTiming(name = "findLocalProxyEndpoint", durationMs = 500L),
                        DebugStepTiming(name = "probeProxyAssistedTelegram", durationMs = 0L, skipped = true),
                        DebugStepTiming(name = "probeStunTargets", durationMs = 30_000L),
                    ),
                    stunScopeTimings = listOf(
                        StunScopeTiming(
                            scope = StunScope.GLOBAL,
                            durationMs = 28_000L,
                            targetCount = 20,
                            respondedCount = 2,
                            noResponseCount = 18,
                        ),
                        StunScopeTiming(
                            scope = StunScope.RU,
                            durationMs = 2_000L,
                            targetCount = 2,
                            respondedCount = 0,
                            noResponseCount = 2,
                        ),
                    ),
                ),
            ),
        )

        val report = DebugDiagnosticsFormatter.format(
            result = result,
            settings = CheckSettings(tunProbeDebugEnabled = true, callTransportProbeEnabled = true),
            privacyMode = false,
            timestampMillis = 0L,
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(report.contains("[indirectSigns.performance]"))
        assertTrue(report.contains("dominantDelay: STUN sweep"))
        assertTrue(report.contains("callTransport.totalStunTargets: 22"))
        assertTrue(report.contains("callTransport.respondedStunTargets: 2"))
        assertTrue(report.contains("scope=GLOBAL"))
        assertTrue(report.contains("name=probeStunTargets durationMs=30000 skipped=false"))
    }

    @Test
    fun `formatter includes operatorWhitelist section with errors when probe present`() {
        val base = CheckResult(
            geoIp = CategoryResult(name = "GeoIP", detected = false, findings = emptyList()),
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
            directSigns = CategoryResult(name = "Direct", detected = false, findings = emptyList()),
            indirectSigns = CategoryResult(name = "Indirect", detected = false, findings = emptyList()),
            locationSignals = CategoryResult(name = "Location", detected = false, findings = emptyList()),
            bypassResult = BypassResult(
                proxyEndpoint = null,
                directIp = null,
                proxyIp = null,
                xrayApiScanResult = null,
                findings = emptyList(),
                detected = false,
            ),
            verdict = Verdict.NOT_DETECTED,
            operatorWhitelistProbe = OperatorWhitelistProbeResult(
                whitelistDetected = true,
                googleReachable = false,
                appleReachable = false,
                firefoxReachable = false,
                russianControlReachable = true,
                errors = mapOf("google" to "timeout", "apple" to "connection refused"),
                durationMs = 4521L,
            ),
        )

        val report = DebugDiagnosticsFormatter.format(
            result = base,
            settings = CheckSettings(tunProbeDebugEnabled = false),
            privacyMode = false,
            timestampMillis = 0L,
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(report.contains("[operatorWhitelist]"))
        assertTrue(report.contains("collected: true"))
        assertTrue(report.contains("detected: true"))
        assertTrue(report.contains("googleReachable: false"))
        assertTrue(report.contains("russianControlReachable: true"))
        assertTrue(report.contains("durationMs: 4521"))
        assertTrue(report.contains("- google: timeout"))
        assertTrue(report.contains("- apple: connection refused"))
    }

    @Test
    fun `formatter reports operatorWhitelist not collected when probe is null`() {
        val base = CheckResult(
            geoIp = CategoryResult(name = "GeoIP", detected = false, findings = emptyList()),
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
            directSigns = CategoryResult(name = "Direct", detected = false, findings = emptyList()),
            indirectSigns = CategoryResult(name = "Indirect", detected = false, findings = emptyList()),
            locationSignals = CategoryResult(name = "Location", detected = false, findings = emptyList()),
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

        val report = DebugDiagnosticsFormatter.format(
            result = base,
            settings = CheckSettings(tunProbeDebugEnabled = false),
            privacyMode = false,
            timestampMillis = 0L,
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(report.contains("[operatorWhitelist]"))
        assertTrue(report.contains("collected: false"))
        assertFalse(report.contains("detected: true"))
    }
}
