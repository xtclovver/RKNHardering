package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.XrayApiEndpoint
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayOutboundSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class VerdictNarrativeTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `split tunnel confirmation is described as public ip only`() {
        val narrative = VerdictNarrativeBuilder.build(
            context = context,
            result = result(
                verdict = Verdict.DETECTED,
                bypass = bypass(
                    directIp = "203.0.113.20",
                    proxyIp = "198.51.100.10",
                    evidence = listOf(evidence(EvidenceSource.SPLIT_TUNNEL_BYPASS)),
                ),
            ),
        )

        assertEquals(ExposureStatus.PUBLIC_IP_ONLY, narrative.exposureStatus)
        assertTrue(narrative.explanation.contains("public"))
        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_direct_ip) &&
                    it.value == "203.0.113.20"
            },
        )
        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_proxy_ip) &&
                    it.value == "198.51.100.10"
            },
        )
    }

    @Test
    fun `xray api endpoint is described as remote endpoint disclosure`() {
        val narrative = VerdictNarrativeBuilder.build(
            context = context,
            result = result(
                verdict = Verdict.DETECTED,
                bypass = bypass(
                    xrayApiScanResult = XrayApiScanResult(
                        endpoint = XrayApiEndpoint(host = "127.0.0.1", port = 10085),
                        outbounds = listOf(
                            XrayOutboundSummary(
                                tag = "proxy",
                                protocolName = "vless",
                                address = "203.0.113.5",
                                port = 443,
                                uuid = null,
                                sni = null,
                                publicKey = null,
                                senderSettingsType = null,
                                proxySettingsType = null,
                            ),
                        ),
                    ),
                    evidence = listOf(evidence(EvidenceSource.XRAY_API)),
                ),
            ),
        )

        assertEquals(ExposureStatus.REMOTE_ENDPOINT_DISCOVERED, narrative.exposureStatus)
        assertTrue(narrative.explanation.contains("Xray API"))
        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_remote_endpoint) &&
                    it.value == "203.0.113.5:443"
            },
        )
    }

    @Test
    fun `tun probe only is described as technical signal`() {
        val narrative = VerdictNarrativeBuilder.build(
            context = context,
            result = result(
                verdict = Verdict.NOT_DETECTED,
                bypass = bypass(
                    findings = listOf(
                        Finding(
                            description = context.getString(
                                R.string.checker_bypass_tun_probe_success,
                                "198.51.100.10",
                            ),
                            isInformational = true,
                            source = EvidenceSource.TUN_ACTIVE_PROBE,
                        ),
                    ),
                ),
            ),
        )

        assertEquals(ExposureStatus.PUBLIC_IP_ONLY, narrative.exposureStatus)
        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_vpn_network_ip)
            },
        )
    }

    @Test
    fun `local proxy without ips stays in local proxy status`() {
        val narrative = VerdictNarrativeBuilder.build(
            context = context,
            result = result(
                verdict = Verdict.NEEDS_REVIEW,
                bypass = bypass(
                    proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
                    needsReview = true,
                ),
            ),
        )

        assertEquals(ExposureStatus.LOCAL_PROXY_OR_API_ONLY, narrative.exposureStatus)
        assertTrue(narrative.explanation.contains("local proxy/API"))
        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_local_proxy) &&
                    it.value.contains("127.0.0.1:1080")
            },
        )
    }

    @Test
    fun `proxy owner is shown in discovered rows`() {
        val narrative = VerdictNarrativeBuilder.build(
            context = context,
            result = result(
                verdict = Verdict.NEEDS_REVIEW,
                bypass = bypass(
                    proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
                    proxyOwner = LocalProxyOwner(
                        uid = 10123,
                        packageNames = listOf("com.whatsapp"),
                        appLabels = listOf("WhatsApp"),
                        confidence = EvidenceConfidence.HIGH,
                    ),
                    needsReview = true,
                ),
            ),
        )

        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_owner_app) &&
                    it.value.contains("WhatsApp")
            },
        )
    }

    @Test
    fun `privacy mode masks ip rows`() {
        val narrative = VerdictNarrativeBuilder.build(
            context = context,
            result = result(
                verdict = Verdict.DETECTED,
                bypass = bypass(
                    directIp = "203.0.113.20",
                    proxyIp = "198.51.100.10",
                    evidence = listOf(evidence(EvidenceSource.SPLIT_TUNNEL_BYPASS)),
                ),
            ),
            privacyMode = true,
        )

        val directRow = narrative.discoveredRows.first {
            it.label == context.getString(R.string.narrative_label_direct_ip)
        }
        val proxyRow = narrative.discoveredRows.first {
            it.label == context.getString(R.string.narrative_label_proxy_ip)
        }

        assertEquals("203.0.*.*", directRow.value)
        assertEquals("198.51.*.*", proxyRow.value)
        assertFalse(proxyRow.value.contains("198.51.100.10"))
    }

    @Test
    fun `gateway leak keeps vpn and real ip order across mixed address families`() {
        val narrative = VerdictNarrativeBuilder.build(
            context = context,
            result = result(
                verdict = Verdict.DETECTED,
                bypass = bypass(
                    vpnNetworkIp = "2001:db8::1",
                    underlyingIp = "198.51.100.10",
                    findings = listOf(
                        Finding(
                            description = context.getString(
                                R.string.checker_bypass_gateway_leak,
                                "2001:db8::1",
                                "198.51.100.10",
                            ),
                            detected = true,
                            source = EvidenceSource.VPN_GATEWAY_LEAK,
                            confidence = EvidenceConfidence.HIGH,
                        ),
                    ),
                    evidence = listOf(evidence(EvidenceSource.VPN_GATEWAY_LEAK)),
                ),
            ),
        )

        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_vpn_network_ip) &&
                    it.value == "2001:db8::1"
            },
        )
        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_real_ip) &&
                    it.value == "198.51.100.10"
            },
        )
    }

    @Test
    fun `empty result falls back to insufficient data`() {
        val narrative = VerdictNarrativeBuilder.build(context = context, result = result())

        assertEquals(ExposureStatus.INSUFFICIENT_DATA, narrative.exposureStatus)
        assertTrue(narrative.explanation.contains("did not find convincing signs"))
    }

    @Test
    fun `call transport leak is shown in discovered rows and reasons`() {
        val narrative = VerdictNarrativeBuilder.build(
            context = context,
            result = result(
                verdict = Verdict.NEEDS_REVIEW,
                bypass = bypass(
                    needsReview = true,
                    callTransportLeaks = listOf(
                        CallTransportLeakResult(
                            service = CallTransportService.TELEGRAM,
                            probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
                            networkPath = CallTransportNetworkPath.ACTIVE,
                            status = CallTransportStatus.NEEDS_REVIEW,
                            targetHost = "149.154.167.51",
                            targetPort = 3478,
                            mappedIp = "198.51.100.20",
                            observedPublicIp = "203.0.113.10",
                            summary = "Telegram call transport via active network responded",
                            confidence = EvidenceConfidence.MEDIUM,
                        ),
                    ),
                ),
            ),
        )

        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_call_transport) &&
                    it.value == "Telegram (direct UDP STUN)"
            },
        )
        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_call_transport_target) &&
                    it.value == "149.154.167.51:3478"
            },
        )
        assertTrue(
            narrative.discoveredRows.any {
                it.label == context.getString(R.string.narrative_label_call_transport_public_ip) &&
                    it.value == "203.0.113.10"
            },
        )
        assertTrue(
            narrative.reasonRows.contains(context.getString(R.string.narrative_reason_call_transport_signal)),
        )
    }

    private fun result(
        verdict: Verdict = Verdict.NOT_DETECTED,
        geoIp: CategoryResult = category(),
        direct: CategoryResult = category(),
        indirect: CategoryResult = category(),
        location: CategoryResult = category(),
        ipComparison: IpComparisonResult = ipComparison(),
        bypass: BypassResult = bypass(),
    ): CheckResult = CheckResult(
        geoIp = geoIp,
        ipComparison = ipComparison,
        directSigns = direct,
        indirectSigns = indirect,
        locationSignals = location,
        bypassResult = bypass,
        verdict = verdict,
    )

    private fun category(
        detected: Boolean = false,
        needsReview: Boolean = false,
        findings: List<Finding> = emptyList(),
    ): CategoryResult = CategoryResult(
        name = "test",
        detected = detected,
        findings = findings,
        needsReview = needsReview,
        evidence = emptyList(),
    )

    private fun ipComparison(
        ruIp: String? = null,
        nonRuIp: String? = null,
        detected: Boolean = false,
        needsReview: Boolean = false,
    ): IpComparisonResult = IpComparisonResult(
        detected = detected,
        needsReview = needsReview,
        summary = "",
        ruGroup = IpCheckerGroupResult(
            title = "RU",
            detected = false,
            needsReview = false,
            statusLabel = "",
            summary = "",
            canonicalIp = ruIp,
            responses = listOf(
                IpCheckerResponse(
                    label = "ru",
                    url = "https://example.ru",
                    scope = IpCheckerScope.RU,
                    ip = ruIp,
                ),
            ),
        ),
        nonRuGroup = IpCheckerGroupResult(
            title = "NON_RU",
            detected = false,
            needsReview = false,
            statusLabel = "",
            summary = "",
            canonicalIp = nonRuIp,
            responses = listOf(
                IpCheckerResponse(
                    label = "non-ru",
                    url = "https://example.com",
                    scope = IpCheckerScope.NON_RU,
                    ip = nonRuIp,
                ),
            ),
        ),
    )

    private fun bypass(
        proxyEndpoint: ProxyEndpoint? = null,
        proxyOwner: LocalProxyOwner? = null,
        directIp: String? = null,
        proxyIp: String? = null,
        vpnNetworkIp: String? = null,
        underlyingIp: String? = null,
        xrayApiScanResult: XrayApiScanResult? = null,
        callTransportLeaks: List<CallTransportLeakResult> = emptyList(),
        findings: List<Finding> = emptyList(),
        detected: Boolean = false,
        needsReview: Boolean = false,
        evidence: List<EvidenceItem> = emptyList(),
    ): BypassResult = BypassResult(
        proxyEndpoint = proxyEndpoint,
        proxyOwner = proxyOwner,
        directIp = directIp,
        proxyIp = proxyIp,
        vpnNetworkIp = vpnNetworkIp,
        underlyingIp = underlyingIp,
        xrayApiScanResult = xrayApiScanResult,
        callTransportLeaks = callTransportLeaks,
        findings = findings,
        detected = detected || evidence.any { it.detected },
        needsReview = needsReview,
        evidence = evidence,
    )

    private fun evidence(source: EvidenceSource): EvidenceItem = EvidenceItem(
        source = source,
        detected = true,
        confidence = EvidenceConfidence.HIGH,
        description = source.name,
    )
}
