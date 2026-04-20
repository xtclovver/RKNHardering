package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.LocalProxyCheckStatus
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.LocalProxyOwnerStatus
import com.notcvnt.rknhardering.model.LocalProxySummaryReason
import com.notcvnt.rknhardering.probe.LocalSocketListener
import com.notcvnt.rknhardering.probe.MtProtoProber
import com.notcvnt.rknhardering.probe.PublicIpModeProbeResult
import com.notcvnt.rknhardering.probe.PublicIpNetworkComparison
import com.notcvnt.rknhardering.probe.PublicIpProbeMode
import com.notcvnt.rknhardering.probe.PublicIpProbeStatus
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.TunProbeDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeModeOverride
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.probe.PerTargetProbe
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetSocketAddress

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BypassCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `explicit vpn network binding on non vpn default network is detected`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "198.51.100.10", directIp = "203.0.113.20"),
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(outcome.detected)
        assertFalse(outcome.needsReview)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertTrue(findings.any { it.description.contains("VPN network binding") })
    }

    @Test
    fun `underlying reachability is treated as gateway leak only when default network is vpn`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "198.51.100.10", directIp = "203.0.113.20"),
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(outcome.detected)
        assertFalse(outcome.needsReview)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
    }

    @Test
    fun `vpn network binding requires verified underlying internet path`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "198.51.100.10"),
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(
            findings.any {
                it.needsReview &&
                    it.source == EvidenceSource.VPN_NETWORK_BINDING &&
                    it.description.contains("manual review")
            },
        )
    }

    @Test
    fun `gateway leak requires vpn and underlying ip comparison`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, directIp = "203.0.113.20"),
                vpnError = "timeout",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(
            findings.any {
                it.source == EvidenceSource.VPN_GATEWAY_LEAK &&
                    it.needsReview &&
                    it.description.contains("203.0.113.20")
            },
        )
    }

    @Test
    fun `gateway leak falls back to manual review on mixed ip families`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "2001:db8::10", directIp = "203.0.113.20"),
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(findings.any { it.needsReview && it.description.contains("different IP families") })
    }

    @Test
    fun `gateway leak not detected when vpn ip and underlying ip are the same`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "128.71.10.5", directIp = "128.71.10.5"),
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(findings.any { it.isInformational && it.source == EvidenceSource.VPN_GATEWAY_LEAK })
    }

    @Test
    fun `vpn network binding is not detected when default and vpn ips match`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "203.0.113.10", directIp = "203.0.113.10"),
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(findings.any { it.isInformational && it.source == EvidenceSource.VPN_NETWORK_BINDING })
    }

    @Test
    fun `vpn network binding falls back to manual review on mixed ip families`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "2001:db8::10", directIp = "203.0.113.20"),
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(findings.any { it.needsReview && it.description.contains("different IP families") })
    }

    @Test
    fun `gateway leak falls back to needs review when vpn comparison relies on curl compatible fallback`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(
                    targetHost = "",
                    targetGroup = TargetGroup.RU,
                    vpnIp = "198.51.100.10",
                    directIp = "203.0.113.20",
                    comparison = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.FAILED,
                            error = "strict timeout",
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "198.51.100.10",
                        ),
                        selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                        selectedIp = "198.51.100.10",
                        dnsPathMismatch = true,
                    ),
                ),
                activeNetworkIsVpn = true,
                tunProbeDiagnostics = TunProbeDiagnostics(
                    enabled = true,
                    modeOverride = TunProbeModeOverride.AUTO,
                    activeNetworkIsVpn = true,
                    vpnNetworkPresent = true,
                    underlyingNetworkPresent = true,
                    vpnPath = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.FAILED,
                            error = "strict timeout",
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "198.51.100.10",
                        ),
                        selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                        selectedIp = "198.51.100.10",
                        dnsPathMismatch = true,
                    ).toPathDiagnostics("tun0"),
                    underlyingPath = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.FAILED,
                            error = "underlying strict timeout",
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.FAILED,
                            error = "underlying bind failed",
                        ),
                        selectedError = "underlying bind failed",
                    ).toPathDiagnostics("wlan0"),
                ),
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(findings.any { it.needsReview && it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertTrue(findings.any { it.isInformational && it.description.contains("curl-compatible transport-only fallback") })
        assertTrue(findings.any { it.isInformational && it.description.contains("VPN path debug") })
        assertTrue(findings.any { it.isInformational && it.description.contains("underlying path debug") })
    }

    @Test
    fun `vpn binding falls back to needs review when comparison relies on curl compatible fallback`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(
                    targetHost = "",
                    targetGroup = TargetGroup.RU,
                    vpnIp = "203.0.113.10",
                    directIp = "198.51.100.10",
                    comparison = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.FAILED,
                            error = "strict timeout",
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "203.0.113.10",
                        ),
                        selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                        selectedIp = "203.0.113.10",
                        dnsPathMismatch = true,
                    ),
                ),
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertTrue(findings.any { it.isInformational && it.description.contains("curl-compatible transport-only fallback") })
        assertTrue(findings.any { it.needsReview && it.source == EvidenceSource.VPN_NETWORK_BINDING })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
    }

    @Test
    fun `transport only fallback does not reintroduce review when merged vpn ip is present`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(
                    targetHost = "",
                    targetGroup = TargetGroup.RU,
                    vpnIp = "203.0.113.10",
                    directIp = "203.0.113.10",
                    comparison = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.FAILED,
                            error = "strict timeout",
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "203.0.113.10",
                        ),
                        selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                        selectedIp = "203.0.113.10",
                        dnsPathMismatch = true,
                    ),
                ),
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
        assertTrue(findings.any { it.isInformational && it.description.contains("curl-compatible transport-only fallback") })
        assertFalse(findings.any { it.needsReview && it.description.contains("strict timeout") })
    }

    @Test
    fun `forced curl compatible mode does not downgrade confirmed gateway leak`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                ruTarget = PerTargetProbe(
                    targetHost = "",
                    targetGroup = TargetGroup.RU,
                    vpnIp = "198.51.100.10",
                    directIp = "203.0.113.20",
                    comparison = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.SKIPPED,
                            error = "Disabled by override",
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "198.51.100.10",
                        ),
                        selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                        selectedIp = "198.51.100.10",
                    ),
                ),
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(outcome.detected)
        assertFalse(outcome.needsReview)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertFalse(findings.any { it.isInformational && it.description.contains("curl-compatible transport-only fallback") })
    }

    @Test
    fun `proxy evaluation continues after mtproto only endpoint and confirms later bypass`() = runBlocking {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val evaluation = BypassChecker.evaluateProxyEndpoints(
            context = context,
            resolverConfig = com.notcvnt.rknhardering.network.DnsResolverConfig.system(),
            proxyEndpoints = listOf(
                ProxyEndpoint(host = "127.0.0.1", port = 2080, type = ProxyType.SOCKS5),
                ProxyEndpoint(host = "127.0.0.1", port = 39365, type = ProxyType.SOCKS5),
            ),
            findings = findings,
            evidence = evidence,
            fetchDirectIp = { Result.success("109.236.0.10") },
            fetchProxyIp = { endpoint ->
                when (endpoint.port) {
                    2080 -> Result.failure(IllegalStateException("blocked"))
                    39365 -> Result.success("45.80.0.20")
                    else -> Result.failure(IllegalArgumentException("unexpected port"))
                }
            },
            resolveProxyOwnerMatch = { endpoint ->
                when (endpoint.port) {
                    39365 -> BypassChecker.ProxyOwnerMatch(
                        owner = owner(uid = 10127, packageName = "com.nekobox", appLabel = "NekoBox"),
                        status = LocalProxyOwnerStatus.RESOLVED,
                    )
                    else -> BypassChecker.ProxyOwnerMatch(status = LocalProxyOwnerStatus.UNRESOLVED)
                }
            },
            probeMtProto = { endpoint ->
                when (endpoint.port) {
                    2080 -> MtProtoProber.ProbeResult(
                        reachable = true,
                        targetAddress = InetSocketAddress("149.154.167.51", 443),
                    )
                    else -> MtProtoProber.ProbeResult(reachable = false, targetAddress = null)
                }
            },
        )

        assertTrue(evaluation.confirmedBypass)
        assertEquals(39365, evaluation.summaryProxyEndpoint?.port)
        assertEquals("45.80.0.20", evaluation.summaryProxyIp)
        assertEquals(2, evaluation.proxyChecks.size)
        assertEquals(LocalProxyCheckStatus.PROXY_IP_UNAVAILABLE, evaluation.proxyChecks[0].status)
        assertEquals(LocalProxyCheckStatus.CONFIRMED_BYPASS, evaluation.proxyChecks[1].status)
        assertEquals(LocalProxySummaryReason.CONFIRMED_BYPASS, evaluation.proxyChecks[1].summaryReason)
        assertTrue(evidence.any { it.source == EvidenceSource.SPLIT_TUNNEL_BYPASS && it.detected })
        assertTrue(findings.any { it.description.contains("127.0.0.1:2080") })
        assertTrue(
            findings.any {
                it.description == context.getString(
                    R.string.checker_bypass_mtproto_reachable,
                    "127.0.0.1:2080",
                    "149.154.167.51:443",
                )
            },
        )
        assertTrue(findings.any { it.description.contains("127.0.0.1:39365") })
        assertTrue(findings.any { it.description == context.getString(R.string.checker_bypass_split_confirmed) && it.detected })
    }

    @Test
    fun `proxy evaluation keeps all proxies when public ips match`() = runBlocking {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val evaluation = BypassChecker.evaluateProxyEndpoints(
            context = context,
            resolverConfig = com.notcvnt.rknhardering.network.DnsResolverConfig.system(),
            proxyEndpoints = listOf(
                ProxyEndpoint(host = "127.0.0.1", port = 2080, type = ProxyType.SOCKS5),
                ProxyEndpoint(host = "127.0.0.1", port = 39365, type = ProxyType.HTTP),
            ),
            findings = findings,
            evidence = evidence,
            fetchDirectIp = { Result.success("109.236.0.10") },
            fetchProxyIp = { Result.success("109.236.0.10") },
            resolveProxyOwnerMatch = { BypassChecker.ProxyOwnerMatch(status = LocalProxyOwnerStatus.UNRESOLVED) },
        )

        assertFalse(evaluation.confirmedBypass)
        assertEquals(2, evaluation.proxyChecks.size)
        assertTrue(evaluation.proxyChecks.all { it.status == LocalProxyCheckStatus.SAME_IP })
        assertEquals(2080, evaluation.summaryProxyEndpoint?.port)
        assertEquals(LocalProxySummaryReason.FIRST_WITH_PROXY_IP, evaluation.proxyChecks[0].summaryReason)
        assertFalse(evidence.any { it.source == EvidenceSource.SPLIT_TUNNEL_BYPASS && it.detected })
        assertEquals(2, findings.count { it.description == context.getString(R.string.checker_bypass_split_disabled) })
    }

    @Test
    fun `proxy evaluation inspects every candidate when proxy ip is unavailable`() = runBlocking {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        val mtProtoPorts = mutableListOf<Int>()

        val evaluation = BypassChecker.evaluateProxyEndpoints(
            context = context,
            resolverConfig = com.notcvnt.rknhardering.network.DnsResolverConfig.system(),
            proxyEndpoints = listOf(
                ProxyEndpoint(host = "127.0.0.1", port = 2080, type = ProxyType.SOCKS5),
                ProxyEndpoint(host = "127.0.0.1", port = 39365, type = ProxyType.SOCKS5),
            ),
            findings = findings,
            evidence = evidence,
            fetchDirectIp = { Result.success("109.236.0.10") },
            fetchProxyIp = { Result.failure(IllegalStateException("timeout")) },
            resolveProxyOwnerMatch = { BypassChecker.ProxyOwnerMatch(status = LocalProxyOwnerStatus.UNRESOLVED) },
            probeMtProto = { endpoint ->
                mtProtoPorts += endpoint.port
                MtProtoProber.ProbeResult(reachable = false, targetAddress = null)
            },
        )

        assertFalse(evaluation.confirmedBypass)
        assertEquals(listOf(2080, 39365), mtProtoPorts)
        assertEquals(2, evaluation.proxyChecks.size)
        assertTrue(evaluation.proxyChecks.all { it.status == LocalProxyCheckStatus.PROXY_IP_UNAVAILABLE })
        assertEquals(LocalProxySummaryReason.FIRST_DISCOVERED, evaluation.proxyChecks[0].summaryReason)
        assertEquals(
            2,
            findings.count {
                it.description == context.getString(
                    R.string.checker_bypass_proxy_ip,
                    context.getString(R.string.checker_bypass_ip_unavailable),
                )
            },
        )
        assertEquals(2, findings.count { it.description == context.getString(R.string.checker_bypass_mtproto_unreachable) })
    }

    @Test
    fun `proxy owner matches exact host and port`() {
        val owner = owner(uid = 10123, packageName = "com.whatsapp", appLabel = "WhatsApp")

        val match = BypassChecker.matchProxyOwner(
            proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            listeners = listOf(
                listener(host = "127.0.0.1", port = 1080, owner = owner),
                listener(host = "0.0.0.0", port = 1080, owner = null),
            ),
        )

        assertEquals(LocalProxyOwnerStatus.RESOLVED, match.status)
        assertEquals(owner, match.owner)
    }

    @Test
    fun `proxy owner falls back to any address listener when unique`() {
        val owner = owner(uid = 10124, packageName = "com.whatsapp", appLabel = "WhatsApp")

        val match = BypassChecker.matchProxyOwner(
            proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 8080, type = ProxyType.HTTP),
            listeners = listOf(
                listener(host = "0.0.0.0", port = 8080, owner = owner),
            ),
        )

        assertEquals(LocalProxyOwnerStatus.RESOLVED, match.status)
        assertEquals(owner, match.owner)
    }

    @Test
    fun `proxy owner is ambiguous when multiple fallback listeners share a port`() {
        val match = BypassChecker.matchProxyOwner(
            proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 8080, type = ProxyType.HTTP),
            listeners = listOf(
                listener(host = "0.0.0.0", port = 8080, owner = owner(uid = 10125, packageName = "com.first", appLabel = "First")),
                listener(host = "::", port = 8080, protocol = "tcp6", owner = owner(uid = 10126, packageName = "com.second", appLabel = "Second")),
            ),
        )

        assertEquals(LocalProxyOwnerStatus.AMBIGUOUS, match.status)
        assertNull(match.owner)
    }

    private fun listener(
        host: String,
        port: Int,
        protocol: String = "tcp",
        owner: LocalProxyOwner?,
    ): LocalSocketListener = LocalSocketListener(
        protocol = protocol,
        host = host,
        port = port,
        state = "0A",
        uid = owner?.uid,
        inode = 0L,
        owner = owner,
    )

    private fun owner(uid: Int, packageName: String, appLabel: String): LocalProxyOwner = LocalProxyOwner(
        uid = uid,
        packageNames = listOf(packageName),
        appLabels = listOf(appLabel),
        confidence = com.notcvnt.rknhardering.model.EvidenceConfidence.HIGH,
    )
}
