package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.probe.PublicIpModeProbeResult
import com.notcvnt.rknhardering.probe.PublicIpNetworkComparison
import com.notcvnt.rknhardering.probe.PublicIpProbeMode
import com.notcvnt.rknhardering.probe.PublicIpProbeStatus
import com.notcvnt.rknhardering.probe.PublicIpTransportDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeModeOverride
import com.notcvnt.rknhardering.probe.TunProbeResolveStrategy
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.probe.PerTargetProbe
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class DirectSignsCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `matches documented proxy ports`() {
        assertTrue(DirectSignsChecker.isKnownProxyPort("1080"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("3128"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("8081"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("9051"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("12345"))
    }

    @Test
    fun `matches documented proxy port ranges`() {
        assertTrue(DirectSignsChecker.isKnownProxyPort("16000"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("16042"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("16100"))
    }

    @Test
    fun `ignores unknown or invalid ports`() {
        assertFalse(DirectSignsChecker.isKnownProxyPort(null))
        assertFalse(DirectSignsChecker.isKnownProxyPort("abc"))
        assertFalse(DirectSignsChecker.isKnownProxyPort("53"))
        assertFalse(DirectSignsChecker.isKnownProxyPort("16101"))
    }

    @Test
    fun `host and port are treated as direct system proxy evidence`() {
        val result = DirectSignsChecker.evaluateProxyEndpoint(context, "HTTP proxy", "127.0.0.1", "8080")

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.evidence.any { it.source == EvidenceSource.SYSTEM_PROXY && it.detected })
    }

    @Test
    fun `host without valid port only needs review`() {
        val result = DirectSignsChecker.evaluateProxyEndpoint(context, "HTTP proxy", "127.0.0.1", null)

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.findings.any { it.needsReview })
        assertTrue(result.evidence.any { it.source == EvidenceSource.SYSTEM_PROXY && !it.detected })
    }

    @Test
    fun `known proxy port adds a dedicated finding`() {
        val result = DirectSignsChecker.evaluateProxyEndpoint(context, "SOCKS proxy", "127.0.0.1", "1080")

        assertTrue(result.detected)
        assertTrue(result.findings.any { it.description.contains("1080") && it.detected })
        assertTrue(result.evidence.count { it.source == EvidenceSource.SYSTEM_PROXY && it.detected } >= 2)
    }

    @Test
    fun `default pac proxy profile is detected and shown to user`() {
        val result = DirectSignsChecker.evaluateProxyProfileCollection(
            context = context,
            collection = DirectSignsChecker.ProxyProfileCollection(
                defaultProfile = DirectSignsChecker.ProxyProfileSnapshot(
                    isDefault = true,
                    pacUrl = "https://proxy.example/wpad.dat",
                    exclusions = listOf("localhost", "*.corp"),
                ),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.detected && it.description.contains("pac=https://proxy.example/wpad.dat") })
        assertTrue(result.findings.any { it.description.contains("excl=localhost, *.corp") })
        assertTrue(result.evidence.any { it.source == EvidenceSource.SYSTEM_PROXY && it.detected })
    }

    @Test
    fun `default direct proxy profile keeps known port heuristic`() {
        val result = DirectSignsChecker.evaluateProxyProfileCollection(
            context = context,
            collection = DirectSignsChecker.ProxyProfileCollection(
                defaultProfile = DirectSignsChecker.ProxyProfileSnapshot(
                    isDefault = true,
                    host = "10.0.0.10",
                    port = 8080,
                    exclusions = listOf("localhost"),
                ),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.detected && it.description.contains("host=10.0.0.10") })
        assertTrue(result.findings.any { it.detected && it.description.contains("8080") })
        assertTrue(result.findings.any { it.detected && it.description.contains("known port 8080") })
    }

    @Test
    fun `per-network proxy profile uses interface name`() {
        val result = DirectSignsChecker.evaluateProxyProfileCollection(
            context = context,
            collection = DirectSignsChecker.ProxyProfileCollection(
                networkProfiles = listOf(
                    DirectSignsChecker.ProxyProfileSnapshot(
                        interfaceName = "wlan0",
                        host = "192.0.2.10",
                        port = 3128,
                    ),
                ),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.findings.any { it.description.contains("wlan0") && it.description.contains("host=192.0.2.10") })
        assertFalse(result.findings.any { it.description.contains("tracked networks") && it.description.contains("not detected") })
    }

    @Test
    fun `empty proxyinfo collection shows visible clear checks`() {
        val result = DirectSignsChecker.evaluateProxyProfileCollection(
            context = context,
            collection = DirectSignsChecker.ProxyProfileCollection(),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals(2, result.findings.size)
        assertTrue(result.findings.any { it.description.contains("not configured") })
        assertTrue(result.findings.any { it.description.contains("tracked networks") && it.description.contains("not detected") })
    }

    @Test
    fun `invalid proxy profile on api 30 plus only needs review`() {
        val result = DirectSignsChecker.evaluateProxyProfileCollection(
            context = context,
            collection = DirectSignsChecker.ProxyProfileCollection(
                defaultProfile = DirectSignsChecker.ProxyProfileSnapshot(
                    isDefault = true,
                    host = "10.0.0.10",
                    port = 8080,
                    pacUrl = "https://proxy.example/wpad.dat",
                    valid = false,
                ),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.findings.any { it.needsReview && it.description.contains("invalid") })
        assertTrue(result.evidence.none { it.detected })
    }

    @Test
    fun `proxyinfo collection failure is surfaced as needs review`() {
        val result = DirectSignsChecker.evaluateProxyProfileCollection(
            context = context,
            collection = DirectSignsChecker.ProxyProfileCollection(
                networkError = "boom",
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.findings.any { it.needsReview && it.description.contains("boom") })
    }

    @Test
    fun `check marks tun probe success as needs review without mismatch`() {
        // existing setup that produces a successful TUN probe with vpnIp != null and no dnsPathMismatch
        val result = DirectSignsChecker.check(
            context = context,
            tunActiveProbeResult = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "198.51.100.10"),
                activeNetworkIsVpn = true,
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.evidence.any { it.source == EvidenceSource.TUN_ACTIVE_PROBE && !it.detected })
    }

    @Test
    fun `check marks tun probe success as detected when dns path mismatches`() {
        // construct probeResult where vpnIpComparison.dnsPathMismatch == true
        val result = DirectSignsChecker.check(
            context = context,
            tunActiveProbeResult = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                ruTarget = PerTargetProbe(
                    targetHost = "",
                    targetGroup = TargetGroup.RU,
                    vpnIp = "198.51.100.10",
                    comparison = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "198.51.100.10",
                            transportDiagnostics = PublicIpTransportDiagnostics(
                                resolveStrategy = TunProbeResolveStrategy.KOTLIN_INJECTED,
                            ),
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "198.51.100.10",
                        ),
                        selectedMode = PublicIpProbeMode.STRICT_SAME_PATH,
                        selectedIp = "198.51.100.10",
                        dnsPathMismatch = true,
                    ),
                ),
                activeNetworkIsVpn = true,
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.evidence.any {
            it.source == EvidenceSource.TUN_ACTIVE_PROBE && it.detected &&
                it.confidence == EvidenceConfidence.HIGH
        })
    }

    @Test
    fun `check marks tun probe failure as needs review`() {
        val result = DirectSignsChecker.check(
            context = context,
            tunActiveProbeResult = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnError = "timeout",
                activeNetworkIsVpn = true,
            ),
        )

        assertTrue(
            result.findings.any {
                it.needsReview &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.description.contains("timeout")
            },
        )
        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.evidence.none { it.source == EvidenceSource.TUN_ACTIVE_PROBE && it.detected })
    }

    @Test
    fun `forced curl mode is treated as selected path instead of fallback`() {
        val comparison = PublicIpNetworkComparison(
            strict = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.STRICT_SAME_PATH,
                status = PublicIpProbeStatus.SKIPPED,
                error = "Disabled by override",
            ),
            curlCompatible = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                status = PublicIpProbeStatus.SUCCEEDED,
                ip = "198.51.100.31",
            ),
            selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
            selectedIp = "198.51.100.31",
            dnsPathMismatch = true,
        )
        val result = DirectSignsChecker.check(
            context = context,
            tunActiveProbeResult = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "198.51.100.31", comparison = comparison),
                activeNetworkIsVpn = true,
                tunProbeDiagnostics = TunProbeDiagnostics(
                    enabled = true,
                    modeOverride = TunProbeModeOverride.CURL_COMPATIBLE,
                    activeNetworkIsVpn = true,
                    vpnNetworkPresent = true,
                    underlyingNetworkPresent = false,
                    vpnPath = comparison.toPathDiagnostics("tun0"),
                ),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.detected &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.confidence == EvidenceConfidence.HIGH
            },
        )
    }

    @Test
    fun `check marks curl compatible tun probe success as detected and needs review`() {
        val result = DirectSignsChecker.check(
            context = context,
            tunActiveProbeResult = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                ruTarget = PerTargetProbe(
                    targetHost = "",
                    targetGroup = TargetGroup.RU,
                    vpnIp = "198.51.100.30",
                    comparison = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.FAILED,
                            error = "strict timeout",
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "198.51.100.30",
                        ),
                        selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                        selectedIp = "198.51.100.30",
                        dnsPathMismatch = true,
                    ),
                ),
                activeNetworkIsVpn = true,
                tunProbeDiagnostics = TunProbeDiagnostics(
                    enabled = true,
                    modeOverride = TunProbeModeOverride.AUTO,
                    activeNetworkIsVpn = true,
                    vpnNetworkPresent = true,
                    underlyingNetworkPresent = false,
                    vpnPath = PublicIpNetworkComparison(
                        strict = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.STRICT_SAME_PATH,
                            status = PublicIpProbeStatus.FAILED,
                            error = "strict timeout",
                        ),
                        curlCompatible = PublicIpModeProbeResult(
                            mode = PublicIpProbeMode.CURL_COMPATIBLE,
                            status = PublicIpProbeStatus.SUCCEEDED,
                            ip = "198.51.100.30",
                        ),
                        selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                        selectedIp = "198.51.100.30",
                        dnsPathMismatch = true,
                    ).toPathDiagnostics("tun0"),
                ),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(
            result.evidence.any {
                it.detected &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE
            },
        )
        assertTrue(
            result.findings.any {
                it.isInformational &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.description.contains("SO_BINDTODEVICE + system DNS")
            },
        )
        assertTrue(
            result.findings.any {
                it.isInformational &&
                    it.description.contains("effective mode Curl-compatible") &&
                    it.description.contains("selected mode Curl-compatible") &&
                    it.description.contains("dnsPathMismatch true")
            },
        )
        assertFalse(
            result.findings.any {
                it.isInformational &&
                    it.description.contains("effective mode Auto")
            },
        )
    }
}
