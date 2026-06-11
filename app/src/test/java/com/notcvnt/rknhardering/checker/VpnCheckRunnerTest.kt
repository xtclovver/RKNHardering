package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.LocationSignalsFacts
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.probe.PerTargetProbe
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CancellationException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
class VpnCheckRunnerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        VpnCheckRunner.dependenciesOverride = null
    }

    @Test
    fun `call transport still runs when split tunnel is disabled`() = runBlocking {
        val leak = CallTransportLeakResult(
            service = CallTransportService.TELEGRAM,
            probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
            networkPath = CallTransportNetworkPath.ACTIVE,
            status = CallTransportStatus.NEEDS_REVIEW,
            targetHost = "149.154.167.51",
            targetPort = 3478,
            mappedIp = "198.51.100.20",
            observedPublicIp = "203.0.113.10",
            summary = "Telegram call transport responded",
            confidence = EvidenceConfidence.MEDIUM,
        )

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, networkRequestsEnabled, callTransportProbeEnabled, _, _, _ ->
                assertTrue(networkRequestsEnabled)
                assertTrue(callTransportProbeEnabled)
                category(
                    name = "indirect",
                    needsReview = true,
                    callTransportLeaks = listOf(leak),
                    evidence = listOf(
                        EvidenceItem(
                            source = EvidenceSource.TELEGRAM_CALL_TRANSPORT,
                            detected = true,
                            confidence = EvidenceConfidence.MEDIUM,
                            description = leak.summary,
                        ),
                    ),
                )
            },
            locationCheck = { _, _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                callTransportProbeEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertTrue(result.indirectSigns.callTransportLeaks.any { it.status == CallTransportStatus.NEEDS_REVIEW })
        assertTrue(
            result.ipConsensus.observedIps.any { it.channel == Channel.DIRECT && it.value == "198.51.100.20" },
        )
        assertEquals(Verdict.NEEDS_REVIEW, result.verdict)
    }

    @Test
    fun `bypass runner forwards separate proxy and xray scan toggles`() = runBlocking {
        var capturedProxyScanEnabled: Boolean? = null
        var capturedXrayApiScanEnabled: Boolean? = null

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            bypassCheck = { _, _, splitTunnelEnabled, proxyScanEnabled, _, xrayApiScanEnabled, _, _, _, _, _, _, _, _, _ ->
                assertTrue(splitTunnelEnabled)
                capturedProxyScanEnabled = proxyScanEnabled
                capturedXrayApiScanEnabled = xrayApiScanEnabled
                BypassResult(
                    proxyEndpoint = null,
                    directIp = null,
                    proxyIp = null,
                    xrayApiScanResult = null,
                    findings = emptyList(),
                    detected = false,
                )
            },
        )

        VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = true,
                proxyScanEnabled = false,
                xrayApiScanEnabled = true,
                networkRequestsEnabled = false,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertEquals(false, capturedProxyScanEnabled)
        assertEquals(true, capturedXrayApiScanEnabled)
    }

    @Test
    fun `icmp spoofing check runs only when network requests are enabled`() = runBlocking {
        var icmpCalls = 0

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            icmpSpoofingCheck = { _, _, _ ->
                icmpCalls += 1
                category(
                    name = "icmp",
                    needsReview = true,
                    evidence = listOf(
                        EvidenceItem(
                            source = EvidenceSource.ICMP_SPOOFING,
                            detected = true,
                            confidence = EvidenceConfidence.MEDIUM,
                            description = "ICMP looked suspicious",
                        ),
                    ),
                )
            },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val disabledResult = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = false,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertEquals(0, icmpCalls)
        assertFalse(disabledResult.icmpSpoofing.needsReview)

        val enabledResult = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertEquals(1, icmpCalls)
        assertTrue(enabledResult.icmpSpoofing.needsReview)
        assertEquals(Verdict.NEEDS_REVIEW, enabledResult.verdict)
    }

    @Test
    fun `disabled network checks do not downgrade strong local verdict`() = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> error("GeoIP should not run when network checks are disabled") },
            ipComparisonCheck = { _, _, _ -> error("IP comparison should not run when network checks are disabled") },
            directCheck = { _, _, _, _ ->
                category(
                    name = "direct",
                    evidence = listOf(
                        EvidenceItem(
                            source = EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
                            detected = true,
                            confidence = EvidenceConfidence.HIGH,
                            description = "Active network exposes VPN transport",
                        ),
                    ),
                )
            },
            indirectCheck = { _, networkRequestsEnabled, _, _, _, _ ->
                assertFalse(networkRequestsEnabled)
                category(
                    name = "indirect",
                    evidence = listOf(
                        EvidenceItem(
                            source = EvidenceSource.ACTIVE_VPN,
                            detected = true,
                            confidence = EvidenceConfidence.MEDIUM,
                            description = "Active VPN package present",
                        ),
                    ),
                )
            },
            locationCheck = { _, _, _, _ -> category("location") },
            nativeCheck = { _ -> category("native") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = false,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertEquals(Verdict.DETECTED, result.verdict)
    }

    @Test
    fun `direct checker failure promotes final verdict to needs review`() = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            directCheck = { _, _, _, _ -> throw java.io.IOException("direct failed") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            nativeCheck = { _ -> category("native") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertTrue(result.directSigns.needsReview)
        assertTrue(result.directSigns.hasError)
        assertEquals(Verdict.NEEDS_REVIEW, result.verdict)
    }

    @Test
    fun `indirect checker failure promotes final verdict to needs review`() = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> throw java.io.IOException("indirect failed") },
            locationCheck = { _, _, _, _ -> category("location") },
            nativeCheck = { _ -> category("native") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertTrue(result.indirectSigns.needsReview)
        assertTrue(result.indirectSigns.hasError)
        assertEquals(Verdict.NEEDS_REVIEW, result.verdict)
    }

    @Test
    fun `run keeps category fallback errors visible`() = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            icmpSpoofingCheck = { _, _, _ -> throw java.io.IOException("icmp failed") },
            rttTriangulationCheck = { _, _, _, _ -> throw java.io.IOException("rtt failed") },
            directCheck = { _, _, _, _ -> throw java.io.IOException("direct failed") },
            indirectCheck = { _, _, _, _, _, _ -> throw java.io.IOException("indirect failed") },
            locationCheck = { _, _, _, _ -> throw java.io.IOException("location failed") },
            nativeCheck = { _ -> throw java.io.IOException("native failed") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                rttTriangulationEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertTrue(result.icmpSpoofing.hasError)
        assertTrue(result.rttTriangulation.hasError)
        assertTrue(result.directSigns.hasError)
        assertTrue(result.indirectSigns.hasError)
        assertTrue(result.locationSignals.hasError)
        assertTrue(result.nativeSigns.hasError)
    }

    @Test
    fun `shared underlying probe reaches direct and bypass checks`() = runBlocking {
        val sharedProbe = UnderlyingNetworkProber.ProbeResult(
            vpnActive = true,
            underlyingReachable = false,
            ruTarget = PerTargetProbe(targetHost = "", targetGroup = TargetGroup.RU, vpnIp = "198.51.100.10"),
            vpnError = "EPERM",
            activeNetworkIsVpn = true,
        )
        var probeCalls = 0
        var directProbeResult: UnderlyingNetworkProber.ProbeResult? = null
        var bypassProbeResult: UnderlyingNetworkProber.ProbeResult? = null

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            underlyingProbe = { _, _, _, _, _, _, _ ->
                probeCalls += 1
                sharedProbe
            },
            directCheck = { _, tunActiveProbeResult, _, _ ->
                directProbeResult = tunActiveProbeResult
                category("direct")
            },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, underlyingProbeDeferred, _ ->
                bypassProbeResult = underlyingProbeDeferred?.await()
                BypassResult(
                    proxyEndpoint = null,
                    directIp = null,
                    proxyIp = null,
                    xrayApiScanResult = null,
                    findings = emptyList(),
                    detected = false,
                )
            },
        )

        VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = true,
                networkRequestsEnabled = false,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertEquals(1, probeCalls)
        assertSame(sharedProbe, directProbeResult)
        assertSame(sharedProbe, bypassProbeResult)
    }

    @Test
    fun `indirect check runs off the caller thread`() = runBlocking {
        val callerThread = Thread.currentThread()
        var indirectThread: Thread? = null

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ ->
                indirectThread = Thread.currentThread()
                category("indirect")
            },
            locationCheck = { _, _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                BypassResult(
                    proxyEndpoint = null,
                    directIp = null,
                    proxyIp = null,
                    xrayApiScanResult = null,
                    findings = emptyList(),
                    detected = false,
                )
            },
        )

        VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = true,
                networkRequestsEnabled = false,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertTrue(indirectThread != null)
        assertTrue(indirectThread !== callerThread)
    }

    @Test
    fun `cdn pulling runs only when enabled and emits update`() = runBlocking {
        val updates = mutableListOf<CheckUpdate>()
        var cdnCalls = 0

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            cdnPullingCheck = { _, _, _ ->
                cdnCalls += 1
                CdnPullingResult(
                    detected = true,
                    summary = "All CDN targets exposed 203.0.113.64",
                    responses = listOf(
                        CdnPullingResponse(
                            targetLabel = "rutracker.org",
                            url = "https://rutracker.org/cdn-cgi/trace",
                            ip = "203.0.113.64",
                            importantFields = linkedMapOf("IP" to "203.0.113.64", "LOC" to "FI"),
                            rawBody = "ip=203.0.113.64\nloc=FI",
                        ),
                    ),
                )
            },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                cdnPullingEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        ) { update ->
            updates += update
        }

        assertEquals(1, cdnCalls)
        assertTrue(result.cdnPulling.detected)
        assertTrue(updates.any { it is CheckUpdate.CdnPullingReady })
    }

    @Test
    fun `home routed roaming relaxes final cdn and icmp categories`() = runBlocking {
        val rawCdn = CdnPullingResult(
            detected = true,
            needsReview = true,
            summary = "CDN targets exposed foreign IP",
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "meduza.io",
                    url = "https://meduza.io/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    ipv4 = "203.0.113.64",
                ),
            ),
            findings = listOf(Finding("meduza.io: IP: 203.0.113.64", detected = true, needsReview = true)),
        )
        val rawIcmp = category(
            name = "icmp",
            needsReview = true,
            evidence = listOf(
                EvidenceItem(
                    source = EvidenceSource.ICMP_SPOOFING,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Blocked target replied",
                ),
            ),
        )

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            cdnPullingCheck = { _, _, _ -> rawCdn },
            icmpSpoofingCheck = { _, _, _ -> rawIcmp },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ ->
                CategoryResult(
                    name = "location",
                    detected = false,
                    findings = listOf(Finding("network_mcc_ru:true")),
                    locationFacts = LocationSignalsFacts(
                        networkMcc = "250",
                        networkIsRussia = true,
                        homeSimMcc = "208",
                        homeSimCountryIso = "FR",
                        homeRoutedRoaming = true,
                    ),
                )
            },
            nativeCheck = { _ -> category("native") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                cdnPullingEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertFalse(result.cdnPulling.detected)
        assertFalse(result.cdnPulling.needsReview)
        assertTrue(result.cdnPulling.findings.none { it.detected || it.needsReview })
        assertFalse(result.icmpSpoofing.detected)
        assertFalse(result.icmpSpoofing.needsReview)
        assertTrue(result.icmpSpoofing.evidence.none { it.detected })
    }

    @Test
    fun `cdn pulling stays disabled when toggle is off`() = runBlocking {
        val updates = mutableListOf<CheckUpdate>()
        var cdnCalls = 0

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            cdnPullingCheck = { _, _, _ ->
                cdnCalls += 1
                error("CDN pulling should not run when disabled")
            },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                cdnPullingEnabled = false,
                resolverConfig = DnsResolverConfig.system(),
            ),
        ) { update ->
            updates += update
        }

        assertEquals(0, cdnCalls)
        assertEquals(CdnPullingResult.empty(), result.cdnPulling)
        assertTrue(updates.none { it is CheckUpdate.CdnPullingReady })
    }

    @Test
    fun `cancelled execution does not emit late updates`() = runBlocking {
        val started = CountDownLatch(6)
        val release = CountDownLatch(1)
        val updates = mutableListOf<CheckUpdate>()
        val executionContext = ScanExecutionContext(scanId = 42L)

        suspend fun awaitRelease() {
            started.countDown()
            withContext(Dispatchers.IO) {
                assertTrue(release.await(2, TimeUnit.SECONDS))
            }
        }

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ ->
                awaitRelease()
                category("geo")
            },
            ipComparisonCheck = { _, _, _ ->
                awaitRelease()
                emptyIpComparison()
            },
            directCheck = { _, _, _, _ ->
                awaitRelease()
                category("direct")
            },
            indirectCheck = { _, _, _, _, _, _ ->
                awaitRelease()
                category("indirect")
            },
            locationCheck = { _, _, _, _ ->
                awaitRelease()
                category("location")
            },
            nativeCheck = { _ ->
                awaitRelease()
                category("native")
            },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val worker = async {
            runCatching {
                VpnCheckRunner.run(
                    context = context,
                    settings = CheckSettings(
                        splitTunnelEnabled = false,
                        networkRequestsEnabled = true,
                        resolverConfig = DnsResolverConfig.system(),
                    ),
                    executionContext = executionContext,
                ) { update ->
                    updates += update
                }
            }.exceptionOrNull()
        }

        assertTrue(withContext(Dispatchers.IO) { started.await(2, TimeUnit.SECONDS) })
        executionContext.cancellationSignal.cancel()
        release.countDown()

        val error = worker.await()
        assertTrue(error is CancellationException)
        assertTrue(updates.isEmpty())
    }

    @Test
    fun `run survives geoIpCheck throwing and produces partial result`() = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> throw java.io.IOException("boom") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            icmpSpoofingCheck = { _, _, _ -> category("icmp") },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            nativeCheck = { _ -> category("native") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )
        try {
            val result = VpnCheckRunner.run(
                context,
                settings = CheckSettings(
                    splitTunnelEnabled = false,
                    networkRequestsEnabled = true,
                    resolverConfig = DnsResolverConfig.system(),
                ),
            )
            assertNotNull(result)
            assertTrue(result.geoIp.hasError)
        } finally {
            VpnCheckRunner.dependenciesOverride = null
        }
    }

    @Test
    fun `run marks ip comparison fallback as error`() = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> throw java.io.IOException("ip comparison failed") },
            icmpSpoofingCheck = { _, _, _ -> category("icmp") },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            nativeCheck = { _ -> category("native") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertTrue(result.ipComparison.hasError)
        assertTrue(result.ipComparison.needsReview)
        assertEquals("ip comparison failed", result.ipComparison.summary)
    }

    @Test
    fun `run marks cdn pulling fallback as error`() = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> category("geo") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            cdnPullingCheck = { _, _, _ -> throw java.io.IOException("cdn failed") },
            icmpSpoofingCheck = { _, _, _ -> category("icmp") },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            nativeCheck = { _ -> category("native") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )

        val result = VpnCheckRunner.run(
            context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = true,
                cdnPullingEnabled = true,
                resolverConfig = DnsResolverConfig.system(),
            ),
        )

        assertTrue(result.cdnPulling.hasError)
        assertTrue(result.cdnPulling.needsReview)
        assertTrue(result.cdnPulling.findings.any { it.isError })
        assertEquals("cdn failed", result.cdnPulling.summary)
    }

    @Test
    fun `run propagates cancellation from geoIpCheck`(): Unit = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _, _ -> throw kotlinx.coroutines.CancellationException("stop") },
            ipComparisonCheck = { _, _, _ -> emptyIpComparison() },
            icmpSpoofingCheck = { _, _, _ -> category("icmp") },
            directCheck = { _, _, _, _ -> category("direct") },
            indirectCheck = { _, _, _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _, _ -> category("location") },
            nativeCheck = { _ -> category("native") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ ->
                error("BypassChecker should not run when split tunnel is disabled")
            },
        )
        try {
            var threw = false
            try {
                VpnCheckRunner.run(
                    context,
                    settings = CheckSettings(
                        splitTunnelEnabled = false,
                        networkRequestsEnabled = true,
                        resolverConfig = DnsResolverConfig.system(),
                    ),
                )
            } catch (e: kotlinx.coroutines.CancellationException) {
                threw = true
            }
            assertTrue("expected CancellationException", threw)
        } finally {
            VpnCheckRunner.dependenciesOverride = null
        }
    }

    @Test
    fun `run forwards ipConsensus into check result`() = runBlocking {
        // default dependencies + empty settings should still produce an ipConsensus (even if empty)
        val result = VpnCheckRunner.run(
            context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = false,
            ),
        )
        assertNotNull(result.ipConsensus)
    }

    private fun category(
        name: String,
        needsReview: Boolean = false,
        evidence: List<EvidenceItem> = emptyList(),
        callTransportLeaks: List<CallTransportLeakResult> = emptyList(),
    ): CategoryResult = CategoryResult(
        name = name,
        detected = evidence.any { it.detected },
        findings = emptyList(),
        needsReview = needsReview,
        evidence = evidence,
        callTransportLeaks = callTransportLeaks,
    )

    private fun emptyIpComparison(): IpComparisonResult = IpComparisonResult(
        detected = false,
        summary = "",
        ruGroup = IpCheckerGroupResult(
            title = context.getString(R.string.checker_ip_comp_ru_checkers),
            detected = false,
            statusLabel = "",
            summary = "",
            responses = emptyList(),
        ),
        nonRuGroup = IpCheckerGroupResult(
            title = context.getString(R.string.checker_ip_comp_non_ru_checkers),
            detected = false,
            statusLabel = "",
            summary = "",
            responses = emptyList(),
        ),
    )
}
