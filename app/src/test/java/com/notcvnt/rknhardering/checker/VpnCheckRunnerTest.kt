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
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.Verdict
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CancellationException
import org.junit.After
import org.junit.Assert.assertEquals
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
            geoIpCheck = { _, _ -> category("geo") },
            ipComparisonCheck = { _, _ -> emptyIpComparison() },
            directCheck = { _, _ -> category("direct") },
            indirectCheck = { _, networkRequestsEnabled, callTransportProbeEnabled, _ ->
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
            locationCheck = { _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _ ->
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
        assertEquals(Verdict.NEEDS_REVIEW, result.verdict)
    }

    @Test
    fun `bypass runner forwards separate proxy and xray scan toggles`() = runBlocking {
        var capturedProxyScanEnabled: Boolean? = null
        var capturedXrayApiScanEnabled: Boolean? = null

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _ -> category("geo") },
            ipComparisonCheck = { _, _ -> emptyIpComparison() },
            directCheck = { _, _ -> category("direct") },
            indirectCheck = { _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _ -> category("location") },
            bypassCheck = { _, _, splitTunnelEnabled, proxyScanEnabled, xrayApiScanEnabled, _, _, _, _, _ ->
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
    fun `shared underlying probe reaches direct and bypass checks`() = runBlocking {
        val sharedProbe = UnderlyingNetworkProber.ProbeResult(
            vpnActive = true,
            underlyingReachable = false,
            vpnIp = "198.51.100.10",
            vpnError = "EPERM",
            activeNetworkIsVpn = true,
        )
        var probeCalls = 0
        var directProbeResult: UnderlyingNetworkProber.ProbeResult? = null
        var bypassProbeResult: UnderlyingNetworkProber.ProbeResult? = null

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _ -> category("geo") },
            ipComparisonCheck = { _, _ -> emptyIpComparison() },
            underlyingProbe = { _, _, _, _ ->
                probeCalls += 1
                sharedProbe
            },
            directCheck = { _, tunActiveProbeResult ->
                directProbeResult = tunActiveProbeResult
                category("direct")
            },
            indirectCheck = { _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, underlyingProbeDeferred, _ ->
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
            geoIpCheck = { _, _ -> category("geo") },
            ipComparisonCheck = { _, _ -> emptyIpComparison() },
            directCheck = { _, _ -> category("direct") },
            indirectCheck = { _, _, _, _ ->
                indirectThread = Thread.currentThread()
                category("indirect")
            },
            locationCheck = { _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _ ->
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
            geoIpCheck = { _, _ -> category("geo") },
            ipComparisonCheck = { _, _ -> emptyIpComparison() },
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
            directCheck = { _, _ -> category("direct") },
            indirectCheck = { _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _ ->
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
    fun `cdn pulling stays disabled when toggle is off`() = runBlocking {
        val updates = mutableListOf<CheckUpdate>()
        var cdnCalls = 0

        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            geoIpCheck = { _, _ -> category("geo") },
            ipComparisonCheck = { _, _ -> emptyIpComparison() },
            cdnPullingCheck = { _, _, _ ->
                cdnCalls += 1
                error("CDN pulling should not run when disabled")
            },
            directCheck = { _, _ -> category("direct") },
            indirectCheck = { _, _, _, _ -> category("indirect") },
            locationCheck = { _, _, _ -> category("location") },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _ ->
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
        val started = CountDownLatch(5)
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
            geoIpCheck = { _, _ ->
                awaitRelease()
                category("geo")
            },
            ipComparisonCheck = { _, _ ->
                awaitRelease()
                emptyIpComparison()
            },
            directCheck = { _, _ ->
                awaitRelease()
                category("direct")
            },
            indirectCheck = { _, _, _, _ ->
                awaitRelease()
                category("indirect")
            },
            locationCheck = { _, _, _ ->
                awaitRelease()
                category("location")
            },
            bypassCheck = { _, _, _, _, _, _, _, _, _, _ ->
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
