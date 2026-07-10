package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.export.CheckResultJsonExportFormatter
import com.notcvnt.rknhardering.export.CompletedExportSnapshot
import com.notcvnt.rknhardering.export.createCompletedExportSnapshot
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.probe.OperatorWhitelistProbeResult
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CheckResultJsonExportFormatterTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `json export contains meta verdict and results structure`() {
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = exportRichCheckResult(),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        assertEquals(1, json.getJSONObject("meta").getInt("formatVersion"))
        assertEquals("DETECTED", json.getJSONObject("verdict").getString("value"))
        val results = json.getJSONObject("results")
        assertTrue(results.has("geoIp"))
        assertTrue(results.has("ipComparison"))
        assertTrue(results.has("cdnPulling"))
        assertTrue(results.has("nativeSigns"))
        assertTrue(results.has("icmpSpoofing"))
        assertTrue(results.has("rttTriangulation"))
        assertTrue(results.has("bypass"))
        assertTrue(results.getJSONObject("ipComparison").getJSONObject("ruGroup").has("responses"))
        val bypass = results.getJSONObject("bypass")
        assertTrue(bypass.getJSONObject("proxyEndpoint").getBoolean("authRequired"))
        val xray = bypass
            .getJSONObject("xrayApiScanResult")
        assertTrue(xray.getBoolean("handlerAvailable"))
        assertEquals(2, xray.getJSONObject("stats").getInt("statCount"))
        val outbound = xray
            .getJSONArray("outbounds")
            .getJSONObject(0)
        assertTrue(outbound.getBoolean("uuidPresent"))
        assertTrue(outbound.getBoolean("publicKeyPresent"))
        assertFalse(outbound.has("uuid"))
        assertFalse(outbound.has("publicKey"))
    }

    @Test
    fun `json export includes deep native detector findings and evidence`() {
        val result = exportRichCheckResult().copy(
            nativeSigns = CategoryResult(
                name = "Native signs",
                detected = true,
                findings = listOf(
                    Finding(
                        description = "backpressure: 50000 packets",
                        isInformational = true,
                        source = EvidenceSource.NATIVE_ROUTE,
                        confidence = EvidenceConfidence.LOW,
                    ),
                    Finding(
                        description = "bindtodevice_leak: tun0",
                        detected = true,
                        source = EvidenceSource.NATIVE_SOCKET,
                        confidence = EvidenceConfidence.HIGH,
                    ),
                ),
                evidence = listOf(
                    EvidenceItem(
                        source = EvidenceSource.NATIVE_SOCKET,
                        detected = true,
                        confidence = EvidenceConfidence.HIGH,
                        description = "bindtodevice_leak: tun0",
                    ),
                ),
            ),
        )

        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = result,
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )
        val nativeSigns = json.getJSONObject("results").getJSONObject("nativeSigns")
        val findings = nativeSigns.getJSONArray("findings")
        val evidence = nativeSigns.getJSONArray("evidence")

        assertEquals("backpressure: 50000 packets", findings.getJSONObject(0).getString("description"))
        assertTrue(findings.getJSONObject(0).getBoolean("isInformational"))
        assertEquals("bindtodevice_leak: tun0", findings.getJSONObject(1).getString("description"))
        assertEquals("NATIVE_SOCKET", evidence.getJSONObject(0).getString("source"))
        assertEquals("bindtodevice_leak: tun0", evidence.getJSONObject(0).getString("description"))
    }

    @Test
    fun `json export marks ip comparison and bypass errors`() {
        val base = exportEmptyCheckResult()
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = base.copy(
                        ipComparison = base.ipComparison.copy(
                            needsReview = true,
                            hasError = true,
                            summary = "ip comparison failed",
                        ),
                        bypassResult = base.bypassResult.copy(
                            needsReview = true,
                            findings = listOf(Finding("bypass failed", isError = true)),
                        ),
                    ),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        val results = json.getJSONObject("results")
        val ipComparison = results.getJSONObject("ipComparison")
        val bypass = results.getJSONObject("bypass")

        assertTrue(ipComparison.getBoolean("hasError"))
        assertEquals("[ERROR]", ipComparison.getString("status"))
        assertTrue(bypass.getBoolean("hasError"))
        assertEquals("[ERROR]", bypass.getString("status"))
    }

    @Test
    fun `json export masks ips in strings and structured fields`() {
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = exportRichCheckResult(),
                    privacyMode = true,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        val results = json.getJSONObject("results")
        val directIp = results.getJSONObject("bypass").getString("directIp")
        val rawBody = results
            .getJSONObject("cdnPulling")
            .getJSONArray("responses")
            .getJSONObject(0)
            .getString("rawBody")

        assertEquals("198.51.*.*", directIp)
        assertTrue(rawBody.contains("203.0.*.*"))
        assertFalse(rawBody.contains("203.0.113.64"))
        assertFalse(results.toString().contains("198.51.100.7"))
        assertFalse(json.toString().contains("203.0.113.64"))
        assertFalse(json.toString().contains("198.51.100.7"))
        assertFalse(json.toString().contains("2001:db8::64"))
    }

    @Test
    fun `json export includes ipConsensus with observed IPs across channels`() {
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = exportRichCheckResult(),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        val ipConsensus = json.getJSONObject("ipConsensus")
        val observedIps = ipConsensus.getJSONArray("observedIps")
        assertEquals(2, observedIps.length())
        assertTrue(ipConsensus.has("observedIps"))
        assertTrue(ipConsensus.has("unparsedIps"))
        assertTrue(ipConsensus.has("channelIps"))
        assertTrue(ipConsensus.has("crossChannelMismatch"))
        assertTrue(ipConsensus.has("dualStackObserved"))
        assertTrue(ipConsensus.has("warpLikeIndicator"))
        assertTrue(ipConsensus.has("probeTargetDivergence"))
        assertTrue(ipConsensus.has("probeTargetDirectDivergence"))
        assertTrue(ipConsensus.has("geoCountryMismatch"))
        assertTrue(ipConsensus.has("sameAsnAcrossChannels"))
        assertTrue(ipConsensus.has("channelConflict"))
        assertTrue(ipConsensus.has("foreignIps"))
        assertTrue(ipConsensus.has("needsReview"))
        assertEquals(1, ipConsensus.getJSONArray("unparsedIps").length())
        assertEquals("198.51.100.7", ipConsensus.getJSONObject("channelIps").getJSONArray("DIRECT").getString(0))
        assertTrue(ipConsensus.getBoolean("dualStackObserved"))
        assertTrue(ipConsensus.getBoolean("sameAsnAcrossChannels"))
        assertEquals("DIRECT", observedIps.getJSONObject(0).getString("channel"))
        assertEquals("V4", observedIps.getJSONObject(0).getString("family"))
        assertEquals("VPN", observedIps.getJSONObject(1).getString("channel"))
    }

    @Test
    fun `json export handles empty ipConsensus`() {
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = exportEmptyCheckResult(),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        val ipConsensus = json.getJSONObject("ipConsensus")
        assertEquals(0, ipConsensus.getJSONArray("observedIps").length())
        assertFalse(ipConsensus.getBoolean("crossChannelMismatch"))
        assertFalse(ipConsensus.getBoolean("needsReview"))
    }

    @Test
    fun `json export includes icmp spoofing category separately`() {
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = exportRichCheckResult(),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        val icmp = json.getJSONObject("results").getJSONObject("icmpSpoofing")
        assertTrue(icmp.getBoolean("needsReview"))
        assertEquals("ICMP spoofing", icmp.getString("name"))
    }

    @Test
    fun `json export includes added report parameters`() {
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = exportRichCheckResult(),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        val results = json.getJSONObject("results")
        val geoFacts = results.getJSONObject("geoIp").getJSONObject("geoFacts")
        assertEquals("203.0.113.64", geoFacts.getString("ip"))
        assertTrue(geoFacts.getBoolean("outsideRu"))
        assertTrue(geoFacts.getBoolean("proxyDb"))

        val cdnResponse = results.getJSONObject("cdnPulling").getJSONArray("responses").getJSONObject(0)
        assertEquals("203.0.113.64", cdnResponse.getString("ipv4"))
        assertEquals("2001:db8::64", cdnResponse.getString("ipv6"))
        assertFalse(cdnResponse.getBoolean("ipv4Unavailable"))
        assertTrue(cdnResponse.getString("ipv4Error").contains("198.51.100.7"))

        val stunGroup = results
            .getJSONObject("indirectSigns")
            .getJSONArray("stunProbeGroups")
            .getJSONObject(0)
        assertEquals("GLOBAL", stunGroup.getString("scope"))
        assertEquals(1, stunGroup.getInt("respondedCount"))
        assertEquals("203.0.113.64", stunGroup.getJSONArray("results").getJSONObject(0).getString("mappedIpv4"))

        val nativeSigns = results.getJSONObject("nativeSigns")
        assertEquals("Native signs", nativeSigns.getString("name"))
        assertTrue(nativeSigns.getBoolean("detected"))
        assertTrue(results.getJSONObject("rttTriangulation").getBoolean("needsReview"))

        val tun = json.getJSONObject("tunProbeDiagnostics")
        assertTrue(tun.getBoolean("enabled"))
        assertEquals("CURL_COMPATIBLE", tun.getString("modeOverride"))
        assertEquals("203.0.113.64", tun.getJSONObject("vpnPath").getString("selectedIp"))
    }

    @Test
    fun `json export includes vpn app technical metadata`() {
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = exportRichCheckResult(),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        val metadata = json
            .getJSONObject("results")
            .getJSONObject("directSigns")
            .getJSONArray("matchedApps")
            .getJSONObject(0)
            .getJSONObject("technicalMetadata")

        assertEquals("V2RayNG", metadata.getString("appType"))
        assertEquals("Xray/V2Ray", metadata.getString("coreType"))
        assertEquals("1.2.3", metadata.getString("versionName"))
        assertEquals("ExampleService", metadata.getJSONArray("serviceNames").getString(0))
    }

    @Test
    fun `json export includes operator_whitelist section when probe present with whitelistDetected true`() {
        val base = exportEmptyCheckResult()
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = base.copy(
                        operatorWhitelistProbe = OperatorWhitelistProbeResult(
                            whitelistDetected = true,
                            googleReachable = false,
                            appleReachable = false,
                            firefoxReachable = false,
                            russianControlReachable = true,
                            errors = mapOf("google" to "timeout", "apple" to "refused"),
                            durationMs = 4521L,
                        ),
                    ),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        assertTrue(json.has("operator_whitelist"))
        val wl = json.getJSONObject("operator_whitelist")
        assertTrue(wl.getBoolean("detected"))
        assertFalse(wl.getBoolean("google_reachable"))
        assertFalse(wl.getBoolean("apple_reachable"))
        assertFalse(wl.getBoolean("firefox_reachable"))
        assertTrue(wl.getBoolean("russian_control_reachable"))
        assertEquals(4521L, wl.getLong("duration_ms"))
        val errors = wl.getJSONObject("errors")
        assertEquals("timeout", errors.getString("google"))
        assertEquals("refused", errors.getString("apple"))
    }

    @Test
    fun `json export omits operator_whitelist section when probe is null`() {
        val json = JSONObject(
            CheckResultJsonExportFormatter.format(
                context = context,
                snapshot = createCompletedExportSnapshot(
                    result = exportEmptyCheckResult(),
                    privacyMode = false,
                    finishedAtMillis = 0L,
                ),
                appVersionName = "1.0",
                buildType = "debug",
            ),
        )

        assertFalse(json.has("operator_whitelist"))
    }
}
