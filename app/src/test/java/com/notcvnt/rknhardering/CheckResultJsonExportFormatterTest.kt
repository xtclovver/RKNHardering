package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
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
        assertTrue(results.has("icmpSpoofing"))
        assertTrue(results.has("bypass"))
        assertTrue(results.getJSONObject("ipComparison").getJSONObject("ruGroup").has("responses"))
        val outbound = results
            .getJSONObject("bypass")
            .getJSONObject("xrayApiScanResult")
            .getJSONArray("outbounds")
            .getJSONObject(0)
        assertTrue(outbound.getBoolean("uuidPresent"))
        assertTrue(outbound.getBoolean("publicKeyPresent"))
        assertFalse(outbound.has("uuid"))
        assertFalse(outbound.has("publicKey"))
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
        assertTrue(ipConsensus.has("crossChannelMismatch"))
        assertTrue(ipConsensus.has("warpLikeIndicator"))
        assertTrue(ipConsensus.has("probeTargetDivergence"))
        assertTrue(ipConsensus.has("probeTargetDirectDivergence"))
        assertTrue(ipConsensus.has("geoCountryMismatch"))
        assertTrue(ipConsensus.has("channelConflict"))
        assertTrue(ipConsensus.has("foreignIps"))
        assertTrue(ipConsensus.has("needsReview"))
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
}
