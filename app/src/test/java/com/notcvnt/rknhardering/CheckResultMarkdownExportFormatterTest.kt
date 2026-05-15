package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.UnparsedIp
import com.notcvnt.rknhardering.probe.OperatorWhitelistProbeResult
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CheckResultMarkdownExportFormatterTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `markdown export contains ascii summary block and major sections`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("# RKNHardering Scan Report"))
        assertTrue(markdown.contains("```text"))
        assertTrue(markdown.contains("VERDICT      : [DETECTED]"))
        assertTrue(markdown.contains("| Section | Status | Summary |"))
        assertTrue(markdown.contains("## GeoIP"))
        assertTrue(markdown.contains("## ${context.getString(R.string.main_card_ip_comparison)}"))
        assertTrue(markdown.contains("## ${context.getString(R.string.main_card_native_signs)}"))
        assertTrue(markdown.contains("## ${context.getString(R.string.main_card_icmp_spoofing)}"))
        assertTrue(markdown.contains("## ${context.getString(R.string.settings_split_tunnel)}"))
        assertTrue(markdown.contains("## Footer"))
    }

    @Test
    fun `markdown export marks ip comparison and bypass errors`() {
        val base = exportEmptyCheckResult()
        val markdown = CheckResultMarkdownExportFormatter.format(
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
        )

        assertTrue(markdown.contains("| ${context.getString(R.string.main_card_ip_comparison)} | [ERROR] | ip comparison failed |"))
        assertTrue(markdown.contains("| ${context.getString(R.string.settings_split_tunnel)} | [ERROR] | bypass failed |"))
        assertTrue(markdown.contains("## ${context.getString(R.string.main_card_ip_comparison)}"))
        assertTrue(markdown.contains("## ${context.getString(R.string.settings_split_tunnel)}"))
        assertTrue(markdown.contains("- Status: [ERROR]"))
    }

    @Test
    fun `markdown export masks public ips in privacy mode`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = true,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("203.0.*.*"))
        assertTrue(markdown.contains("198.51.*.*"))
        assertFalse(markdown.contains("203.0.113.64"))
        assertFalse(markdown.contains("198.51.100.7"))
        assertFalse(markdown.contains("2001:db8::64"))
    }

    @Test
    fun `markdown export stays readable for empty result`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportEmptyCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("### Findings"))
        assertTrue(markdown.contains("- <none>"))
        assertFalse(markdown.contains("null"))
    }

    @Test
    fun `markdown export includes IP channels section when observed IPs present`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("| DIRECT | RU | 198.51.100.7 | V4 | RU | AS64501 Example Direct |"))
        assertTrue(markdown.contains("| VPN | NON_RU | 203.0.113.64 | V4 | FI | AS64502 Example VPN |"))
    }

    @Test
    fun `markdown export skips IP channels section when empty`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportEmptyCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertFalse(markdown.contains("Unparsed IP inputs:"))
        assertFalse(markdown.contains("Channel IPs:"))
    }

    @Test
    fun `markdown export includes IP consensus raw fields without observed IPs`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportEmptyCheckResult().copy(
                    ipConsensus = IpConsensusResult(
                        unparsedIps = listOf(
                            UnparsedIp(
                                raw = "raw 203.0.113.64",
                                source = "fixture.raw",
                            ),
                        ),
                        needsReview = true,
                    ),
                ),
                privacyMode = true,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("Unparsed IP inputs:"))
        assertTrue(markdown.contains("source=fixture.raw"))
        assertTrue(markdown.contains("raw 203.0.*.*"))
        assertFalse(markdown.contains("203.0.113.64"))
    }

    @Test
    fun `markdown export includes vpn app technical metadata`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("appType=V2RayNG"))
        assertTrue(markdown.contains("coreType=Xray/V2Ray"))
        assertTrue(markdown.contains("goVersion=go1.24.1"))
    }

    @Test
    fun `markdown export includes added report parameters`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("### Geo facts"))
        assertTrue(markdown.contains("outsideRu=true"))
        assertTrue(markdown.contains("- IPv4: 203.0.113.64"))
        assertTrue(markdown.contains("- IPv6: 2001:db8::64"))
        assertTrue(markdown.contains("- IPv4 error: IPv4 retry saw 198.51.100.7"))
        assertTrue(markdown.contains("### STUN probe groups"))
        assertTrue(markdown.contains("mappedIpv4=203.0.113.64"))
        assertTrue(markdown.contains("Native getifaddrs() reports tun0"))
        assertTrue(markdown.contains("RTT target mix needs review"))
        assertTrue(markdown.contains("authRequired=true"))
        assertTrue(markdown.contains("handlerAvailable=true"))
        assertTrue(markdown.contains("statCount=2"))
        assertTrue(markdown.contains("dualStackObserved=true"))
        assertTrue(markdown.contains("sameAsnAcrossChannels=true"))
        assertTrue(markdown.contains("Channel IPs:"))
        assertTrue(markdown.contains("Unparsed IP inputs:"))
        assertTrue(markdown.contains("## TUN probe diagnostics"))
        assertTrue(markdown.contains("- Selected IP: 203.0.113.64"))
    }

    @Test
    fun `markdown export includes operator whitelist section when probe present`() {
        val base = exportEmptyCheckResult()
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = base.copy(
                    operatorWhitelistProbe = OperatorWhitelistProbeResult(
                        whitelistDetected = true,
                        googleReachable = false,
                        appleReachable = false,
                        firefoxReachable = false,
                        russianControlReachable = true,
                        errors = emptyMap(),
                        durationMs = 3000L,
                    ),
                ),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("## Белые списки оператора"))
        assertTrue(markdown.contains("Детектировано: да"))
        assertTrue(markdown.contains("google.com/generate_204: недоступен"))
        assertTrue(markdown.contains("yandex.ru (контроль): доступен"))
        assertTrue(markdown.contains("Длительность: 3000 мс"))
    }

    @Test
    fun `markdown export omits operator whitelist section when probe is null`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportEmptyCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertFalse(markdown.contains("## Белые списки оператора"))
    }
}
