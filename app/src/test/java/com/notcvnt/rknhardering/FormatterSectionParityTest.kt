package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.export.CheckResultJsonExportFormatter
import com.notcvnt.rknhardering.export.CheckResultMarkdownExportFormatter
import com.notcvnt.rknhardering.export.createCompletedExportSnapshot
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Cheap drift insurance for the three independent CheckResult traversals:
 * when a new section is added to the model, it must show up in every
 * formatter, not just the one the author remembered to extend.
 */
@RunWith(RobolectricTestRunner::class)
class FormatterSectionParityTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private val richResult = exportRichCheckResult()

    @Test
    fun `markdown emits every populated section`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(richResult, privacyMode = false, finishedAtMillis = 0L),
            appVersionName = "1.0",
            buildType = "debug",
        )

        listOf(
            "## Verdict",
            "## Section Summary",
            "## GeoIP",
            "## IP comparison",
            "## CDN pulling",
            "## Direct signs",
            "## Indirect signs",
            "## Native signs",
            "## ICMP spoofing",
            "## RTT triangulation",
            "## Location signals",
            "## TUN probe diagnostics",
            "## Footer",
        ).forEach { header ->
            assertTrue("markdown export lost section '$header'", markdown.contains(header))
        }
        // Bypass and IP-channels headers are localized/hardcoded differently;
        // assert by stable content markers instead.
        assertTrue(markdown.contains(context.getString(R.string.settings_split_tunnel)))
    }

    @Test
    fun `json emits every populated section`() {
        val json = CheckResultJsonExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(richResult, privacyMode = false, finishedAtMillis = 0L),
            appVersionName = "1.0",
            buildType = "debug",
        )

        listOf(
            "\"meta\"",
            "\"verdict\"",
            "\"geoIp\"",
            "\"ipComparison\"",
            "\"cdnPulling\"",
            "\"directSigns\"",
            "\"indirectSigns\"",
            "\"nativeSigns\"",
            "\"icmpSpoofing\"",
            "\"rttTriangulation\"",
            "\"locationSignals\"",
            "\"bypass\"",
            "\"ipConsensus\"",
            "\"tunProbeDiagnostics\"",
        ).forEach { key ->
            assertTrue("json export lost key $key", json.contains(key))
        }
    }

    @Test
    fun `debug diagnostics emit every populated section`() {
        val debug = DebugDiagnosticsFormatter.format(
            result = richResult,
            settings = CheckSettings(),
            privacyMode = false,
            timestampMillis = 0L,
            appVersionName = "1.0",
            buildType = "debug",
        )

        listOf(
            "[geoIp]",
            "[ipComparison]",
            "[cdnPulling]",
            "[directSigns]",
            "[indirectSigns]",
            "[icmpSpoofing]",
            "[rttTriangulation]",
            "[locationSignals]",
            "[bypass]",
            "[nativeSigns]",
            "[operatorWhitelist]",
            "[tunProbe]",
        ).forEach { marker ->
            assertTrue("debug diagnostics lost section $marker", debug.contains(marker))
        }
    }
}
