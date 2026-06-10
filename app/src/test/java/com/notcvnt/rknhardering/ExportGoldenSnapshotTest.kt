package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.export.CheckResultJsonExportFormatter
import com.notcvnt.rknhardering.export.CheckResultMarkdownExportFormatter
import com.notcvnt.rknhardering.export.createCompletedExportSnapshot
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.util.Locale
import java.util.TimeZone

/**
 * Pins the exact output of all three CheckResult formatters against golden
 * files. The three formatters traverse the model independently and diverge
 * on purpose (separators, masking policy, flag emission); these snapshots
 * are the regression net that lets the rest of the codebase be refactored
 * without silently changing any export byte.
 *
 * To update goldens after an INTENTIONAL format change: run the test, then
 * copy the freshly generated files from app/build/export-golden-actual/
 * over app/src/test/resources/export/golden/ and review the diff.
 */
@RunWith(RobolectricTestRunner::class)
class ExportGoldenSnapshotTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    private lateinit var originalTimeZone: TimeZone
    private lateinit var originalLocale: Locale

    @Before
    fun pinEnvironment() {
        originalTimeZone = TimeZone.getDefault()
        originalLocale = Locale.getDefault()
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
        Locale.setDefault(Locale.US)
    }

    @After
    fun restoreEnvironment() {
        TimeZone.setDefault(originalTimeZone)
        Locale.setDefault(originalLocale)
    }

    @Test
    fun `markdown export matches golden`() {
        assertMatchesGolden("full-scan.md", renderMarkdown(privacyMode = false))
    }

    @Test
    fun `markdown export with privacy mode matches golden`() {
        assertMatchesGolden("full-scan-privacy.md", renderMarkdown(privacyMode = true))
    }

    @Test
    fun `json export matches golden`() {
        assertMatchesGolden("full-scan.json", renderJson(privacyMode = false))
    }

    @Test
    fun `json export with privacy mode matches golden`() {
        assertMatchesGolden("full-scan-privacy.json", renderJson(privacyMode = true))
    }

    @Test
    fun `debug diagnostics match golden`() {
        assertMatchesGolden("full-scan-debug.txt", renderDebug(privacyMode = false))
    }

    @Test
    fun `debug diagnostics with privacy mode match golden`() {
        assertMatchesGolden("full-scan-debug-privacy.txt", renderDebug(privacyMode = true))
    }

    private fun renderMarkdown(privacyMode: Boolean): String =
        CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = privacyMode,
                finishedAtMillis = FIXED_TIMESTAMP_MS,
            ),
            appVersionName = GOLDEN_APP_VERSION,
            buildType = GOLDEN_BUILD_TYPE,
        )

    private fun renderJson(privacyMode: Boolean): String =
        CheckResultJsonExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = privacyMode,
                finishedAtMillis = FIXED_TIMESTAMP_MS,
            ),
            appVersionName = GOLDEN_APP_VERSION,
            buildType = GOLDEN_BUILD_TYPE,
        )

    private fun renderDebug(privacyMode: Boolean): String =
        DebugDiagnosticsFormatter.format(
            result = exportRichCheckResult(),
            settings = CheckSettings(),
            privacyMode = privacyMode,
            timestampMillis = FIXED_TIMESTAMP_MS,
            appVersionName = GOLDEN_APP_VERSION,
            buildType = GOLDEN_BUILD_TYPE,
        )

    private fun assertMatchesGolden(name: String, rendered: String) {
        val actual = rendered.normalizeEol()
        dumpActual(name, actual)
        val stream = javaClass.classLoader?.getResourceAsStream("export/golden/$name")
            ?: fail(
                "Golden resource export/golden/$name is missing. The actual output was written to " +
                    "app/build/export-golden-actual/$name; review it and copy it into " +
                    "app/src/test/resources/export/golden/.",
            ).let { return }
        val expected = stream.use { it.readBytes().toString(Charsets.UTF_8) }.normalizeEol()
        assertEquals("Formatter output diverged from golden export/golden/$name", expected, actual)
    }

    private fun dumpActual(name: String, content: String) {
        val dir = File(System.getProperty("user.dir"), "build/export-golden-actual")
        dir.mkdirs()
        File(dir, name).writeText(content)
    }

    // Goldens are compared modulo line endings so git checkout EOL settings
    // cannot break them.
    private fun String.normalizeEol(): String = replace("\r\n", "\n")

    private companion object {
        // 2023-11-14T22:13:20Z, fixed so goldens are stable.
        const val FIXED_TIMESTAMP_MS = 1_700_000_000_000L
        const val GOLDEN_APP_VERSION = "0.0-golden"
        const val GOLDEN_BUILD_TYPE = "golden"
    }
}
