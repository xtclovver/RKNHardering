package com.notcvnt.rknhardering

import android.content.Context
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.button.MaterialButton
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.diagnostics.DiagnosticEntry
import com.notcvnt.rknhardering.diagnostics.DiagnosticSnapshot
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.Verdict
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
class ResultDisplayModeUiTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        AppUiSettings.prefs(context).edit().clear().commit()
    }

    @After
    fun tearDown() {
        CheckViewModel.runScanOverride = null
    }

    @Test
    fun `normal mode keeps existing technical finding presentation`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        invokePrivate<Unit>(activity, "prepareCheckSessionUi", CheckSettings(), false, ResultDisplayMode.NORMAL)
        invokePrivate<Unit>(
            activity,
            "applyScanEvent",
            ScanEvent.Update(CheckUpdate.DirectSignsReady(technicalCategory())),
            false,
        )
        invokePrivate<Unit>(activity, "expandCategory", "dir")

        assertTrue(collectVisibleText(activity.findViewById(R.id.bodyDirect)).contains(TECHNICAL_MARKER))
    }

    @Test
    fun `simple mode keeps enabled cards but hides technical strings`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        invokePrivate<Unit>(activity, "prepareCheckSessionUi", CheckSettings(), false, ResultDisplayMode.SIMPLE)
        invokePrivate<Unit>(
            activity,
            "applyScanEvent",
            ScanEvent.Update(CheckUpdate.DirectSignsReady(technicalCategory())),
            false,
        )
        invokePrivate<Unit>(activity, "expandCategory", "dir")

        assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.cardDirect).visibility)
        val visibleText = collectVisibleText(activity.findViewById(R.id.bodyDirect))
        assertFalse(visibleText.contains(TECHNICAL_MARKER))
        assertTrue(visibleText.contains(activity.getString(R.string.simple_result_checked_label)))
    }

    @Test
    fun `simple mode names the exact ip group mismatch without technical data`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        invokePrivate<Unit>(activity, "prepareCheckSessionUi", CheckSettings(), false, ResultDisplayMode.SIMPLE)
        val rawSummary = "technical summary 87.116.181.251 vs 87.116.162.101"
        val ruGroup = IpCheckerGroupResult(
            title = "RU",
            detected = true,
            statusLabel = "raw enum-like status",
            summary = rawSummary,
            responses = listOf(
                ipResponse("87.116.181.251", IpCheckerScope.RU),
                ipResponse("87.116.162.101", IpCheckerScope.RU),
            ),
        )
        val nonRuGroup = group("non-ru")

        invokePrivate<Unit>(
            activity,
            "applyScanEvent",
            ScanEvent.Update(
                CheckUpdate.IpComparisonReady(
                    IpComparisonResult(
                        detected = false,
                        needsReview = true,
                        summary = rawSummary,
                        ruGroup = ruGroup,
                        nonRuGroup = nonRuGroup,
                    ),
                ),
            ),
            false,
        )
        invokePrivate<Unit>(activity, "expandCategory", "ipc")

        val visibleText = collectVisibleText(activity.findViewById(R.id.bodyIpComparison))
        assertTrue(visibleText.contains(activity.getString(R.string.simple_cause_ip_ru_services_disagree)))
        assertFalse(visibleText.contains(rawSummary))
        assertFalse(visibleText.contains("87.116.181.251"))
        assertFalse(visibleText.contains("87.116.162.101"))
        assertFalse(visibleText.contains(activity.getString(R.string.simple_result_area_public_address)))
    }

    @Test
    fun `advanced mode creates closed lazy technical block and clears it on new scan`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        invokePrivate<Unit>(
            activity,
            "applyScanEvent",
            ScanEvent.Completed(checkResult(snapshot(runTruncated = true)), false, ResultDisplayMode.ADVANCED),
            false,
        )
        invokePrivate<Unit>(activity, "expandCategory", "dir")
        val body = activity.findViewById<ViewGroup>(R.id.bodyDirect)
        val toggle = findMaterialButton(body, activity.getString(R.string.technical_data_title))
        assertNotNull(toggle)
        assertFalse(collectVisibleText(body).contains("current-run payload"))

        toggle!!.performClick()
        assertTrue(collectVisibleText(body).contains(activity.getString(R.string.technical_data_run_truncated)))
        val raw = findTextView(body) { it.text.toString().contains("current-run payload") }
        assertNotNull(raw)
        assertTrue(raw!!.isTextSelectable)
        assertEquals(View.TEXT_DIRECTION_LTR, raw.textDirection)
        assertEquals(View.LAYOUT_DIRECTION_LTR, raw.layoutDirection)

        invokePrivate<Unit>(activity, "prepareCheckSessionUi", CheckSettings(), false, ResultDisplayMode.NORMAL)
        assertFalse(collectAllText(body).contains(activity.getString(R.string.technical_data_title)))
    }

    @Test
    @Config(qualifiers = "fa-rIR")
    fun `persian layout keeps raw diagnostic text ltr`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        invokePrivate<Unit>(
            activity,
            "applyScanEvent",
            ScanEvent.Completed(checkResult(snapshot()), false, ResultDisplayMode.ADVANCED),
            false,
        )
        val body = activity.findViewById<ViewGroup>(R.id.bodyDirect)
        findMaterialButton(body, activity.getString(R.string.technical_data_title))!!.performClick()
        val raw = findTextView(body) { it.text.toString().contains("current-run payload") }!!

        assertEquals(View.TEXT_DIRECTION_LTR, raw.textDirection)
        assertEquals(View.LAYOUT_DIRECTION_LTR, raw.layoutDirection)
    }

    @Test
    fun `rotation replay keeps captured mode after preference changes`() {
        CheckViewModel.runScanOverride = { _, _, executionContext, _ ->
            executionContext.diagnosticCollector?.record(
                category = "dir",
                source = "fake",
                status = "ok",
                body = "rotation payload",
            )
            checkResult()
        }
        val controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        val first = controller.get()
        getPrivateField<CheckViewModel>(first, "viewModel").startScan(
            CheckSettings(),
            privacyMode = false,
            resultDisplayMode = ResultDisplayMode.ADVANCED,
        )
        shadowOf(Looper.getMainLooper()).idle()
        AppUiSettings.prefs(first).edit()
            .putString(SettingsPrefs.PREF_RESULT_DISPLAY_MODE, ResultDisplayMode.SIMPLE.prefValue)
            .commit()

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val recreated = controller.get()

        assertNotNull(
            findMaterialButton(
                recreated.findViewById(R.id.bodyDirect),
                recreated.getString(R.string.technical_data_title),
            ),
        )
    }

    private fun technicalCategory() = CategoryResult(
        name = "direct",
        detected = false,
        findings = listOf(Finding(TECHNICAL_MARKER)),
    )

    private fun snapshot(runTruncated: Boolean = false) = DiagnosticSnapshot(
        entries = listOf(
            DiagnosticEntry(
                category = "dir",
                source = "fake probe",
                target = "example.test",
                status = "ok",
                durationMs = 12,
                body = "current-run payload",
                storedBytes = 19,
                originalBytes = 19,
                truncated = false,
            ),
        ),
        storedBytes = 19,
        truncated = runTruncated,
    )

    private fun checkResult(snapshot: DiagnosticSnapshot? = null): CheckResult = CheckResult(
        geoIp = category("geo"),
        ipComparison = IpComparisonResult(
            detected = false,
            summary = "",
            ruGroup = group("ru"),
            nonRuGroup = group("non-ru"),
        ),
        directSigns = category("direct"),
        indirectSigns = category("indirect"),
        locationSignals = category("location"),
        bypassResult = BypassResult(
            proxyEndpoint = null,
            directIp = null,
            proxyIp = null,
            xrayApiScanResult = null,
            findings = emptyList(),
            detected = false,
        ),
        verdict = Verdict.NOT_DETECTED,
        diagnosticSnapshot = snapshot,
    )

    private fun category(name: String) = CategoryResult(name, detected = false, findings = emptyList())

    private fun group(name: String) = IpCheckerGroupResult(
        title = name,
        detected = false,
        statusLabel = "",
        summary = "",
        responses = emptyList(),
    )

    private fun ipResponse(ip: String, scope: IpCheckerScope) = IpCheckerResponse(
        label = "service",
        url = "https://example.test/ip",
        scope = scope,
        ip = ip,
    )

    private fun collectVisibleText(view: View): String {
        if (view.visibility != View.VISIBLE) return ""
        if (view is TextView) return view.text.toString()
        if (view !is ViewGroup) return ""
        return (0 until view.childCount).joinToString("\n") { collectVisibleText(view.getChildAt(it)) }
    }

    private fun collectAllText(view: View): String {
        if (view is TextView) return view.text.toString()
        if (view !is ViewGroup) return ""
        return (0 until view.childCount).joinToString("\n") { collectAllText(view.getChildAt(it)) }
    }

    private fun findMaterialButton(root: View, text: String): MaterialButton? {
        if (root is MaterialButton && root.text.toString() == text) return root
        if (root !is ViewGroup) return null
        return (0 until root.childCount).firstNotNullOfOrNull { findMaterialButton(root.getChildAt(it), text) }
    }

    private fun findTextView(root: View, predicate: (TextView) -> Boolean): TextView? {
        if (root is TextView && predicate(root)) return root
        if (root !is ViewGroup) return null
        return (0 until root.childCount).firstNotNullOfOrNull { findTextView(root.getChildAt(it), predicate) }
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getPrivateField(target: Any, name: String): T {
        val field = target::class.java.getDeclaredField(name)
        field.isAccessible = true
        return field.get(target) as T
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> invokePrivate(target: Any, name: String, vararg args: Any?): T {
        val method = target::class.java.declaredMethods.first {
            it.name == name && it.parameterTypes.size == args.size
        }
        method.isAccessible = true
        return method.invoke(target, *args) as T
    }

    companion object {
        private const val TECHNICAL_MARKER = "enum=ROUTING command=dumpsys path=/proc/net/route"
    }
}
