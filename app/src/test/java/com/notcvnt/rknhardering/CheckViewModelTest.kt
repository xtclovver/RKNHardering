package com.notcvnt.rknhardering

import android.app.Application
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.Verdict
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
class CheckViewModelTest {

    @After
    fun tearDown() {
        CheckViewModel.runScanOverride = null
    }

    @Test
    fun `completed diagnostics retention can be consumed and reset`() {
        val viewModel = CheckViewModel(Application())

        assertTrue(viewModel.canRetainCompletedDiagnostics())

        viewModel.markCompletedDiagnosticsConsumed()
        assertFalse(viewModel.canRetainCompletedDiagnostics())

        viewModel.resetCompletedDiagnosticsRetention()
        assertTrue(viewModel.canRetainCompletedDiagnostics())
    }

    @Test
    fun `cancel scan publishes cancelled immediately and ignores late events`() {
        val started = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val viewModel = CheckViewModel(ApplicationProvider.getApplicationContext())

        CheckViewModel.runScanOverride = { _, _, _, onUpdate ->
            try {
                suspendCancellableCoroutine<Unit> { continuation ->
                    started.countDown()
                    continuation.invokeOnCancellation { }
                }
            } catch (_: CancellationException) {
            }

            withContext(NonCancellable) {
                onUpdate?.invoke(CheckUpdate.DirectSignsReady(category("late-direct")))
                finished.countDown()
                completedResult()
            }
        }

        viewModel.startScan(
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = false,
            ),
            privacyMode = false,
        )
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(started.await(1, TimeUnit.SECONDS))

        viewModel.cancelScan()

        assertFalse(viewModel.isRunning.value)
        assertTrue(viewModel.scanEvents.value.events.last() is ScanEvent.Cancelled)

        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(finished.await(1, TimeUnit.SECONDS))
        shadowOf(Looper.getMainLooper()).idle()

        val timeline = viewModel.scanEvents.value
        val events = timeline.events
        assertTrue(timeline.scanId != null)
        assertEquals(2, events.size)
        assertTrue(events[0] is ScanEvent.Started)
        assertTrue(events[1] is ScanEvent.Cancelled)
    }

    @Test
    fun `scan timeline keeps captured display mode and next scan uses changed preference`() {
        val firstScanMayComplete = CompletableDeferred<Unit>()
        val capturedContexts = mutableListOf<ScanExecutionContext>()
        val app: Application = ApplicationProvider.getApplicationContext()
        val prefs = AppUiSettings.prefs(app)
        prefs.edit().clear().putString(
            SettingsPrefs.PREF_RESULT_DISPLAY_MODE,
            ResultDisplayMode.SIMPLE.prefValue,
        ).commit()
        val viewModel = CheckViewModel(app)

        CheckViewModel.runScanOverride = { _, _, executionContext, _ ->
            capturedContexts += executionContext
            if (capturedContexts.size == 1) firstScanMayComplete.await()
            completedResult()
        }

        viewModel.startScan(
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = false,
            ),
            privacyMode = true,
        )
        shadowOf(Looper.getMainLooper()).idle()

        val started = viewModel.scanEvents.value.events.single() as ScanEvent.Started
        assertEquals(ResultDisplayMode.SIMPLE, started.resultDisplayMode)
        assertEquals(ResultDisplayMode.SIMPLE, capturedContexts.single().resultDisplayMode)
        assertEquals(null, capturedContexts.single().diagnosticCollector)

        prefs.edit().putString(
            SettingsPrefs.PREF_RESULT_DISPLAY_MODE,
            ResultDisplayMode.ADVANCED.prefValue,
        ).commit()
        assertEquals(ResultDisplayMode.SIMPLE, started.resultDisplayMode)

        firstScanMayComplete.complete(Unit)
        shadowOf(Looper.getMainLooper()).idle()

        val firstCompleted = viewModel.scanEvents.value.events.last() as ScanEvent.Completed
        assertEquals(ResultDisplayMode.SIMPLE, firstCompleted.resultDisplayMode)

        viewModel.startScan(
            settings = started.settings,
            privacyMode = true,
        )
        shadowOf(Looper.getMainLooper()).idle()

        val secondEvents = viewModel.scanEvents.value.events
        assertEquals(ResultDisplayMode.ADVANCED, (secondEvents.first() as ScanEvent.Started).resultDisplayMode)
        assertEquals(ResultDisplayMode.ADVANCED, (secondEvents.last() as ScanEvent.Completed).resultDisplayMode)
        assertEquals(ResultDisplayMode.ADVANCED, capturedContexts.last().resultDisplayMode)
        assertTrue(capturedContexts.last().diagnosticCollector != null)
    }

    private fun category(name: String): CategoryResult = CategoryResult(
        name = name,
        detected = false,
        findings = emptyList(),
    )

    private fun completedResult(): CheckResult = CheckResult(
        geoIp = category("geo"),
        ipComparison = IpComparisonResult(
            detected = false,
            summary = "",
            ruGroup = IpCheckerGroupResult(
                title = "ru",
                detected = false,
                statusLabel = "",
                summary = "",
                responses = emptyList(),
            ),
            nonRuGroup = IpCheckerGroupResult(
                title = "non-ru",
                detected = false,
                statusLabel = "",
                summary = "",
                responses = emptyList(),
            ),
        ),
        cdnPulling = CdnPullingResult.empty(),
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
    )
}
