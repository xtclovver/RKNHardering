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
        assertTrue(viewModel.scanEvents.value.last() is ScanEvent.Cancelled)

        shadowOf(Looper.getMainLooper()).idle()
        assertTrue(finished.await(1, TimeUnit.SECONDS))
        shadowOf(Looper.getMainLooper()).idle()

        val events = viewModel.scanEvents.value
        assertEquals(2, events.size)
        assertTrue(events[0] is ScanEvent.Started)
        assertTrue(events[1] is ScanEvent.Cancelled)
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
