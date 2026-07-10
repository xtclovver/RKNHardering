package com.notcvnt.rknhardering

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.checker.VpnCheckRunner
import com.notcvnt.rknhardering.customcheck.CustomCheckRunner
import com.notcvnt.rknhardering.diagnostics.DiagnosticTraceCollector
import com.notcvnt.rknhardering.model.CheckResult
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

sealed interface ScanEvent {
    data class Started(
        val settings: CheckSettings,
        val privacyMode: Boolean,
        val resultDisplayMode: ResultDisplayMode = ResultDisplayMode.NORMAL,
    ) : ScanEvent
    data class Update(val update: CheckUpdate) : ScanEvent
    data class Completed(
        val result: CheckResult,
        val privacyMode: Boolean,
        val resultDisplayMode: ResultDisplayMode = ResultDisplayMode.NORMAL,
    ) : ScanEvent
    data object Cancelled : ScanEvent
}

data class ScanEventTimeline(
    val scanId: Long? = null,
    val version: Long = 0L,
    val events: List<ScanEvent> = emptyList(),
)

class CheckViewModel(app: Application) : AndroidViewModel(app) {
    internal companion object {
        var runScanOverride: (suspend (Application, CheckSettings, ScanExecutionContext, (suspend (CheckUpdate) -> Unit)?) -> CheckResult)? = null
    }

    private val _scanEvents = MutableStateFlow(ScanEventTimeline())
    val scanEvents: StateFlow<ScanEventTimeline> = _scanEvents

    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning

    private var scanJob: Job? = null
    private var scanEventBuffer: MutableList<ScanEvent> = mutableListOf()
    private var scanEventVersion = 0L
    private var nextScanId = 1L
    private var activeScanId: Long? = null
    private var activeExecutionContext: ScanExecutionContext? = null
    private var completedDiagnosticsConsumed = false

    fun startScan(settings: CheckSettings, privacyMode: Boolean) {
        val resultDisplayMode = ResultDisplayMode.fromPrefs(AppUiSettings.prefs(getApplication()))
        startScan(settings, privacyMode, resultDisplayMode)
    }

    fun startScan(
        settings: CheckSettings,
        privacyMode: Boolean,
        resultDisplayMode: ResultDisplayMode,
    ) {
        if (scanJob?.isActive == true && activeExecutionContext?.cancellationSignal?.isCancelled() == false) return

        val scanId = nextScanId++
        val diagnosticCollector = if (resultDisplayMode == ResultDisplayMode.ADVANCED) {
            DiagnosticTraceCollector(privacyMode)
        } else {
            null
        }
        val executionContext = ScanExecutionContext(
            scanId = scanId,
            resultDisplayMode = resultDisplayMode,
            diagnosticCollector = diagnosticCollector,
        )
        activeScanId = scanId
        activeExecutionContext = executionContext
        resetCompletedDiagnosticsRetention()
        replaceScanEvents(scanId, ScanEvent.Started(settings, privacyMode, resultDisplayMode))
        _isRunning.value = true

        lateinit var launchedJob: Job
        launchedJob = viewModelScope.launch {
            try {
                val runner = runScanOverride
                val result = if (runner != null) {
                    runner(
                        getApplication(),
                        settings,
                        executionContext,
                    ) { update ->
                        if (isCurrentScan(scanId, executionContext)) {
                            appendScanEvent(scanId, ScanEvent.Update(update))
                        }
                    }
                } else {
                    VpnCheckRunner.run(
                        context = getApplication(),
                        settings = settings,
                        executionContext = executionContext,
                    ) { update ->
                        if (isCurrentScan(scanId, executionContext)) {
                            appendScanEvent(scanId, ScanEvent.Update(update))
                        }
                    }
                }
                if (isCurrentScan(scanId, executionContext)) {
                    val resultWithProfile = try {
                        val app: Application = getApplication()
                        val customEnabled = AppUiSettings.prefs(app)
                            .getBoolean(SettingsPrefs.PREF_CUSTOM_CHECKS_ENABLED, false)
                        val profile = if (customEnabled) CustomCheckRunner.getActiveProfile(app) else null
                        result.copy(
                            customProfileId = profile?.id,
                            customProfileName = profile?.name,
                        )
                    } catch (_: Exception) {
                        result
                    }
                    val enrichedResult = if (resultWithProfile.diagnosticSnapshot == null) {
                        resultWithProfile.copy(
                            diagnosticSnapshot = executionContext.diagnosticCollector?.snapshot(),
                        )
                    } else {
                        resultWithProfile
                    }
                    appendScanEvent(scanId, ScanEvent.Completed(enrichedResult, privacyMode, resultDisplayMode))
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                executionContext.diagnosticCollector?.clear()
                if (isCurrentScan(scanId, executionContext)) {
                    appendScanEvent(scanId, ScanEvent.Cancelled)
                }
                throw e
            } finally {
                if (activeExecutionContext === executionContext) {
                    activeExecutionContext = null
                    activeScanId = null
                    _isRunning.value = false
                }
                if (scanJob === launchedJob) {
                    scanJob = null
                }
            }
        }
        scanJob = launchedJob
    }

    fun cancelScan() {
        val executionContext = activeExecutionContext ?: return
        val scanId = activeScanId
        if (scanId != null) {
            appendScanEvent(scanId, ScanEvent.Cancelled)
        }
        activeExecutionContext = null
        activeScanId = null
        _isRunning.value = false
        executionContext.diagnosticCollector?.clear()
        executionContext.cancellationSignal.cancel()
        scanJob?.cancel()
    }

    private fun isCurrentScan(scanId: Long, executionContext: ScanExecutionContext): Boolean {
        return activeScanId == scanId && activeExecutionContext === executionContext
    }

    private fun replaceScanEvents(scanId: Long, event: ScanEvent) {
        scanEventBuffer = mutableListOf(event)
        publishScanEvents(scanId)
    }

    private fun appendScanEvent(scanId: Long, event: ScanEvent) {
        scanEventBuffer.add(event)
        publishScanEvents(scanId)
    }

    private fun publishScanEvents(scanId: Long) {
        scanEventVersion += 1
        _scanEvents.value = ScanEventTimeline(
            scanId = scanId,
            version = scanEventVersion,
            events = scanEventBuffer,
        )
    }

    internal fun canRetainCompletedDiagnostics(): Boolean = !completedDiagnosticsConsumed

    internal fun markCompletedDiagnosticsConsumed() {
        completedDiagnosticsConsumed = true
    }

    internal fun resetCompletedDiagnosticsRetention() {
        completedDiagnosticsConsumed = false
    }
}
