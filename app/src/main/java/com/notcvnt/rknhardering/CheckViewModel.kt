package com.notcvnt.rknhardering

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.checker.VpnCheckRunner
import com.notcvnt.rknhardering.model.CheckResult
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

sealed interface ScanEvent {
    data class Started(val settings: CheckSettings, val privacyMode: Boolean) : ScanEvent
    data class Update(val update: CheckUpdate) : ScanEvent
    data class Completed(val result: CheckResult, val privacyMode: Boolean) : ScanEvent
    data object Cancelled : ScanEvent
}

class CheckViewModel(app: Application) : AndroidViewModel(app) {
    internal companion object {
        var runScanOverride: (suspend (Application, CheckSettings, ScanExecutionContext, (suspend (CheckUpdate) -> Unit)?) -> CheckResult)? = null
    }

    private val _scanEvents = MutableStateFlow<List<ScanEvent>>(emptyList())
    val scanEvents: StateFlow<List<ScanEvent>> = _scanEvents

    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning

    private var scanJob: Job? = null
    private var nextScanId = 1L
    private var activeScanId: Long? = null
    private var activeExecutionContext: ScanExecutionContext? = null
    private var completedDiagnosticsConsumed = false

    fun startScan(settings: CheckSettings, privacyMode: Boolean) {
        if (scanJob?.isActive == true && activeExecutionContext?.cancellationSignal?.isCancelled() == false) return

        resetCompletedDiagnosticsRetention()
        _scanEvents.value = listOf(ScanEvent.Started(settings, privacyMode))
        _isRunning.value = true
        val scanId = nextScanId++
        val executionContext = ScanExecutionContext(scanId = scanId)
        activeScanId = scanId
        activeExecutionContext = executionContext

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
                            _scanEvents.value = _scanEvents.value + ScanEvent.Update(update)
                        }
                    }
                } else {
                    VpnCheckRunner.run(
                        context = getApplication(),
                        settings = settings,
                        executionContext = executionContext,
                    ) { update ->
                        if (isCurrentScan(scanId, executionContext)) {
                            _scanEvents.value = _scanEvents.value + ScanEvent.Update(update)
                        }
                    }
                }
                if (isCurrentScan(scanId, executionContext)) {
                    _scanEvents.value = _scanEvents.value + ScanEvent.Completed(result, privacyMode)
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                if (isCurrentScan(scanId, executionContext)) {
                    _scanEvents.value = _scanEvents.value + ScanEvent.Cancelled
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
            _scanEvents.value = _scanEvents.value + ScanEvent.Cancelled
        }
        activeExecutionContext = null
        activeScanId = null
        _isRunning.value = false
        executionContext.cancellationSignal.cancel()
        scanJob?.cancel()
    }

    private fun isCurrentScan(scanId: Long, executionContext: ScanExecutionContext): Boolean {
        return activeScanId == scanId && activeExecutionContext === executionContext
    }

    internal fun canRetainCompletedDiagnostics(): Boolean = !completedDiagnosticsConsumed

    internal fun markCompletedDiagnosticsConsumed() {
        completedDiagnosticsConsumed = true
    }

    internal fun resetCompletedDiagnosticsRetention() {
        completedDiagnosticsConsumed = false
    }
}
