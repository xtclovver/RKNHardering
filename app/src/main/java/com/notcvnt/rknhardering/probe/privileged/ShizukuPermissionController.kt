package com.notcvnt.rknhardering.probe.privileged

import android.content.pm.PackageManager
import rikka.shizuku.Shizuku

enum class ShizukuPermissionState {
    GRANTED,
    DENIED,
    RATIONALE_REQUIRED,
    UNAVAILABLE,
}

internal object ShizukuPermissionController {
    fun state(): ShizukuPermissionState = runCatching {
        when {
            !Shizuku.pingBinder() || Shizuku.isPreV11() -> ShizukuPermissionState.UNAVAILABLE
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED -> ShizukuPermissionState.GRANTED
            Shizuku.shouldShowRequestPermissionRationale() -> ShizukuPermissionState.RATIONALE_REQUIRED
            else -> ShizukuPermissionState.DENIED
        }
    }.getOrDefault(ShizukuPermissionState.UNAVAILABLE)

    fun requestAfterConsent(requestCode: Int): Boolean {
        if (state() !in setOf(ShizukuPermissionState.DENIED, ShizukuPermissionState.RATIONALE_REQUIRED)) {
            return false
        }
        return runCatching {
            Shizuku.requestPermission(requestCode)
            true
        }.getOrDefault(false)
    }
}
