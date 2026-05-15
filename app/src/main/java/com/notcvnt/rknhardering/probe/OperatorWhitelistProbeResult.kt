package com.notcvnt.rknhardering.probe

data class OperatorWhitelistProbeResult(
    val whitelistDetected: Boolean,
    val googleReachable: Boolean,
    val appleReachable: Boolean,
    val firefoxReachable: Boolean,
    val russianControlReachable: Boolean,
    val errors: Map<String, String>,
    val durationMs: Long,
)
