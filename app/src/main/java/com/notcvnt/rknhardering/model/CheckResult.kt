package com.notcvnt.rknhardering.model

import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.XrayApiScanResult

data class Finding(val description: String, val detected: Boolean)

data class CategoryResult(
    val name: String,
    val detected: Boolean,
    val findings: List<Finding>
)

enum class Verdict {
    NOT_DETECTED,
    NEEDS_REVIEW,
    DETECTED
}

data class BypassResult(
    val proxyEndpoint: ProxyEndpoint?,
    val directIp: String?,
    val proxyIp: String?,
    val xrayApiScanResult: XrayApiScanResult?,
    val findings: List<Finding>,
    val detected: Boolean,
)

data class CheckResult(
    val geoIp: CategoryResult,
    val directSigns: CategoryResult,
    val indirectSigns: CategoryResult,
    val bypassResult: BypassResult,
    val verdict: Verdict
)
