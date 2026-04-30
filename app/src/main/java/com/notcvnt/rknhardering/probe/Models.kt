package com.notcvnt.rknhardering.probe

enum class ScanMode {
    AUTO,
    MANUAL,
    POPULAR_ONLY,
}

enum class ScanPhase {
    POPULAR_PORTS,
    FULL_RANGE,
}

enum class ProxyType {
    SOCKS5,
    HTTP,
}

data class ProxyEndpoint(
    val host: String,
    val port: Int,
    val type: ProxyType,
    val authRequired: Boolean = false,
)

data class ScanProgress(
    val phase: ScanPhase,
    val scanned: Int,
    val total: Int,
    val currentPort: Int,
)
