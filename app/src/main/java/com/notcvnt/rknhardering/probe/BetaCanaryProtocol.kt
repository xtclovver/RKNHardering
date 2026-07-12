package com.notcvnt.rknhardering.probe

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Base64

internal const val BETA_CANARY_SCHEMA_VERSION = 1

internal enum class BetaCanaryStatus {
    AVAILABLE,
    UNAVAILABLE,
    DISABLED,
    FAILED,
    UNSUPPORTED,
}

internal enum class BetaCanaryTransport {
    HTTP,
    HTTPS,
    TCP,
    UDP,
    DNS,
    QUIC,
}

internal enum class BetaCanaryAddressFamily(val wireValue: String) {
    IPV4("ipv4"),
    IPV6("ipv6");

    internal fun accepts(address: InetAddress): Boolean = when (this) {
        IPV4 -> address is Inet4Address
        IPV6 -> address is Inet6Address
    }
}

internal data class BetaCanaryEndpointConfig(
    val ipv4Address: String? = null,
    val ipv6Address: String? = null,
    val httpPort: Int,
    val tcpPort: Int,
    val udpPort: Int,
    val dnsPort: Int,
    val dnsZone: String,
    val httpsPort: Int? = null,
    val tlsServerName: String? = null,
    val tlsSpkiSha256: String? = null,
    val timeoutMs: Int = 4_000,
) {
    internal fun validated(): Result<BetaCanaryEndpointConfig> = runCatching {
        require(ipv4Address != null || ipv6Address != null) { "At least one literal address is required" }
        listOfNotNull(ipv4Address, ipv6Address).forEach { literal ->
            require(isIpLiteral(literal)) { "Canary address must be an IP literal" }
        }
        require(ipv4Address?.let { InetAddress.getByName(it) is Inet4Address } != false) { "ipv4Address is not IPv4" }
        require(ipv6Address?.let { InetAddress.getByName(it) is Inet6Address } != false) { "ipv6Address is not IPv6" }
        listOf(httpPort, tcpPort, udpPort, dnsPort).forEach { require(it in 1..65535) { "Invalid port" } }
        httpsPort?.let { require(it in 1..65535) { "Invalid HTTPS port" } }
        require(timeoutMs in 250..30_000) { "Timeout is outside safe bounds" }
        val normalizedZone = dnsZone.trim().trimEnd('.').lowercase()
        require(normalizedZone.isNotBlank() && normalizedZone.length <= 180) { "Invalid DNS zone" }
        normalizedZone.split('.').forEach { label ->
            require(label.length in 1..63 && label.all { it.isLetterOrDigit() || it == '-' }) { "Invalid DNS zone" }
        }
        if (httpsPort != null) {
            require(!tlsServerName.isNullOrBlank()) { "TLS server name is required for HTTPS" }
            require(!tlsServerName.contains(':') && tlsServerName.any { it.isLetter() }) { "TLS server name must be a DNS name" }
        }
        tlsSpkiSha256?.let { pin ->
            require(pin.startsWith("sha256/")) { "Invalid SPKI pin" }
            require(Base64.getDecoder().decode(pin.removePrefix("sha256/")).size == 32) { "Invalid SPKI pin" }
        }
        copy(dnsZone = normalizedZone)
    }

    internal fun targets(): List<Pair<BetaCanaryAddressFamily, InetAddress>> = buildList {
        ipv4Address?.let { add(BetaCanaryAddressFamily.IPV4 to InetAddress.getByName(it)) }
        ipv6Address?.let { add(BetaCanaryAddressFamily.IPV6 to InetAddress.getByName(it)) }
    }

    private fun isIpLiteral(value: String): Boolean {
        if (value.contains(':')) return value.matches(Regex("[0-9A-Fa-f:.%]+"))
        return value.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            value.split('.').all { it.toIntOrNull() in 0..255 }
    }
}

internal data class BetaCanaryObservation(
    val transport: BetaCanaryTransport,
    val family: BetaCanaryAddressFamily,
    val status: BetaCanaryStatus,
    val observedAddressHash: String? = null,
    val clientLocalAddressHash: String? = null,
    val localDestinationHash: String? = null,
    val ingressInterfaceIndex: Int? = null,
    val serverInstance: String? = null,
    val serverTimestampSeconds: Long? = null,
    val tlsVersion: String? = null,
    val tlsCipher: String? = null,
    val tlsAlpn: String? = null,
    val certificateSpkiSha256: String? = null,
    val certificateChainSha256: List<String> = emptyList(),
    val httpVersion: String? = null,
    val serverFingerprintHash: String? = null,
    val failureKind: String? = null,
)

internal data class BetaCanaryRunResult(
    val schemaVersion: Int = BETA_CANARY_SCHEMA_VERSION,
    val status: BetaCanaryStatus,
    val runTokenHash: String? = null,
    val boundNetworkHandle: Long? = null,
    val observations: List<BetaCanaryObservation> = emptyList(),
    val reason: String? = null,
)
