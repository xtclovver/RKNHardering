package com.notcvnt.rknhardering.customcheck

import java.net.IDN
import java.net.InetAddress
import java.net.URI
import java.util.Locale

// Validates URLs and host names extracted from imported profiles. Goal: stop
// profiles from steering checks at attacker-controlled cleartext endpoints or
// the user's own LAN/loopback.
//
// Rules (all silently drop the value when violated; the caller treats a dropped
// value as if the field were empty):
//   * URLs: only https:// is accepted. http://, file://, content://, javascript:,
//     data: are rejected. Host must pass the host check below.
//   * Hosts (used by ICMP/RTT/STUN/DoH bootstrap): no IP-literal in private/loopback/
//     link-local ranges, no .local mDNS. Hostnames must look like a public DNS name.
//   * Length cap on URL: 512 chars. On host: 253 (RFC 1035 + IDN headroom).
object UrlSanitizer {

    private const val MAX_URL_LEN = 512
    private const val MAX_HOST_LEN = 253

    private const val IP_PLACEHOLDER = "{ip}"
    // Public, routable literal used only to validate a placeholder URL. Must pass
    // isPublicAddress (TEST-NET ranges like 203.0.113.x are rejected there).
    private const val IP_PLACEHOLDER_PROBE = "8.8.8.8"

    private val DISALLOWED_HOST_SUFFIXES = listOf(".local", ".localhost", ".internal", ".lan", ".home")
    private val DISALLOWED_HOST_EXACT = setOf("localhost", "broadcasthost")

    fun sanitizeHttpsUrl(raw: String): String {
        if (raw.isBlank() || raw.length > MAX_URL_LEN) return ""
        val uri = runCatching { URI(raw) }.getOrNull() ?: return ""
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return ""
        if (scheme != "https") return ""
        val host = uri.host ?: return ""
        if (!isPublicHost(host)) return ""
        return raw
    }

    // GeoIP custom providers may embed the documented "{ip}" placeholder in the
    // URL (see GeoIpChecker.fetchCustomProvider). The raw "{" / "}" are illegal in
    // a java.net.URI, so the generic sanitizeHttpsUrl drops such URLs. This variant
    // validates a copy with "{ip}" replaced by a public IP literal and returns the
    // ORIGINAL string (placeholder intact) when that copy passes. Only the GeoIP
    // provider path substitutes "{ip}" at fetch time; do not use this for endpoints
    // that send the URL verbatim.
    fun sanitizeGeoIpProviderUrl(raw: String): String {
        if (raw.isBlank() || raw.length > MAX_URL_LEN) return ""
        val probe = raw.replace(IP_PLACEHOLDER, IP_PLACEHOLDER_PROBE)
        if (sanitizeHttpsUrl(probe).isEmpty()) return ""
        return raw
    }

    fun sanitizeHost(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty() || trimmed.length > MAX_HOST_LEN) return ""
        if (!isPublicHost(trimmed)) return ""
        return trimmed
    }

    // Drops dns_servers / doh_bootstrap entries pointing at private/loopback addresses.
    // Accepts both single string and comma/whitespace separated lists.
    fun sanitizeAddressList(raw: String): String {
        if (raw.isBlank()) return ""
        return raw.split(Regex("[,\\s]+"))
            .map { it.trim() }
            .filter { it.isNotEmpty() && isPublicAddress(it) }
            .joinToString(", ")
    }

    private fun isPublicHost(host: String): Boolean {
        val h = host.removeSurrounding("[", "]").lowercase(Locale.ROOT)
        if (h.isEmpty() || h.length > MAX_HOST_LEN) return false
        if (h in DISALLOWED_HOST_EXACT) return false
        if (DISALLOWED_HOST_SUFFIXES.any { h.endsWith(it) }) return false
        // IP literal — must not be private/loopback/link-local
        if (looksLikeIpLiteral(h)) return isPublicAddress(h)
        // Hostname — must contain a dot and start/end with alphanumeric
        if (!h.contains('.')) return false
        val ascii = runCatching { IDN.toASCII(h) }.getOrNull() ?: return false
        return ascii.matches(Regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$"))
    }

    private fun looksLikeIpLiteral(s: String): Boolean =
        s.matches(Regex("^[0-9.]+$")) || s.contains(':')

    private fun isPublicAddress(s: String): Boolean {
        val addr = runCatching { InetAddress.getByName(s) }.getOrNull() ?: return false
        if (addr.isLoopbackAddress) return false
        if (addr.isAnyLocalAddress) return false
        if (addr.isLinkLocalAddress) return false
        if (addr.isSiteLocalAddress) return false
        if (addr.isMulticastAddress) return false
        val bytes = addr.address
        // CGNAT 100.64.0.0/10
        if (bytes.size == 4 && (bytes[0].toInt() and 0xFF) == 100) {
            val second = bytes[1].toInt() and 0xFF
            if (second in 64..127) return false
        }
        // 169.254.0.0/16 already covered by isLinkLocalAddress
        // 192.0.0.0/24, 192.0.2.0/24 (TEST-NET-1), 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4
        if (bytes.size == 4) {
            val b0 = bytes[0].toInt() and 0xFF
            val b1 = bytes[1].toInt() and 0xFF
            val b2 = bytes[2].toInt() and 0xFF
            if (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) return false
            if (b0 == 198 && (b1 == 18 || b1 == 19)) return false
            if (b0 == 198 && b1 == 51 && b2 == 100) return false
            if (b0 == 203 && b1 == 0 && b2 == 113) return false
            if (b0 >= 240) return false
        }
        return true
    }
}
