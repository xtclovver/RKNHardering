package com.notcvnt.rknhardering.probe

import java.net.Inet4Address
import java.net.Inet6Address

/**
 * Strict IP-literal validators (charset checks + real InetAddress parsing).
 * Moved verbatim from CdnPullingClient. Not interchangeable with the
 * deliberately loose heuristic in PublicIpClient.looksLikeIp.
 */
internal object IpLiterals {

    fun isIpLiteral(value: String): Boolean {
        if (value.isBlank() || value.length > 64) return false
        val normalized = value.trim()
        return when {
            ':' in normalized -> isIpv6Body(normalized)
            '.' in normalized -> isIpv4Body(normalized)
            else -> false
        }
    }

    fun isIpv4Literal(value: String): Boolean {
        if (value.isBlank() || value.length > 64) return false
        return isIpv4Body(value.trim())
    }

    fun isIpv6Literal(value: String): Boolean {
        if (value.isBlank() || value.length > 64) return false
        val normalized = value.trim()
        return ':' in normalized && isIpv6Body(normalized)
    }

    private fun isIpv4Body(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4 || parts.any { it.isBlank() }) return false
        if (parts.any { it.length > 1 && it.startsWith('0') }) return false
        if (parts.any { part -> part.any { !it.isDigit() } }) return false
        if (parts.any { (it.toIntOrNull() ?: -1) !in 0..255 }) return false
        val parsed = runCatching { java.net.InetAddress.getByName(value) }.getOrNull() ?: return false
        return parsed is Inet4Address
    }

    private fun isIpv6Body(value: String): Boolean {
        if (!value.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
            return false
        }
        val parsed = runCatching { java.net.InetAddress.getByName(value) }.getOrNull() ?: return false
        return parsed is Inet6Address
    }
}
