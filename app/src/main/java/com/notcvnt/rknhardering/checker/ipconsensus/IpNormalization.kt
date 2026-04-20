package com.notcvnt.rknhardering.checker.ipconsensus

import com.notcvnt.rknhardering.model.IpFamily
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

object IpNormalization {

    data class Normalized(val value: String, val family: IpFamily)

    private val IPV4_STRICT = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    fun parse(raw: String?): Normalized? {
        val trimmed = raw?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        if (!looksNumeric(trimmed)) return null
        val stripped = trimmed.substringBefore('%')
        if (!stripped.contains(':')) {
            // IPv4 candidate — strict validation before InetAddress
            if (!IPV4_STRICT.matches(stripped)) return null
            if (!stripped.split('.').all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }) return null
        }
        return try {
            val address = InetAddress.getByName(trimmed)
            when (address) {
                is Inet4Address -> Normalized(address.hostAddress.orEmpty(), IpFamily.V4)
                is Inet6Address -> collapseMappedOrFormat(address)
                else -> null
            }?.takeIf { it.value.isNotEmpty() }
        } catch (_: Exception) {
            null
        }
    }

    private fun collapseMappedOrFormat(address: Inet6Address): Normalized {
        val mapped = address.toIpv4MappedOrNull()
        if (mapped != null) return Normalized(mapped, IpFamily.V4)
        val compressed = compressIpv6(address)
        return Normalized(compressed, IpFamily.V6)
    }

    /**
     * Produces RFC 5952 canonical compressed form.
     * Expands the address to 8 groups, finds the longest run of consecutive zero groups
     * (minimum length 2; earliest run wins ties), replaces with "::", lowercases.
     */
    private fun compressIpv6(address: Inet6Address): String {
        val bytes = address.address
        val groups = IntArray(8) { i ->
            ((bytes[i * 2].toInt() and 0xFF) shl 8) or (bytes[i * 2 + 1].toInt() and 0xFF)
        }

        // Find the longest run of zeros (length >= 2)
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (groups[i] == 0) {
                var j = i
                while (j < 8 && groups[j] == 0) j++
                val len = j - i
                if (len >= 2 && len > bestLen) {
                    bestStart = i
                    bestLen = len
                }
                i = j
            } else {
                i++
            }
        }

        val sb = StringBuilder()
        var idx = 0
        while (idx < 8) {
            if (idx == bestStart) {
                sb.append("::")
                idx += bestLen
            } else {
                if (sb.isNotEmpty() && !sb.endsWith(':')) sb.append(':')
                sb.append(groups[idx].toString(16))
                idx++
            }
        }
        return sb.toString()
    }

    private fun Inet6Address.toIpv4MappedOrNull(): String? {
        val bytes = address
        if (bytes.size != 16) return null
        for (i in 0 until 10) if (bytes[i] != 0.toByte()) return null
        if (bytes[10] != 0xFF.toByte() || bytes[11] != 0xFF.toByte()) return null
        return "${bytes[12].toInt() and 0xFF}." +
            "${bytes[13].toInt() and 0xFF}." +
            "${bytes[14].toInt() and 0xFF}." +
            "${bytes[15].toInt() and 0xFF}"
    }

    private fun looksNumeric(value: String): Boolean {
        val stripped = value.substringBefore('%')
        val hasColon = stripped.contains(':')
        val hasDot = stripped.contains('.')
        if (!hasColon && !hasDot) return false
        if (hasColon) return stripped.all { it == ':' || it == '.' || it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
        return stripped.all { it == '.' || it.isDigit() }
    }
}
