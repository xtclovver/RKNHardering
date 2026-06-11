package com.notcvnt.rknhardering.util

import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportStatus
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

private const val IP_MASK_PLACEHOLDER = "*.*.*.*"

fun maskIp(ip: String): String {
    val normalized = ip.trim()
    val parsed = when {
        normalized.contains('.') -> {
            val parts = normalized.split('.')
            if (parts.size != 4 || parts.any { (it.toIntOrNull() ?: -1) !in 0..255 }) {
                return IP_MASK_PLACEHOLDER
            }
            runCatching { InetAddress.getByName(normalized) }.getOrNull()
        }
        normalized.contains(':') -> runCatching { InetAddress.getByName(normalized) }.getOrNull()
        else -> null
    } ?: return IP_MASK_PLACEHOLDER
    return when (parsed) {
        is Inet4Address -> {
            if (parsed.isSiteLocalAddress || parsed.isLoopbackAddress || parsed.isLinkLocalAddress) {
                normalized
            } else {
                val bytes = parsed.address.map { it.toInt() and 0xff }
                "${bytes[0]}.${bytes[1]}.*.*"
            }
        }
        is Inet6Address -> {
            if (parsed.isLoopbackAddress || parsed.isLinkLocalAddress || isUniqueLocalIpv6(parsed)) {
                normalized
            } else {
                val groups = parsed.hostAddress?.substringBefore('%')?.split(':').orEmpty()
                if (groups.size < 4) {
                    "*:*:*:*"
                } else {
                    groups.take(4).joinToString(":") + ":*:*:*:*"
                }
            }
        }
        else -> IP_MASK_PLACEHOLDER
    }
}

fun maskIpsInText(text: String): String {
    val ipv4Regex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
    val maskedIpv4 = ipv4Regex.replace(text) { match ->
        maskIp(match.value)
    }
    val ipv6Regex = Regex("""(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9])""")
    return ipv6Regex.replace(maskedIpv4) { match ->
        maskIp(match.value.trim('[', ']'))
    }
}

internal fun maskInfoValue(value: String, privacyMode: Boolean): String {
    return if (privacyMode) maskIpsInText(value) else value
}

private const val CALL_TRANSPORT_NO_STUN_RESPONSE_MARKER = "did not receive a STUN response"
private const val CALL_TRANSPORT_TELEGRAM_DC_UNREACHABLE_MARKER = "did not expose a reachable Telegram DC"

internal fun formatCallTransportReason(
    context: android.content.Context,
    leak: CallTransportLeakResult,
    privacyMode: Boolean,
): String? {
    val summary = leak.summary.trim()
    return when {
        leak.status == CallTransportStatus.BASELINE || leak.status == CallTransportStatus.NEEDS_REVIEW -> null
        summary.contains(CALL_TRANSPORT_NO_STUN_RESPONSE_MARKER, ignoreCase = true) ->
            buildCallTransportReason(
                base = context.getString(R.string.main_card_call_transport_reason_no_response),
                detail = summaryDetailAfterMarker(summary, CALL_TRANSPORT_NO_STUN_RESPONSE_MARKER),
                privacyMode = privacyMode,
            )
        summary.contains(CALL_TRANSPORT_TELEGRAM_DC_UNREACHABLE_MARKER, ignoreCase = true) ->
            buildCallTransportReason(
                base = context.getString(R.string.main_card_call_transport_reason_telegram_dc_unreachable),
                detail = summaryDetailAfterMarker(summary, CALL_TRANSPORT_TELEGRAM_DC_UNREACHABLE_MARKER),
                privacyMode = privacyMode,
            )
        summary.contains("targets are unavailable", ignoreCase = true) ||
            summary.contains("target catalog is unavailable", ignoreCase = true) ->
            context.getString(R.string.main_card_call_transport_reason_targets_unavailable)
        else -> maskInfoValue(summary, privacyMode)
    }
}

private fun buildCallTransportReason(base: String, detail: String?, privacyMode: Boolean): String {
    val maskedDetail = detail
        ?.takeIf { it.isNotBlank() }
        ?.let { maskInfoValue(it, privacyMode) }
    return if (maskedDetail.isNullOrBlank()) base else "$base: $maskedDetail"
}

private fun summaryDetailAfterMarker(summary: String, marker: String): String? {
    val tail = summary.substringAfter(marker, missingDelimiterValue = "").trim()
    return tail.removePrefix(":").trim().takeIf { it.isNotBlank() }
}

private fun isUniqueLocalIpv6(address: Inet6Address): Boolean {
    val firstByte = address.address.firstOrNull()?.toInt()?.and(0xff) ?: return false
    return (firstByte and 0xfe) == 0xfc
}
