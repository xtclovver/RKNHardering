package com.notcvnt.rknhardering.diagnostics

import java.nio.charset.StandardCharsets

data class DiagnosticEntry(
    val category: String,
    val source: String,
    val target: String?,
    val status: String,
    val durationMs: Long?,
    val body: String,
    val storedBytes: Int,
    val originalBytes: Int,
    val truncated: Boolean,
) {
    override fun toString(): String =
        "DiagnosticEntry(category=$category, source=$source, target=$target, status=$status, " +
            "durationMs=$durationMs, storedBytes=$storedBytes, originalBytes=$originalBytes, truncated=$truncated)"
}

data class DiagnosticSnapshot(
    val entries: List<DiagnosticEntry>,
    val storedBytes: Int,
    val truncated: Boolean,
) {
    companion object {
        val EMPTY = DiagnosticSnapshot(emptyList(), storedBytes = 0, truncated = false)
    }
}

class DiagnosticTraceCollector(
    private val privacyMode: Boolean,
    private val entryLimitBytes: Int = DEFAULT_ENTRY_LIMIT_BYTES,
    private val runLimitBytes: Int = DEFAULT_RUN_LIMIT_BYTES,
) {
    private val lock = Any()
    private val entries = mutableListOf<DiagnosticEntry>()
    private var storedBytes = 0
    private var closed = false
    private var runTruncated = false

    fun record(
        category: String,
        source: String,
        target: String? = null,
        status: String,
        durationMs: Long? = null,
        body: String = "",
    ) {
        val safeCategory = DiagnosticSanitizer.sanitize(category, privacyMode)
        val safeSource = DiagnosticSanitizer.sanitize(source, privacyMode)
        val safeTarget = target?.let { DiagnosticSanitizer.sanitize(it, privacyMode) }
        val safeStatus = DiagnosticSanitizer.sanitize(status, privacyMode)
        val safeBody = DiagnosticSanitizer.sanitize(body, privacyMode)
        val metadataBytes = listOfNotNull(safeCategory, safeSource, safeTarget, safeStatus)
            .sumOf { it.toByteArray(StandardCharsets.UTF_8).size }
        val originalBodyBytes = safeBody.toByteArray(StandardCharsets.UTF_8).size
        val originalBytes = metadataBytes + originalBodyBytes

        synchronized(lock) {
            if (closed) return
            val available = (runLimitBytes - storedBytes).coerceAtLeast(0)
            val allowed = minOf(entryLimitBytes.coerceAtLeast(0), available)
            if (allowed < metadataBytes) {
                runTruncated = true
                return
            }
            val storedBody = truncateUtf8(safeBody, allowed - metadataBytes)
            val bodyBytes = storedBody.toByteArray(StandardCharsets.UTF_8).size
            val entryBytes = metadataBytes + bodyBytes
            val truncated = bodyBytes < originalBodyBytes
            storedBytes += entryBytes
            runTruncated = runTruncated || truncated
            entries += DiagnosticEntry(
                category = safeCategory,
                source = safeSource,
                target = safeTarget,
                status = safeStatus,
                durationMs = durationMs?.coerceAtLeast(0),
                body = storedBody,
                storedBytes = entryBytes,
                originalBytes = originalBytes,
                truncated = truncated,
            )
        }
    }

    fun snapshot(): DiagnosticSnapshot = synchronized(lock) {
        closed = true
        DiagnosticSnapshot(
            entries = entries.sortedWith(
                compareBy<DiagnosticEntry>(
                    DiagnosticEntry::category,
                    DiagnosticEntry::source,
                    { it.target.orEmpty() },
                    DiagnosticEntry::status,
                    DiagnosticEntry::body,
                ),
            ),
            storedBytes = storedBytes,
            truncated = runTruncated,
        )
    }

    fun clear() = synchronized(lock) {
        entries.clear()
        storedBytes = 0
        runTruncated = false
        closed = true
    }

    companion object {
        const val DEFAULT_ENTRY_LIMIT_BYTES = 64 * 1024
        const val DEFAULT_RUN_LIMIT_BYTES = 512 * 1024

        private fun truncateUtf8(value: String, maxBytes: Int): String {
            if (maxBytes <= 0 || value.isEmpty()) return ""
            if (value.toByteArray(StandardCharsets.UTF_8).size <= maxBytes) return value
            var used = 0
            var index = 0
            while (index < value.length) {
                val codePoint = value.codePointAt(index)
                val charCount = Character.charCount(codePoint)
                val byteCount = String(Character.toChars(codePoint))
                    .toByteArray(StandardCharsets.UTF_8)
                    .size
                if (used + byteCount > maxBytes) break
                used += byteCount
                index += charCount
            }
            return value.substring(0, index)
        }
    }
}

object DiagnosticSanitizer {
    private const val REDACTED = "[REDACTED]"
    private const val IPV4_REDACTED = "[IPv4 redacted]"
    private const val IPV6_REDACTED = "[IPv6 redacted]"

    private val sensitiveHeader = Regex(
        "(?im)^(\\s*)(authorization|proxy-authorization|cookie|set-cookie)(\\s*:\\s*).*$",
    )
    private val bearerOrBasic = Regex("(?i)\\b(Bearer|Basic)\\s+[A-Za-z0-9._~+/=-]+")
    private val sensitiveQuery = Regex(
        "(?i)([?&](?:token|key|api[_-]?key|password|secret|auth|authorization|signature|session|cookie)=)[^&#\\s]+",
    )
    private val sensitiveQuotedAssignment = Regex(
        "(?i)([\\\"']?(?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|password|passwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|key|secret|private[_-]?key|public[_-]?key|uuid|bssid|cell[_-]?(?:id|identity))[\\\"']?\\s*[:=]\\s*)([\\\"'])(.*?)\\2",
    )
    private val sensitiveAssignment = Regex(
        "(?i)([\\\"']?(?:authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|password|passwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|key|secret|private[_-]?key|public[_-]?key|uuid|bssid|cell[_-]?(?:id|identity))[\\\"']?\\s*[:=]\\s*)([\\\"']?)[^,;\\s&}\\\"']+([\\\"']?)",
    )
    private val uriUserInfo = Regex("(?i)([a-z][a-z0-9+.-]*://)[^/@\\s]+@")
    private val uuid = Regex("(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b")
    private val pem = Regex("(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----")
    private val macAddress = Regex("(?i)\\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\\b")
    private val ipv4 = Regex("(?<![A-Za-z0-9])(?:\\d{1,3}\\.){3}\\d{1,3}(?![A-Za-z0-9])")
    private val ipv6 = Regex("(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}(?![A-Za-z0-9])")

    fun sanitize(value: String, privacyMode: Boolean): String {
        var safe = sensitiveHeader.replace(value) { match ->
            "${match.groupValues[1]}${match.groupValues[2]}${match.groupValues[3]}$REDACTED"
        }
        safe = bearerOrBasic.replace(safe) { "${it.groupValues[1]} $REDACTED" }
        safe = sensitiveQuery.replace(safe) { "${it.groupValues[1]}$REDACTED" }
        safe = sensitiveQuotedAssignment.replace(safe) { "${it.groupValues[1]}$REDACTED" }
        safe = sensitiveAssignment.replace(safe) { "${it.groupValues[1]}$REDACTED" }
        safe = uriUserInfo.replace(safe) { "${it.groupValues[1]}$REDACTED@" }
        safe = uuid.replace(safe, REDACTED)
        safe = pem.replace(safe, REDACTED)
        safe = macAddress.replace(safe, REDACTED)
        if (privacyMode) {
            safe = ipv4.replace(safe, IPV4_REDACTED)
            safe = ipv6.replace(safe, IPV6_REDACTED)
        }
        return safe
    }
}
