package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.rethrowIfCancellation
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address

object CdnPullingClient {

    private const val USER_AGENT = "curl/8.0"

    @Volatile
    internal var fetchBodyOverride: ((String, Int, DnsResolverConfig, ResolverBinding?, Class<out java.net.InetAddress>?) -> Result<String>)? = null

    enum class TargetKind {
        GOOGLEVIDEO_REPORT_MAPPING,
        CLOUDFLARE_TRACE,
    }

    data class ParsedBody(
        val ip: String? = null,
        val importantFields: Map<String, String> = emptyMap(),
    ) {
        val hasUsefulData: Boolean
            get() = ip != null || importantFields.isNotEmpty()
    }

    fun fetchBody(
        endpoint: String,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        binding: ResolverBinding? = null,
        addressFamily: Class<out java.net.InetAddress>? = null,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): Result<String> {
        fetchBodyOverride?.let { return it(endpoint, timeoutMs, resolverConfig, binding, addressFamily) }
        return try {
            executionContext.throwIfCancelled()
            val response = ResolverNetworkStack.execute(
                url = endpoint,
                method = "GET",
                headers = mapOf(
                    "User-Agent" to USER_AGENT,
                    "Accept" to "text/plain",
                ),
                timeoutMs = timeoutMs,
                config = resolverConfig,
                binding = binding,
                addressFamily = addressFamily,
                cancellationSignal = executionContext.cancellationSignal,
            )
            executionContext.throwIfCancelled()
            if (response.code !in 200..299) {
                return Result.failure(IOException(PublicIpClient.formatHttpError(response.code, response.body)))
            }
            val body = response.body.trim()
            if (body.isBlank()) {
                return Result.failure(IOException("Empty response body"))
            }
            Result.success(body)
        } catch (e: Exception) {
            rethrowIfCancellation(e, executionContext)
            Result.failure(e)
        }
    }

    internal fun parseBody(kind: TargetKind, body: String): ParsedBody? {
        return when (kind) {
            TargetKind.GOOGLEVIDEO_REPORT_MAPPING -> parseGooglevideoReportMapping(body)
            TargetKind.CLOUDFLARE_TRACE -> parseCloudflareTrace(body)
        }
    }

    internal fun parseGooglevideoReportMapping(body: String): ParsedBody? {
        val firstLine = body.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotBlank() }
            ?: return null
        val ipCandidate = firstLine.substringBefore("=>").trim().removeSuffix(":")
        if (!looksLikeIp(ipCandidate)) return null
        return ParsedBody(ip = ipCandidate)
    }

    internal fun parseCloudflareTrace(body: String): ParsedBody? {
        val fields = linkedMapOf<String, String>()
        body.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .forEach { line ->
                val separatorIndex = line.indexOf('=')
                if (separatorIndex <= 0 || separatorIndex == line.lastIndex) return@forEach
                val key = line.substring(0, separatorIndex).trim()
                val value = line.substring(separatorIndex + 1).trim()
                if (key.isNotBlank() && value.isNotBlank()) {
                    fields[key] = value
                }
            }
        if (fields.isEmpty()) return null
        val parsedIp = fields["ip"]?.takeIf(::looksLikeIp)
        return ParsedBody(
            ip = parsedIp,
            importantFields = buildMap {
                parsedIp?.let { put("IP", it) }
                fields["loc"]?.let { put("LOC", it) }
                fields["colo"]?.let { put("COLO", it) }
                fields["warp"]?.let { put("WARP", it) }
            },
        ).takeIf { it.hasUsefulData }
    }

    internal fun looksLikeIp(value: String): Boolean {
        if (value.isBlank() || value.length > 64) return false
        val normalized = value.trim()
        return when {
            ':' in normalized -> looksLikeIpv6Literal(normalized)
            '.' in normalized -> looksLikeIpv4Literal(normalized)
            else -> false
        }
    }

    internal fun looksLikeIpv4(value: String): Boolean {
        if (value.isBlank() || value.length > 64) return false
        return looksLikeIpv4Literal(value.trim())
    }

    internal fun looksLikeIpv6(value: String): Boolean {
        if (value.isBlank() || value.length > 64) return false
        val normalized = value.trim()
        return ':' in normalized && looksLikeIpv6Literal(normalized)
    }

    private fun looksLikeIpv4Literal(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4 || parts.any { it.isBlank() }) return false
        if (parts.any { it.length > 1 && it.startsWith('0') }) return false
        if (parts.any { part -> part.any { !it.isDigit() } }) return false
        if (parts.any { (it.toIntOrNull() ?: -1) !in 0..255 }) return false
        val parsed = runCatching { java.net.InetAddress.getByName(value) }.getOrNull() ?: return false
        return parsed is Inet4Address
    }

    private fun looksLikeIpv6Literal(value: String): Boolean {
        if (!value.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
            return false
        }
        val parsed = runCatching { java.net.InetAddress.getByName(value) }.getOrNull() ?: return false
        return parsed is Inet6Address
    }

    internal fun resetForTests() {
        fetchBodyOverride = null
    }
}
