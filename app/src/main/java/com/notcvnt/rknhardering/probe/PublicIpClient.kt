package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.NativeCurlHttpClient
import com.notcvnt.rknhardering.network.ResolverBinding
import com.notcvnt.rknhardering.network.ResolverHttpRequest
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Proxy
import java.net.URL

object PublicIpClient {
    private enum class TransportPolicy {
        DEFAULT,
        NATIVE_CURL_ONLY,
    }

    @Volatile
    internal var fetchIpOverride: ((String, Int, Proxy?, DnsResolverConfig, ResolverBinding?) -> Result<String>)? = null

    data class DnsRecords(
        val ipv4Records: List<String> = emptyList(),
        val ipv6Records: List<String> = emptyList(),
    )

    private const val USER_AGENT = "curl/8.0"
    private val HTML_TAG_REGEX = Regex("""<\s*(?:!doctype|html|head|body)\b""", RegexOption.IGNORE_CASE)
    private val HTML_SCRIPT_REGEX = Regex("""(?is)<script\b.*?</script>""")
    private val HTML_STYLE_REGEX = Regex("""(?is)<style\b.*?</style>""")
    private val HTML_TAG_STRIP_REGEX = Regex("""(?is)<[^>]+>""")
    private val JSON_IP_REGEX = Regex(""""ip"\s*:\s*"([^"]+)"""")
    private val MAIL_RU_IP_REGEX = Regex("""(?i)\bip:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b""")

    fun fetchIp(
        endpoint: String,
        timeoutMs: Int = 7000,
        proxy: Proxy? = null,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        binding: ResolverBinding? = null,
    ): Result<String> {
        fetchIpOverride?.let { return it(endpoint, timeoutMs, proxy, resolverConfig, binding) }
        return try {
            val request = ResolverHttpRequest(
                url = endpoint,
                method = "GET",
                headers = mapOf(
                    "User-Agent" to USER_AGENT,
                    "Accept" to "text/plain",
                ),
                body = null,
                bodyContentType = null,
                timeoutMs = timeoutMs,
                config = resolverConfig,
                proxy = proxy,
                binding = binding,
            )
            val response = executeRequest(request)
            val code = response.code
            if (code !in 200..299) {
                return Result.failure(
                    IOException(formatHttpError(code, response.body)),
                )
            }

            val body = response.body.trim()
            if (body.isBlank()) {
                return Result.failure(IOException("Empty response body"))
            }
            val ip = extractIp(body, endpoint = endpoint)
                ?: return Result.failure(IOException("Response does not look like an IP: $body"))
            if (!looksLikeIp(ip)) {
                return Result.failure(IOException("Response does not look like an IP: $ip"))
            }
            Result.success(ip)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    internal fun extractIp(body: String, endpoint: String? = null): String? {
        val trimmed = body.trim()
        JSON_IP_REGEX.find(trimmed)?.groupValues?.getOrNull(1)?.trim()
            ?.takeIf(::looksLikeIp)
            ?.let { return it }
        val candidate = trimmed
            .lineSequence()
            .map { it.trim() }
            .firstOrNull()
            ?.removeSurrounding("\"")
            ?.trim()
            .orEmpty()
        if (!candidate.isBlank() && looksLikeIp(candidate)) return candidate
        return extractMailRuIp(trimmed, endpoint)
    }

    internal fun formatHttpError(code: Int, body: String): String {
        val trimmedBody = body.trim()
        if (trimmedBody.isBlank() || looksLikeHtml(trimmedBody)) {
            return "HTTP $code"
        }

        val firstLine = trimmedBody
            .lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() }
            .orEmpty()

        if (firstLine.isBlank() || firstLine.length > 160) {
            return "HTTP $code"
        }

        return "HTTP $code: $firstLine"
    }

    fun resolveDnsRecords(
        endpoint: String,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        binding: ResolverBinding? = null,
    ): DnsRecords {
        return try {
            val host = java.net.URL(endpoint).host
            val allAddresses = ResolverNetworkStack.lookup(host, resolverConfig, binding)
            DnsRecords(
                ipv4Records = allAddresses
                    .filterIsInstance<Inet4Address>()
                    .mapNotNull { it.hostAddress }
                    .distinct(),
                ipv6Records = allAddresses
                    .filterIsInstance<Inet6Address>()
                    .mapNotNull { it.hostAddress }
                    .distinct(),
            )
        } catch (_: Exception) {
            DnsRecords()
        }
    }

    private fun looksLikeIp(text: String): Boolean {
        if (text.length > 45) return false
        return text.matches(Regex("""[\d.:a-fA-F]+"""))
    }

    private fun looksLikeHtml(body: String): Boolean {
        return HTML_TAG_REGEX.containsMatchIn(body)
    }

    private fun extractMailRuIp(body: String, endpoint: String?): String? {
        val host = endpoint
            ?.let { runCatching { URL(it).host.lowercase() }.getOrNull() }
            ?: return null
        if (host != "ip.mail.ru") return null

        val text = body
            .replace(HTML_SCRIPT_REGEX, " ")
            .replace(HTML_STYLE_REGEX, " ")
            .replace(HTML_TAG_STRIP_REGEX, " ")
            .replace("&nbsp;", " ")
            .replace(Regex("""\s+"""), " ")
            .trim()

        return MAIL_RU_IP_REGEX.find(text)?.groupValues?.getOrNull(1)?.takeIf(::looksLikeIp)
    }

    internal fun resetForTests() {
        fetchIpOverride = null
    }

    private fun executeRequest(request: ResolverHttpRequest) = when (transportPolicyFor(request.url)) {
        TransportPolicy.DEFAULT -> ResolverNetworkStack.execute(
            url = request.url,
            method = request.method,
            headers = request.headers,
            body = request.body,
            bodyContentType = request.bodyContentType,
            timeoutMs = request.timeoutMs,
            config = request.config,
            proxy = request.proxy,
            binding = request.binding,
        )
        TransportPolicy.NATIVE_CURL_ONLY -> {
            if (!NativeCurlHttpClient.canExecute(request)) {
                throw IOException("Native curl transport is unavailable")
            }
            NativeCurlHttpClient.execute(request)
        }
    }

    private fun transportPolicyFor(endpoint: String): TransportPolicy {
        val host = runCatching { URL(endpoint).host.lowercase() }.getOrDefault("")
        return when (host) {
            "ipv4-internet.yandex.net",
            "ipv6-internet.yandex.net" -> TransportPolicy.NATIVE_CURL_ONLY
            else -> TransportPolicy.DEFAULT
        }
    }
}
