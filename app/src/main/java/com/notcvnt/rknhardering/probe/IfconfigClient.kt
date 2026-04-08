package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object IfconfigClient {

    private val ENDPOINTS = listOf(
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
        "https://ipv4-internet.yandex.net/api/v0/ip",
        "https://ipv6-internet.yandex.net/api/v0/ip",
    )

    private const val USER_AGENT = "curl/8.0"

    suspend fun fetchDirectIp(timeoutMs: Int = 7000): Result<String> =
        fetchIpWithFallback(timeoutMs = timeoutMs)

    suspend fun fetchIpViaProxy(
        endpoint: ProxyEndpoint,
        timeoutMs: Int = 7000,
    ): Result<String> = fetchIpWithFallback(
        timeoutMs = timeoutMs,
        proxy = Proxy(
            when (endpoint.type) {
                ProxyType.SOCKS5 -> Proxy.Type.SOCKS
                ProxyType.HTTP -> Proxy.Type.HTTP
            },
            InetSocketAddress(endpoint.host, endpoint.port),
        ),
    )

    private suspend fun fetchIpWithFallback(
        timeoutMs: Int,
        proxy: Proxy? = null,
    ): Result<String> = withContext(Dispatchers.IO) {
        var lastError: Exception? = null
        for (ep in ENDPOINTS) {
            val result = fetchIp(ep, timeoutMs, proxy)
            if (result.isSuccess) return@withContext result
            lastError = result.exceptionOrNull() as? Exception ?: lastError
        }
        Result.failure(lastError ?: IOException("All IP endpoints failed"))
    }

    private fun fetchIp(
        endpoint: String,
        timeoutMs: Int,
        proxy: Proxy? = null,
    ): Result<String> {
        val url = URL(endpoint)
        val connection = if (proxy == null) url.openConnection() else url.openConnection(proxy)
        val https = connection as? HttpsURLConnection
            ?: return Result.failure(IllegalStateException("Not an HTTPS connection"))

        return try {
            https.instanceFollowRedirects = true
            https.requestMethod = "GET"
            https.useCaches = false
            https.connectTimeout = timeoutMs
            https.readTimeout = timeoutMs
            https.setRequestProperty("User-Agent", USER_AGENT)
            https.setRequestProperty("Accept", "text/plain")

            val code = https.responseCode
            if (code !in 200..299) {
                val errorText = https.errorStream?.bufferedReader()?.use { it.readText() }?.trim()
                return Result.failure(
                    IOException(
                        buildString {
                            append("HTTP ")
                            append(code)
                            if (!errorText.isNullOrBlank()) {
                                append(": ")
                                append(errorText)
                            }
                        },
                    ),
                )
            }

            val body = https.inputStream.bufferedReader().use { it.readText() }.trim()
            if (body.isBlank()) {
                return Result.failure(IOException("Empty response body"))
            }
            val ip = body.lines().first().trim()
            if (!looksLikeIp(ip)) {
                return Result.failure(IOException("Response does not look like an IP: $ip"))
            }
            Result.success(ip)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            https.disconnect()
        }
    }

    private fun looksLikeIp(text: String): Boolean {
        if (text.length > 45) return false
        return text.matches(Regex("""[\d.:a-fA-F]+"""))
    }
}
