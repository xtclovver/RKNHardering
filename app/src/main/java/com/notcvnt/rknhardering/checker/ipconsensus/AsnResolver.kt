package com.notcvnt.rknhardering.checker.ipconsensus

import com.notcvnt.rknhardering.model.AsnInfo
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

class AsnResolver(
    private val maxIps: Int = DEFAULT_MAX_IPS,
    private val batchTimeoutMs: Long = BATCH_TIMEOUT_MS,
    private val perRequestTimeoutMs: Long = PER_REQUEST_TIMEOUT_MS,
    private val lookup: suspend (String) -> AsnInfo?,
) {

    private val cache = ConcurrentHashMap<String, AsnInfo?>()

    suspend fun resolveAll(ips: Set<String>): Map<String, AsnInfo?> = coroutineScope {
        val deduped = ips.distinct().take(maxIps)
        val results = withTimeoutOrNull(batchTimeoutMs) {
            deduped.map { ip ->
                async {
                    ip to resolveOne(ip)
                }
            }.awaitAll()
        } ?: emptyList()
        results.toMap()
    }

    private suspend fun resolveOne(ip: String): AsnInfo? {
        cache[ip]?.let { return it }
        val result = withTimeoutOrNull(perRequestTimeoutMs) { lookup(ip) }
        if (result != null) cache[ip] = result
        return result
    }

    companion object {
        const val DEFAULT_MAX_IPS = 6
        const val BATCH_TIMEOUT_MS = 5_000L
        const val PER_REQUEST_TIMEOUT_MS = 3_000L

        fun default(resolverConfig: DnsResolverConfig): AsnResolver {
            return AsnResolver(
                lookup = { ip -> lookupViaIpapiIs(ip, resolverConfig) },
            )
        }

        private fun lookupViaIpapiIs(ip: String, resolverConfig: DnsResolverConfig): AsnInfo? {
            return try {
                val url = "https://api.ipapi.is/?q=$ip"
                val response = ResolverNetworkStack.execute(
                    url = url,
                    method = "GET",
                    timeoutMs = PER_REQUEST_TIMEOUT_MS.toInt(),
                    config = resolverConfig,
                    cancellationSignal = null,
                )
                if (response.code !in 200..299) return null
                val json = JSONObject(response.body)
                val asnObj = json.optJSONObject("asn")
                val location = json.optJSONObject("location")
                val asnCode = asnObj?.opt("asn")?.toString()
                val asnName = asnObj?.optString("org")?.takeIf { it.isNotBlank() }
                val asnPretty = when {
                    asnCode == null -> asnName
                    asnName == null -> "AS$asnCode"
                    else -> "AS$asnCode $asnName"
                }
                val country = location?.optString("country_code")
                    ?.takeIf { it.isNotBlank() }
                    ?.uppercase()
                AsnInfo(asn = asnPretty, countryCode = country)
            } catch (_: Exception) {
                null
            }
        }
    }
}
