package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.PublicIpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.URL

object IpComparisonChecker {

    private const val MAX_FETCH_ATTEMPTS = 1
    private const val RETRY_DELAY_MS = 250L

    private enum class IpFamily {
        IPV4,
        IPV6,
    }

    private data class EndpointSpec(
        val label: String,
        val url: String,
        val scope: IpCheckerScope,
    )

    private val ENDPOINTS = listOf(
        EndpointSpec(
            label = "2ip.ru",
            url = "https://2ip.ru",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "Yandex IPv4",
            url = "https://ipv4-internet.yandex.net/api/v0/ip",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "Yandex IPv6",
            url = "https://ipv6-internet.yandex.net/api/v0/ip",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "sypexgeo.net",
            url = "https://api.sypexgeo.net/json/",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "mail.ru",
            url = "https://ip.mail.ru",
            scope = IpCheckerScope.RU,
        ),
        EndpointSpec(
            label = "ifconfig.me IPv4",
            url = "https://ipv4.ifconfig.me/ip",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ifconfig.me IPv6",
            url = "https://ipv6.ifconfig.me/ip",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "checkip.amazonaws.com",
            url = "https://checkip.amazonaws.com",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ipify",
            url = "https://api.ipify.org",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ip.sb IPv4",
            url = "https://api-ipv4.ip.sb/ip",
            scope = IpCheckerScope.NON_RU,
        ),
        EndpointSpec(
            label = "ip.sb IPv6",
            url = "https://api-ipv6.ip.sb/ip",
            scope = IpCheckerScope.NON_RU,
        ),
    )

    suspend fun check(
        context: Context,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): IpComparisonResult = withContext(Dispatchers.IO) {
        coroutineScope {
            val responses = ENDPOINTS.map { endpoint ->
                async {
                    val dnsRecords = PublicIpClient.resolveDnsRecords(endpoint.url, resolverConfig)
                    val result = fetchIpWithRetries(
                        endpoint = endpoint.url,
                        timeoutMs = timeoutMs,
                        resolverConfig = resolverConfig,
                    )
                    val error = result.exceptionOrNull()?.let(::formatError)
                    IpCheckerResponse(
                        label = endpoint.label,
                        url = endpoint.url,
                        scope = endpoint.scope,
                        ip = result.getOrNull(),
                        error = error,
                        ipv4Records = dnsRecords.ipv4Records,
                        ipv6Records = dnsRecords.ipv6Records,
                        ignoredIpv6Error = shouldIgnoreIpv6Error(
                            url = endpoint.url,
                            error = error,
                            dnsRecords = dnsRecords,
                        ),
                    )
                }
            }.map { it.await() }
            evaluate(context, responses)
        }
    }

    internal suspend fun fetchIpWithRetries(
        endpoint: String,
        timeoutMs: Int,
        resolverConfig: DnsResolverConfig,
        maxAttempts: Int = MAX_FETCH_ATTEMPTS,
        retryDelayMs: Long = RETRY_DELAY_MS,
        fetcher: (String, Int, DnsResolverConfig) -> Result<String> = { url, timeout, resolver ->
            PublicIpClient.fetchIp(url, timeout, resolverConfig = resolver)
        },
    ): Result<String> {
        var lastError: Throwable? = null
        repeat(maxAttempts.coerceAtLeast(1)) { attempt ->
            val result = fetcher(endpoint, timeoutMs, resolverConfig)
            if (result.isSuccess) {
                return result
            }
            lastError = result.exceptionOrNull() ?: lastError
            if (attempt < maxAttempts - 1 && retryDelayMs > 0) {
                delay(retryDelayMs)
            }
        }
        return Result.failure(lastError ?: IOException("All IP attempts failed"))
    }

    internal fun evaluate(context: Context, responses: List<IpCheckerResponse>): IpComparisonResult {
        val ruGroup = buildGroup(
            context = context,
            title = context.getString(R.string.checker_ip_comp_ru_checkers),
            responses = responses.filter { it.scope == IpCheckerScope.RU },
        )
        val nonRuGroup = buildGroup(
            context = context,
            title = context.getString(R.string.checker_ip_comp_non_ru_checkers),
            responses = responses.filter { it.scope == IpCheckerScope.NON_RU },
        )

        val fullConsensusAvailable = !ruGroup.needsReview &&
            !nonRuGroup.needsReview &&
            !ruGroup.detected &&
            !nonRuGroup.detected &&
            ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null

        val familyMismatch = ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null &&
            detectFamily(ruGroup.canonicalIp) != detectFamily(nonRuGroup.canonicalIp)

        val rawMismatch = ruGroup.canonicalIp != null &&
            nonRuGroup.canonicalIp != null &&
            !familyMismatch &&
            ruGroup.canonicalIp != nonRuGroup.canonicalIp

        val detected = fullConsensusAvailable && rawMismatch
        val needsReview = !detected && (
            ruGroup.detected ||
                nonRuGroup.detected ||
                ruGroup.needsReview ||
                nonRuGroup.needsReview ||
                familyMismatch ||
                rawMismatch
            )

        val summary = when {
            detected -> context.getString(R.string.checker_ip_comp_summary_detected, ruGroup.canonicalIp, nonRuGroup.canonicalIp)
            familyMismatch -> context.getString(R.string.checker_ip_comp_summary_family_mismatch, ruGroup.canonicalIp, nonRuGroup.canonicalIp)
            rawMismatch -> context.getString(R.string.checker_ip_comp_summary_raw_mismatch, ruGroup.canonicalIp, nonRuGroup.canonicalIp)
            ruGroup.ignoredIpv6ErrorCount > 0 || nonRuGroup.ignoredIpv6ErrorCount > 0 ->
                context.getString(R.string.checker_ip_comp_summary_ipv4_only, ruGroup.canonicalIp ?: nonRuGroup.canonicalIp)
            ruGroup.canonicalIp != null && nonRuGroup.canonicalIp != null ->
                context.getString(R.string.checker_ip_comp_summary_all_same, ruGroup.canonicalIp)
            ruGroup.canonicalIp == null && nonRuGroup.canonicalIp == null ->
                context.getString(R.string.checker_ip_comp_summary_no_response)
            else -> context.getString(R.string.checker_ip_comp_summary_incomplete)
        }

        return IpComparisonResult(
            detected = detected,
            needsReview = needsReview,
            summary = summary,
            ruGroup = ruGroup,
            nonRuGroup = nonRuGroup,
        )
    }

    private fun buildGroup(
        context: Context,
        title: String,
        responses: List<IpCheckerResponse>,
    ): IpCheckerGroupResult {
        if (responses.size == 1) {
            val response = responses.single()
            return if (response.ip != null) {
                IpCheckerGroupResult(
                    title = title,
                    detected = false,
                    needsReview = false,
                    statusLabel = context.getString(R.string.checker_ip_comp_status_has_response),
                    summary = context.getString(R.string.checker_ip_comp_single_ip, response.ip),
                    canonicalIp = response.ip,
                    responses = responses,
                )
            } else {
                IpCheckerGroupResult(
                    title = title,
                    detected = false,
                    needsReview = true,
                    statusLabel = context.getString(R.string.checker_ip_comp_status_no_response),
                    summary = response.error?.let { context.getString(R.string.checker_ip_comp_single_error, it) }
                        ?: context.getString(R.string.checker_ip_comp_single_no_answer),
                    responses = responses,
                )
            }
        }

        val successfulIps = responses.mapNotNull { it.ip }
        val uniqueIps = successfulIps.distinct()
        val noIpCount = responses.count { it.ip == null && !it.ignoredIpv6Error }
        val ignoredIpv6ErrorCount = responses.count { it.ip == null && it.ignoredIpv6Error }
        val families = successfulIps.mapNotNull(::detectFamily).distinct()

        return when {
            uniqueIps.isEmpty() && noIpCount > 0 -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = true,
                statusLabel = context.getString(R.string.checker_ip_comp_status_no_response),
                summary = context.getString(R.string.checker_ip_comp_no_ip_returned),
                responses = responses,
            )
            uniqueIps.isEmpty() -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = false,
                statusLabel = context.getString(R.string.checker_ip_comp_status_ipv6_ignored),
                summary = context.getString(R.string.checker_ip_comp_ipv6_ignored_no_ipv4),
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
            families.size > 1 -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = true,
                statusLabel = context.getString(R.string.checker_ip_comp_status_ipv4_ipv6),
                summary = context.getString(R.string.checker_ip_comp_mixed_families, uniqueIps.joinToString()),
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
            uniqueIps.size > 1 -> IpCheckerGroupResult(
                title = title,
                detected = true,
                needsReview = false,
                statusLabel = context.getString(R.string.checker_ip_comp_status_mismatch),
                summary = context.getString(R.string.checker_ip_comp_different_ips, uniqueIps.joinToString()),
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
            else -> IpCheckerGroupResult(
                title = title,
                detected = false,
                needsReview = false,
                statusLabel = context.getString(R.string.checker_ip_comp_status_match),
                summary = buildString {
                    append(context.getString(R.string.checker_ip_comp_all_same, uniqueIps.single()))
                    if (ignoredIpv6ErrorCount > 0) {
                        append(context.getString(R.string.checker_ip_comp_ipv6_ignored_suffix, ignoredIpv6ErrorCount))
                    }
                },
                canonicalIp = uniqueIps.single(),
                responses = responses,
                ignoredIpv6ErrorCount = ignoredIpv6ErrorCount,
            )
        }
    }

    private fun formatError(throwable: Throwable): String {
        val message = throwable.message?.trim().orEmpty()
        if (message.isNotBlank()) return message
        return when (throwable) {
            is IOException -> "Network error"
            else -> throwable::class.java.simpleName
        }
    }

    private fun detectFamily(ip: String?): IpFamily? {
        return when {
            ip == null -> null
            ip.contains(':') -> IpFamily.IPV6
            ip.contains('.') -> IpFamily.IPV4
            else -> null
        }
    }

    private fun shouldIgnoreIpv6Error(
        url: String,
        error: String?,
        dnsRecords: PublicIpClient.DnsRecords,
    ): Boolean {
        if (error.isNullOrBlank()) return false
        val host = try {
            URL(url).host.lowercase()
        } catch (_: Exception) {
            ""
        }
        if (host.contains("ipv6")) {
            return true
        }
        val normalizedError = error.lowercase()
        if (Regex("""\[[0-9a-f:]+]""").containsMatchIn(normalizedError)) {
            return true
        }
        if (normalizedError.contains("address family not supported")) {
            return true
        }
        if (normalizedError.contains("network is unreachable") && dnsRecords.ipv6Records.isNotEmpty()) {
            return true
        }
        if (normalizedError.contains("no route to host") && dnsRecords.ipv6Records.isNotEmpty()) {
            return true
        }
        return false
    }
}
