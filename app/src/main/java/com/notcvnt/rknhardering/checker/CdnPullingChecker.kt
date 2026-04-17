package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.CdnPullingClient
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.security.cert.CertPathBuilderException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

object CdnPullingChecker {

    private const val MAX_FETCH_ATTEMPTS = 1
    private const val RETRY_DELAY_MS = 250L

    internal data class EndpointSpec(
        val label: String,
        val url: String,
        val kind: CdnPullingClient.TargetKind,
    )

    internal val ENDPOINTS = listOf(
        EndpointSpec(
            label = "redirector.googlevideo.com",
            url = "https://redirector.googlevideo.com/report_mapping?di=no",
            kind = CdnPullingClient.TargetKind.GOOGLEVIDEO_REPORT_MAPPING,
        ),
        EndpointSpec(
            label = "cloudflare.com",
            url = "https://www.cloudflare.com/cdn-cgi/trace",
            kind = CdnPullingClient.TargetKind.CLOUDFLARE_TRACE,
        ),
        EndpointSpec(
            label = "one.one.one.one",
            url = "https://one.one.one.one/cdn-cgi/trace",
            kind = CdnPullingClient.TargetKind.CLOUDFLARE_TRACE,
        ),
        EndpointSpec(
            label = "rutracker.org",
            url = "https://rutracker.org/cdn-cgi/trace",
            kind = CdnPullingClient.TargetKind.CLOUDFLARE_TRACE,
        ),
        EndpointSpec(
            label = "meduza.io",
            url = "https://meduza.io/cdn-cgi/trace",
            kind = CdnPullingClient.TargetKind.CLOUDFLARE_TRACE,
        ),
    )

    suspend fun check(
        context: Context,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        meduzaEnabled: Boolean = true,
    ): CdnPullingResult = withContext(Dispatchers.IO) {
        coroutineScope {
            val activeEndpoints = if (meduzaEnabled) ENDPOINTS else ENDPOINTS.filter { it.label != "meduza.io" }
            val responses = activeEndpoints.map { endpoint ->
                async {
                    val ipv4Deferred = async {
                        fetchBodyWithRetries(
                            endpoint = endpoint.url,
                            timeoutMs = timeoutMs,
                            resolverConfig = resolverConfig,
                            addressFamily = Inet4Address::class.java,
                        )
                    }
                    val ipv6Deferred = async {
                        fetchBodyWithRetries(
                            endpoint = endpoint.url,
                            timeoutMs = timeoutMs,
                            resolverConfig = resolverConfig,
                            addressFamily = Inet6Address::class.java,
                        )
                    }

                    val ipv4Result = ipv4Deferred.await()
                    val ipv6Result = ipv6Deferred.await()

                    val ipv4Raw = ipv4Result.getOrNull()
                    val ipv6Raw = ipv6Result.getOrNull()
                    val ipv4Parsed = ipv4Raw?.let { CdnPullingClient.parseBody(endpoint.kind, it) }
                    val ipv6Parsed = ipv6Raw?.let { CdnPullingClient.parseBody(endpoint.kind, it) }

                    val ipv4 = ipv4Parsed?.ip?.takeIf { CdnPullingClient.looksLikeIpv4(it) }
                    val ipv6 = ipv6Parsed?.ip?.takeIf { CdnPullingClient.looksLikeIpv6(it) }

                    val representativeParsed = ipv4Parsed?.takeIf { it.hasUsefulData }
                        ?: ipv6Parsed?.takeIf { it.hasUsefulData }
                    val representativeIp = ipv4 ?: ipv6 ?: representativeParsed?.ip
                    val rawBody = ipv4Raw ?: ipv6Raw
                    val ipv4Unavailable = ipv4 == null && ipv6 != null

                    val hasAnyBody = rawBody != null
                    val hasUsefulData = representativeParsed?.hasUsefulData == true
                    val error = when {
                        !hasAnyBody -> formatError(
                            context,
                            ipv4Result.exceptionOrNull() ?: ipv6Result.exceptionOrNull(),
                        )
                        hasUsefulData -> null
                        else -> context.getString(R.string.checker_cdn_pulling_error_unrecognized)
                    }

                    val ipv4ErrorMessage = when {
                        ipv4Result.isFailure -> ipv4Result.exceptionOrNull()?.let { formatError(context, it) }
                        ipv4 == null && ipv4Parsed?.ip != null ->
                            "server returned non-IPv4 address: ${ipv4Parsed.ip}"
                        ipv4 == null && ipv4Raw != null ->
                            "response did not contain an IPv4 address"
                        else -> null
                    }
                    val ipv6ErrorMessage = when {
                        ipv6Result.isFailure -> ipv6Result.exceptionOrNull()?.let { formatError(context, it) }
                        ipv6 == null && ipv6Parsed?.ip != null ->
                            "server returned non-IPv6 address: ${ipv6Parsed.ip}"
                        ipv6 == null && ipv6Raw != null ->
                            "response did not contain an IPv6 address"
                        else -> null
                    }

                    CdnPullingResponse(
                        targetLabel = endpoint.label,
                        url = endpoint.url,
                        ip = representativeIp,
                        ipv4 = ipv4,
                        ipv6 = ipv6,
                        ipv4Unavailable = ipv4Unavailable,
                        ipv4Error = ipv4ErrorMessage,
                        ipv6Error = ipv6ErrorMessage,
                        importantFields = representativeParsed?.importantFields.orEmpty(),
                        rawBody = rawBody,
                        error = error,
                    )
                }
            }.map { it.await() }
            evaluate(context, responses)
        }
    }

    internal suspend fun fetchBodyWithRetries(
        endpoint: String,
        timeoutMs: Int,
        resolverConfig: DnsResolverConfig,
        addressFamily: Class<out java.net.InetAddress>? = null,
        maxAttempts: Int = MAX_FETCH_ATTEMPTS,
        retryDelayMs: Long = RETRY_DELAY_MS,
        fetcher: (String, Int, DnsResolverConfig, Class<out java.net.InetAddress>?) -> Result<String> = { url, timeout, resolver, family ->
            CdnPullingClient.fetchBody(url, timeoutMs = timeout, resolverConfig = resolver, addressFamily = family)
        },
    ): Result<String> {
        val executionContext = ScanExecutionContext.currentOrDefault()
        var lastError: Throwable? = null
        repeat(maxAttempts.coerceAtLeast(1)) { attempt ->
            executionContext.throwIfCancelled()
            val result = fetcher(endpoint, timeoutMs, resolverConfig, addressFamily)
            if (result.isSuccess) {
                return result
            }
            lastError = result.exceptionOrNull() ?: lastError
            if (!shouldRetry(lastError)) {
                return Result.failure(lastError ?: IOException("All CDN pulling attempts failed"))
            }
            if (attempt < maxAttempts - 1 && retryDelayMs > 0) {
                delay(retryDelayMs)
            }
        }
        return Result.failure(lastError ?: IOException("All CDN pulling attempts failed"))
    }

    internal fun evaluate(
        context: Context,
        responses: List<CdnPullingResponse>,
    ): CdnPullingResult {
        val successfulResponses = responses.filter { it.ip != null || it.importantFields.isNotEmpty() }
        val successfulCount = successfulResponses.size

        val allIpv4s = successfulResponses.mapNotNull { it.ipv4 ?: it.ip?.takeIf { ip -> CdnPullingClient.looksLikeIpv4(ip) } }.distinct()
        val allIpv6s = successfulResponses.mapNotNull { it.ipv6 ?: it.ip?.takeIf { ip -> CdnPullingClient.looksLikeIpv6(ip) } }.distinct()
        val allIps = successfulResponses.mapNotNull { it.ip }.distinct()

        val allSuccessfulResponsesExposeIp = successfulResponses.isNotEmpty() && successfulResponses.all { it.ip != null }
        val hasError = successfulCount == 0
        val detected = successfulCount > 0

        val ipv4Conflict = allIpv4s.size > 1
        val ipv6Conflict = allIpv6s.size > 1
        val needsReview = detected && (
            successfulCount < responses.size ||
                ipv4Conflict ||
                ipv6Conflict ||
                !allSuccessfulResponsesExposeIp
        )

        val findings = buildFindings(successfulResponses, responses)

        val representativeIps = buildList {
            if (allIpv4s.size == 1) add(allIpv4s.single())
            else addAll(allIpv4s)
            if (allIpv6s.size == 1) add(allIpv6s.single())
            else addAll(allIpv6s)
        }.distinct()

        val ipsFormatted = buildString {
            if (allIpv4s.isNotEmpty()) append("IPv4: ${allIpv4s.joinToString(", ")}")
            if (allIpv4s.isNotEmpty() && allIpv6s.isNotEmpty()) append("; ")
            if (allIpv6s.isNotEmpty()) append("IPv6: ${allIpv6s.joinToString(", ")}")
        }.ifEmpty { representativeIps.joinToString(", ") }

        val summary = when {
            hasError -> context.getString(R.string.checker_cdn_pulling_summary_error)
            ipv4Conflict || ipv6Conflict -> context.getString(
                R.string.checker_cdn_pulling_summary_mixed_ips,
                ipsFormatted,
            )
            successfulCount == responses.size && allSuccessfulResponsesExposeIp && representativeIps.isNotEmpty() -> context.getString(
                R.string.checker_cdn_pulling_summary_detected_full,
                ipsFormatted,
            )
            allSuccessfulResponsesExposeIp && representativeIps.size == 1 -> context.getString(
                R.string.checker_cdn_pulling_summary_detected_partial,
                representativeIps.single(),
                successfulCount,
                responses.size,
            )
            allSuccessfulResponsesExposeIp && representativeIps.isNotEmpty() -> context.getString(
                R.string.checker_cdn_pulling_summary_detected_full,
                ipsFormatted,
            )
            else -> context.getString(
                R.string.checker_cdn_pulling_summary_detected_no_ip,
                successfulCount,
                responses.size,
            )
        }

        return CdnPullingResult(
            detected = detected,
            needsReview = needsReview,
            hasError = hasError,
            summary = summary,
            responses = responses,
            findings = findings,
        )
    }

    private fun buildFindings(
        successfulResponses: List<CdnPullingResponse>,
        allResponses: List<CdnPullingResponse>,
    ): List<Finding> {
        val findings = mutableListOf<Finding>()
        successfulResponses.forEach { response ->
            val fieldsSummary = response.importantFields.entries
                .filterNot { response.ip != null && it.key.equals("IP", ignoreCase = true) }
                .joinToString(", ") { "${it.key}: ${it.value}" }
            val suffix = when {
                response.ip != null && fieldsSummary.isNotBlank() -> "IP: ${response.ip}, $fieldsSummary"
                response.ip != null -> "IP: ${response.ip}"
                else -> fieldsSummary
            }
            findings += Finding(
                description = "${response.targetLabel}: $suffix",
                detected = true,
                isInformational = true,
                confidence = EvidenceConfidence.MEDIUM,
            )
        }
        allResponses.filter { it.error != null }.forEach { response ->
            findings += Finding(
                description = "${response.targetLabel}: ${response.error}",
                needsReview = successfulResponses.isNotEmpty(),
                isError = successfulResponses.isEmpty(),
                confidence = EvidenceConfidence.LOW,
            )
        }
        return findings
    }

    internal fun formatError(context: Context, error: Throwable?): String {
        val message = error?.message?.trim().orEmpty()
        if (isTlsCertificateError(error)) {
            val friendlyMessage = context.getString(R.string.checker_cdn_pulling_error_tls_certificate)
            val details = tlsCertificateErrorDetails(error).ifBlank { message }
            return if (details.isBlank()) friendlyMessage else {
                "$friendlyMessage ${context.getString(R.string.checker_cdn_pulling_error_details, details)}"
            }
        }
        if (message.isNotBlank()) return message
        return when (error) {
            is IOException -> "Network error"
            null -> "Unknown error"
            else -> error::class.java.simpleName
        }
    }

    internal fun shouldRetry(error: Throwable?): Boolean {
        return error != null && !isTlsCertificateError(error)
    }

    internal fun isTlsCertificateError(error: Throwable?): Boolean {
        if (error == null) return false
        return errorCauseSequence(error).any { cause ->
            cause is CertPathValidatorException ||
                cause is CertPathBuilderException ||
                cause is CertificateException ||
                cause is SSLPeerUnverifiedException ||
                cause is SSLHandshakeException && containsTlsCertificateKeywords(cause.message) ||
                containsTlsCertificateKeywords(cause.message)
        }
    }

    private fun tlsCertificateErrorDetails(error: Throwable?): String {
        if (error == null) return ""
        return errorCauseSequence(error)
            .mapNotNull { cause ->
                cause.message
                    ?.trim()
                    ?.takeIf {
                        cause is CertPathValidatorException ||
                            cause is CertPathBuilderException ||
                            cause is CertificateException ||
                            cause is SSLPeerUnverifiedException ||
                            containsTlsCertificateKeywords(it)
                    }
            }
            .firstOrNull()
            .orEmpty()
    }

    private fun errorCauseSequence(error: Throwable): Sequence<Throwable> {
        return generateSequence(error) { current ->
            current.cause?.takeIf { it !== current }
        }
    }

    private fun containsTlsCertificateKeywords(message: String?): Boolean {
        val normalized = message?.trim()?.lowercase().orEmpty()
        if (normalized.isBlank()) return false
        return normalized.contains("trust anchor") ||
            normalized.contains("certpath") ||
            normalized.contains("certificate path") ||
            normalized.contains("path building failed") ||
            normalized.contains("peer not authenticated") ||
            normalized.contains("hostname") && normalized.contains("not verified")
    }
}
