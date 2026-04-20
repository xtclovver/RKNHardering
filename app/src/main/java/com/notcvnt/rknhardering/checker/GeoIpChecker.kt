package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.rethrowIfCancellation
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.GeoIpFacts
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject

object GeoIpChecker {

    private const val MAX_FETCH_ATTEMPTS = 1
    private const val RETRY_DELAY_MS = 250L
    private const val GEOIP_TIMEOUT_MS = 10_000

    internal data class GeoIpSnapshot(
        val ip: String,
        val country: String,
        val countryCode: String,
        val isp: String,
        val org: String,
        val asn: String,
        val isProxy: Boolean,
        val isHosting: Boolean,
        val hostingVotes: Int,
        val hostingChecks: Int,
        val hostingSources: List<String>,
    )

    internal data class ProviderSnapshot(
        val provider: String,
        val snapshot: GeoIpSnapshot,
    )

    private const val IPAPIIS_PROVIDER = "ipapi.is"
    private const val IPLOCATE_PROVIDER = "iplocate.io"

    private const val IPAPIIS_URL = "https://api.ipapi.is/"

    private const val IPLOCATE_URL = "https://www.iplocate.io/api/lookup"

    suspend fun check(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): CategoryResult = withContext(Dispatchers.IO) {
        val executionContext = ScanExecutionContext.currentOrDefault()
        try {
            coroutineScope {
                val ipapiIsDeferred = async { fetchWithRetries { fetchIpapiIs(resolverConfig) } }
                val iplocateDeferred = async { fetchWithRetries { fetchIplocate(resolverConfig) } }

                val ipapiIsResult = ipapiIsDeferred.await()
                val iplocateResult = iplocateDeferred.await()

                val providers = listOfNotNull(ipapiIsResult, iplocateResult)
                val baseProvider = ipapiIsResult ?: iplocateResult
                    ?: return@coroutineScope noProviderResult(
                        context.getString(R.string.checker_geo_error_no_provider),
                    )

                evaluate(
                    context = context,
                    snapshot = mergeSnapshots(
                        baseProvider = baseProvider,
                        providers = providers,
                    ),
                )
            }
        } catch (e: Exception) {
            rethrowIfCancellation(e, executionContext)
            errorResult(context.getString(R.string.checker_geo_error_fetch, e.message))
        }
    }

    internal suspend fun <T> fetchWithRetries(
        maxAttempts: Int = MAX_FETCH_ATTEMPTS,
        retryDelayMs: Long = RETRY_DELAY_MS,
        fetcher: suspend () -> T?,
    ): T? {
        repeat(maxAttempts.coerceAtLeast(1)) { attempt ->
            try {
                val result = fetcher()
                if (result != null) {
                    return result
                }
            } catch (error: Exception) {
                rethrowIfCancellation(error)
                // Ignore transient provider errors and retry the next attempt.
            }
            if (attempt < maxAttempts - 1 && retryDelayMs > 0) {
                delay(retryDelayMs)
            }
        }
        return null
    }

    private fun fetchIpapiIs(resolverConfig: DnsResolverConfig): ProviderSnapshot? {
        return try {
            val json = fetchJson(IPAPIIS_URL, resolverConfig)
            if (!json.has("ip")) return null

            val location = json.optJSONObject("location")
            val company = json.optJSONObject("company")
            val datacenter = json.optJSONObject("datacenter")
            val asn = json.optJSONObject("asn")

            ProviderSnapshot(
                provider = IPAPIIS_PROVIDER,
                snapshot = GeoIpSnapshot(
                    ip = firstMeaningful(json.optString("ip"), default = "N/A"),
                    country = firstMeaningful(location?.optString("country"), default = "N/A"),
                    countryCode = firstMeaningful(location?.optString("country_code"), default = ""),
                    isp = firstMeaningful(
                        company?.optString("name"),
                        asn?.optString("org"),
                        datacenter?.optString("datacenter"),
                        asn?.optString("descr"),
                        default = "N/A",
                    ),
                    org = firstMeaningful(
                        datacenter?.optString("datacenter"),
                        company?.optString("name"),
                        asn?.optString("org"),
                        asn?.optString("descr"),
                        default = "N/A",
                    ),
                    asn = formatAsn(
                        code = asn?.opt("asn")?.toString(),
                        name = firstMeaningful(
                            asn?.optString("org"),
                            asn?.optString("descr"),
                            default = "N/A",
                        ),
                    ),
                    isProxy = json.optBoolean("is_proxy", false) ||
                        json.optBoolean("is_vpn", false) ||
                        json.optBoolean("is_tor", false),
                    isHosting = json.optBoolean("is_datacenter", false),
                    hostingVotes = 0,
                    hostingChecks = 0,
                    hostingSources = emptyList(),
                ),
            )
        } catch (error: Exception) {
            rethrowIfCancellation(error)
            null
        }
    }

    private fun fetchIplocate(resolverConfig: DnsResolverConfig): ProviderSnapshot? {
        return try {
            val json = fetchJson(IPLOCATE_URL, resolverConfig)
            if (!json.has("ip")) return null

            val privacy = json.optJSONObject("privacy")
            val company = json.optJSONObject("company")
            val hosting = json.optJSONObject("hosting")
            val asn = json.optJSONObject("asn")

            ProviderSnapshot(
                provider = IPLOCATE_PROVIDER,
                snapshot = GeoIpSnapshot(
                    ip = firstMeaningful(json.optString("ip"), default = "N/A"),
                    country = firstMeaningful(json.optString("country"), default = "N/A"),
                    countryCode = firstMeaningful(json.optString("country_code"), default = ""),
                    isp = firstMeaningful(
                        company?.optString("name"),
                        asn?.optString("name"),
                        hosting?.optString("provider"),
                        default = "N/A",
                    ),
                    org = firstMeaningful(
                        hosting?.optString("provider"),
                        company?.optString("name"),
                        asn?.optString("name"),
                        default = "N/A",
                    ),
                    asn = formatAsn(
                        code = asn?.optString("asn"),
                        name = firstMeaningful(asn?.optString("name"), default = "N/A"),
                    ),
                    isProxy = (privacy?.optBoolean("is_proxy", false) == true) ||
                        (privacy?.optBoolean("is_vpn", false) == true) ||
                        (privacy?.optBoolean("is_tor", false) == true),
                    isHosting = privacy?.optBoolean("is_hosting", false) == true,
                    hostingVotes = 0,
                    hostingChecks = 0,
                    hostingSources = emptyList(),
                ),
            )
        } catch (error: Exception) {
            rethrowIfCancellation(error)
            null
        }
    }

    private fun fetchJson(url: String, resolverConfig: DnsResolverConfig): JSONObject {
        val executionContext = ScanExecutionContext.currentOrDefault()
        val response = ResolverNetworkStack.execute(
            url = url,
            method = "GET",
            timeoutMs = GEOIP_TIMEOUT_MS,
            config = resolverConfig,
            cancellationSignal = executionContext.cancellationSignal,
        )
        if (response.code !in 200..299) {
            throw IllegalStateException("HTTP ${response.code}")
        }
        return JSONObject(response.body)
    }

    internal fun mergeSnapshots(
        baseProvider: ProviderSnapshot,
        providers: List<ProviderSnapshot>,
    ): GeoIpSnapshot {
        val compatibleProviders = providers.filter {
            isCompatibleIp(
                expectedIp = baseProvider.snapshot.ip,
                candidateIp = it.snapshot.ip,
            )
        }

        val orderedForFill = buildList {
            add(baseProvider)
            compatibleProviders
                .filterNot { it.provider == baseProvider.provider }
                .forEach(::add)
        }

        val hostingVotes = compatibleProviders.count { it.snapshot.isHosting }
        val hostingChecks = compatibleProviders.size
        val hostingSources = compatibleProviders
            .filter { it.snapshot.isHosting }
            .map { it.provider }

        return GeoIpSnapshot(
            ip = pickField(orderedForFill) { it.snapshot.ip },
            country = pickField(orderedForFill) { it.snapshot.country },
            countryCode = pickField(orderedForFill, default = "") { it.snapshot.countryCode },
            isp = pickField(orderedForFill) { it.snapshot.isp },
            org = pickField(orderedForFill) { it.snapshot.org },
            asn = pickField(orderedForFill) { it.snapshot.asn },
            isProxy = resolveProxy(
                compatibleProviders = compatibleProviders,
            ),
            isHosting = hostingVotes > hostingChecks / 2,
            hostingVotes = hostingVotes,
            hostingChecks = hostingChecks,
            hostingSources = hostingSources,
        )
    }

    internal fun evaluate(context: Context, snapshot: GeoIpSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        findings.add(Finding(context.getString(R.string.checker_geo_info_ip, snapshot.ip), isInformational = true))
        findings.add(Finding(context.getString(R.string.checker_geo_info_country, snapshot.country, snapshot.countryCode), isInformational = true))
        findings.add(Finding(context.getString(R.string.checker_geo_info_isp, snapshot.isp), isInformational = true))
        findings.add(Finding(context.getString(R.string.checker_geo_info_org, snapshot.org), isInformational = true))
        findings.add(Finding(context.getString(R.string.checker_geo_info_asn, snapshot.asn), isInformational = true))

        val foreignIp = snapshot.countryCode.isNotEmpty() && snapshot.countryCode != "RU"
        val needsReview = foreignIp && !snapshot.isHosting && !snapshot.isProxy
        val foreignIpDesc = if (foreignIp) {
            context.getString(R.string.checker_geo_foreign_ip_yes, snapshot.countryCode)
        } else {
            context.getString(R.string.checker_geo_foreign_ip_no)
        }
        findings.add(
            Finding(
                description = foreignIpDesc,
                needsReview = needsReview,
                source = EvidenceSource.GEO_IP,
                confidence = needsReview.takeIf { it }?.let { EvidenceConfidence.LOW },
            ),
        )

        val yesStr = context.getString(R.string.checker_yes)
        val noStr = context.getString(R.string.checker_no)
        val hostingDesc = buildString {
            append(context.getString(R.string.checker_geo_hosting_prefix, if (snapshot.isHosting) yesStr else noStr))
            if (snapshot.hostingChecks > 0) {
                append(" (${snapshot.hostingVotes}/${snapshot.hostingChecks}")
                if (snapshot.hostingSources.isNotEmpty()) {
                    append(": ")
                    append(snapshot.hostingSources.joinToString(", "))
                }
                append(")")
            }
        }
        addGeoFinding(
            findings = findings,
            evidence = evidence,
            description = hostingDesc,
            detected = snapshot.isHosting,
        )
        addGeoFinding(
            findings = findings,
            evidence = evidence,
            description = context.getString(R.string.checker_geo_proxy_db, if (snapshot.isProxy) yesStr else noStr),
            detected = snapshot.isProxy,
        )

        val countryCode = snapshot.countryCode.uppercase().ifBlank { null }
        val outsideRu = countryCode != null && countryCode != "RU"
        val geoFacts = GeoIpFacts(
            ip = snapshot.ip.takeUnless { it.isBlank() || it == "N/A" },
            countryCode = countryCode,
            asn = snapshot.asn.takeUnless { it.isBlank() || it == "N/A" },
            outsideRu = outsideRu,
            hosting = snapshot.isHosting,
            proxyDb = snapshot.isProxy,
            fetchError = false,
        )
        return CategoryResult(
            name = "GeoIP",
            detected = snapshot.isHosting || snapshot.isProxy,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
            geoFacts = geoFacts,
        )
    }

    private fun errorResult(message: String): CategoryResult {
        return CategoryResult(
            name = "GeoIP",
            detected = false,
            findings = listOf(Finding(message, isError = true)),
            geoFacts = GeoIpFacts(fetchError = true),
        )
    }

    internal fun noProviderResult(message: String): CategoryResult {
        return CategoryResult(
            name = "GeoIP",
            detected = false,
            findings = listOf(Finding(message)),
            geoFacts = GeoIpFacts(fetchError = true),
        )
    }

    private fun addGeoFinding(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
        description: String,
        detected: Boolean,
    ) {
        findings.add(
            Finding(
                description = description,
                detected = detected,
                source = EvidenceSource.GEO_IP,
                confidence = detected.takeIf { it }?.let { EvidenceConfidence.MEDIUM },
            ),
        )
        if (detected) {
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.GEO_IP,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = description,
                ),
            )
        }
    }

    private fun resolveProxy(compatibleProviders: List<ProviderSnapshot>): Boolean {
        return compatibleProviders.any { it.snapshot.isProxy }
    }

    private fun pickField(
        providers: List<ProviderSnapshot>,
        default: String = "N/A",
        selector: (ProviderSnapshot) -> String,
    ): String {
        return providers
            .asSequence()
            .map(selector)
            .firstOrNull(::isMeaningfulField)
            ?: default
    }

    private fun isCompatibleIp(expectedIp: String, candidateIp: String): Boolean {
        if (!isMeaningfulField(expectedIp) || !isMeaningfulField(candidateIp)) {
            return true
        }
        return expectedIp.equals(candidateIp, ignoreCase = true)
    }

    private fun formatAsn(code: String?, name: String?): String {
        val normalizedCode = code
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
        val normalizedName = name
            ?.trim()
            ?.takeIf(::isMeaningfulField)

        if (normalizedCode == null) {
            return normalizedName ?: "N/A"
        }

        val asnCode = if (normalizedCode.startsWith("AS", ignoreCase = true)) {
            normalizedCode.uppercase()
        } else {
            "AS$normalizedCode"
        }
        return normalizedName?.let { "$asnCode $it" } ?: asnCode
    }

    private fun firstMeaningful(vararg candidates: String?, default: String): String {
        return candidates.firstOrNull(::isMeaningfulField)?.trim() ?: default
    }

    private fun isMeaningfulField(value: String?): Boolean {
        return !value.isNullOrBlank() && !value.equals("N/A", ignoreCase = true)
    }
}
