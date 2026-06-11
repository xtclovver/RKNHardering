package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.rethrowIfCancellation
import com.notcvnt.rknhardering.customcheck.CustomGeoIpProvider
import com.notcvnt.rknhardering.customcheck.GeoIpConfig
import com.notcvnt.rknhardering.customcheck.mapper.EndpointResponseMapper
import com.notcvnt.rknhardering.customcheck.mapper.MappingField
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.GeoIpFacts
import com.notcvnt.rknhardering.model.GeoIpResponse
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URLEncoder

object GeoIpChecker {

    private const val MAX_FETCH_ATTEMPTS = 1
    private const val RETRY_DELAY_MS = 250L
    private const val GEOIP_TIMEOUT_MS = 10_000

    private fun isBuiltinEnabled(config: GeoIpConfig, providerName: String): Boolean {
        return config.builtinProviders[providerName] != false
    }

    private fun parseBooleanString(value: String?): Boolean {
        return value?.trim()?.lowercase() in setOf("true", "1", "yes")
    }

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
        val proxyVotes: Int = 0,
        val proxyChecks: Int = 0,
        val proxySources: List<String> = emptyList(),
    )

    internal data class ProviderSnapshot(
        val provider: String,
        val isCustom: Boolean,
        val snapshot: GeoIpSnapshot?,
        val error: String? = null,
        val rawBody: String? = null,
    ) {
        val isSuccess: Boolean get() = snapshot != null
        fun toGeoIpResponse(): GeoIpResponse = GeoIpResponse(
            provider = provider,
            isCustom = isCustom,
            ip = snapshot?.ip,
            error = error,
            rawBody = rawBody,
        )
    }

    private const val IPAPIIS_PROVIDER = "ipapi.is"
    private const val IPLOCATE_PROVIDER = "iplocate.io"
    private const val IPQUERY_PROVIDER = "ipquery.io"
    private const val IPLOOKUP_PROVIDER = "iplookup.it"
    private const val IPBOT_PROVIDER = "ipbot.com"

    private const val MISSING_IP_FIELD = "Missing ip field"

    private const val IPAPIIS_URL = "https://api.ipapi.is/"

    private const val IPLOCATE_URL = "https://www.iplocate.io/api/lookup"
    private const val IPQUERY_URL = "https://api.ipquery.io/"
    private const val IPLOOKUP_URL = "https://www.iplookup.it"
    private const val IPBOT_URL = "https://api.ipbot.com/"

    suspend fun check(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        config: GeoIpConfig = GeoIpConfig(),
    ): CategoryResult = withContext(Dispatchers.IO) {
        if (!config.enabled) {
            return@withContext CategoryResult(
                name = "GeoIP",
                detected = false,
                findings = emptyList(),
                geoFacts = GeoIpFacts(fetchError = false),
            )
        }
        val executionContext = ScanExecutionContext.currentOrDefault()
        try {
            coroutineScope {
                val ipapiIsDeferred = if (isBuiltinEnabled(config, IPAPIIS_PROVIDER)) {
                    async { fetchWithRetries { fetchIpapiIs(resolverConfig, timeoutMs = config.timeoutMs) } }
                } else null
                val iplocateDeferred = if (isBuiltinEnabled(config, IPLOCATE_PROVIDER)) {
                    async { fetchWithRetries { fetchIplocate(resolverConfig, timeoutMs = config.timeoutMs) } }
                } else null
                val ipqueryDeferred = if (isBuiltinEnabled(config, IPQUERY_PROVIDER)) {
                    async { fetchWithRetries { fetchIpquery(resolverConfig, timeoutMs = config.timeoutMs) } }
                } else null
                val iplookupDeferred = if (isBuiltinEnabled(config, IPLOOKUP_PROVIDER)) {
                    async { fetchWithRetries { fetchIplookup(resolverConfig, timeoutMs = config.timeoutMs) } }
                } else null
                val ipbotDeferred = if (isBuiltinEnabled(config, IPBOT_PROVIDER)) {
                    async { fetchWithRetries { fetchIpbot(resolverConfig, timeoutMs = config.timeoutMs) } }
                } else null

                val ipapiIsResult = ipapiIsDeferred?.await()
                val iplocateResult = iplocateDeferred?.await()
                val ipqueryResult = ipqueryDeferred?.await()
                val iplookupResult = iplookupDeferred?.await()
                val ipbotResult = ipbotDeferred?.await()

                val seedProviders = listOfNotNull(
                    ipapiIsResult,
                    iplocateResult,
                    ipqueryResult,
                    iplookupResult,
                    ipbotResult,
                )
                val seedProvider = seedProviders.firstOrNull { it.isSuccess }
                    ?: return@coroutineScope noProviderResult(
                        context.getString(R.string.checker_geo_error_no_provider),
                        responses = seedProviders
                    )
                val explicitProviders = fetchSpecificIpProviders(
                    resolverConfig = resolverConfig,
                    ip = seedProvider.snapshot!!.ip,
                    config = config,
                )
                val customSnapshots = fetchCustomProviders(
                    resolverConfig = resolverConfig,
                    ip = seedProvider.snapshot.ip,
                    config = config,
                )
                val mergedSeed = seedProviders + customSnapshots
                val mergedExplicit = explicitProviders + customSnapshots
                val providers = mergeProviderLists(
                    mergedExplicit.ifEmpty { mergedSeed },
                    mergedSeed,
                )
                val baseProvider = providers.firstOrNull { it.provider == seedProvider.provider }
                    ?: seedProvider

                evaluate(
                    context = context,
                    snapshot = mergeSnapshots(
                        baseProvider = baseProvider,
                        providers = providers,
                    ),
                    responses = listOf(baseProvider) + providers.filter { it.provider != baseProvider.provider }
                )
            }
        } catch (e: Exception) {
            rethrowIfCancellation(e, executionContext)
            errorResult(context.getString(R.string.checker_geo_error_fetch, e.message))
        }
    }

    private suspend fun fetchSpecificIpProviders(
        resolverConfig: DnsResolverConfig,
        ip: String,
        config: GeoIpConfig = GeoIpConfig(),
    ): List<ProviderSnapshot> {
        if (!isMeaningfulField(ip)) return emptyList()
        return coroutineScope {
            buildList {
                if (isBuiltinEnabled(config, IPAPIIS_PROVIDER)) {
                    add(async { fetchWithRetries { fetchIpapiIs(resolverConfig, ip, config.timeoutMs) } })
                }
                if (isBuiltinEnabled(config, IPLOCATE_PROVIDER)) {
                    add(async { fetchWithRetries { fetchIplocate(resolverConfig, ip, config.timeoutMs) } })
                }
                if (isBuiltinEnabled(config, IPQUERY_PROVIDER)) {
                    add(async { fetchWithRetries { fetchIpquery(resolverConfig, ip, config.timeoutMs) } })
                }
                if (isBuiltinEnabled(config, IPLOOKUP_PROVIDER)) {
                    add(async { fetchWithRetries { fetchIplookup(resolverConfig, ip, config.timeoutMs) } })
                }
                if (isBuiltinEnabled(config, IPBOT_PROVIDER)) {
                    add(async { fetchWithRetries { fetchIpbot(resolverConfig, ip, config.timeoutMs) } })
                }
            }
                .awaitAll()
        }
    }

    private suspend fun fetchCustomProviders(
        resolverConfig: DnsResolverConfig,
        ip: String,
        config: GeoIpConfig,
    ): List<ProviderSnapshot> {
        val enabled = config.customProviders.filter { it.enabled }
        if (enabled.isEmpty()) return emptyList()
        return coroutineScope {
            enabled
                .map { provider ->
                    async {
                        fetchWithRetries {
                            fetchCustomProvider(resolverConfig, ip, provider, config.timeoutMs)
                        }
                    }
                }
                .awaitAll()
        }
    }

    private fun fetchCustomProvider(
        resolverConfig: DnsResolverConfig,
        ip: String,
        provider: CustomGeoIpProvider,
        timeoutMs: Int,
    ): ProviderSnapshot {
        return try {
            val resolvedUrl = when {
                provider.url.contains("{ip}") -> provider.url.replace("{ip}", urlEncode(ip))
                provider.url.endsWith("?q=") -> "${provider.url}${urlEncode(ip)}"
                else -> provider.url
            }
            val acceptHeaders = when (provider.responseMapping.responseType) {
                com.notcvnt.rknhardering.customcheck.ResponseType.JSON -> mapOf("Accept" to "application/json")
                else -> mapOf("Accept" to "*/*")
            }
            val rawBody = fetchRawBody(resolvedUrl, resolverConfig, timeoutMs, acceptHeaders)
                ?: return ProviderSnapshot(provider.name, true, null, "HTTP Request failed (non-2xx code)")
            val mapping = provider.responseMapping

            val ipVal = EndpointResponseMapper.extractField(rawBody, mapping, MappingField.IP)
                ?.takeIf { it.isNotBlank() } ?: ip
            val countryCode = EndpointResponseMapper.extractField(rawBody, mapping, MappingField.COUNTRY_CODE)
                ?.trim() ?: ""
            val countryName = EndpointResponseMapper.extractField(rawBody, mapping, MappingField.COUNTRY_NAME)
                ?.trim() ?: "N/A"
            val isp = EndpointResponseMapper.extractField(rawBody, mapping, MappingField.ISP)
                ?.trim() ?: "N/A"
            val org = EndpointResponseMapper.extractField(rawBody, mapping, MappingField.ORG)
                ?.trim() ?: "N/A"
            val asn = EndpointResponseMapper.extractField(rawBody, mapping, MappingField.ASN)
                ?.trim() ?: "N/A"
            val isHosting = parseBooleanString(
                EndpointResponseMapper.extractField(rawBody, mapping, MappingField.IS_HOSTING)
            )
            val isProxy = parseBooleanString(
                EndpointResponseMapper.extractField(rawBody, mapping, MappingField.IS_PROXY)
            )

            ProviderSnapshot(
                provider = provider.name,
                isCustom = true,
                snapshot = GeoIpSnapshot(
                    ip = ipVal,
                    country = countryName,
                    countryCode = countryCode,
                    isp = isp,
                    org = org,
                    asn = asn,
                    isProxy = isProxy,
                    isHosting = isHosting,
                    hostingVotes = 0,
                    hostingChecks = 0,
                    hostingSources = emptyList(),
                ),
                rawBody = rawBody,
            )
        } catch (e: Exception) {
            rethrowIfCancellation(e)
            ProviderSnapshot(provider.name, true, null, e.message)
        }
    }

    private fun fetchRawBody(url: String, resolverConfig: DnsResolverConfig, timeoutMs: Int = GEOIP_TIMEOUT_MS, headers: Map<String, String> = mapOf("Accept" to "*/*")): String? {
        val executionContext = ScanExecutionContext.currentOrDefault()
        val response = ResolverNetworkStack.execute(
            url = url,
            method = "GET",
            headers = headers,
            timeoutMs = timeoutMs,
            config = resolverConfig,
            cancellationSignal = executionContext.cancellationSignal,
        )
        if (response.code !in 200..299) return null
        return response.body
    }

    internal suspend fun fetchWithRetries(
        maxAttempts: Int = MAX_FETCH_ATTEMPTS,
        retryDelayMs: Long = RETRY_DELAY_MS,
        fetcher: suspend () -> ProviderSnapshot,
    ): ProviderSnapshot {
        var lastResult: ProviderSnapshot? = null
        repeat(maxAttempts.coerceAtLeast(1)) { attempt ->
            try {
                val result = fetcher()
                lastResult = result
                if (result.isSuccess) {
                    return result
                }
            } catch (error: Exception) {
                rethrowIfCancellation(error)
            }
            if (attempt < maxAttempts - 1 && retryDelayMs > 0) {
                delay(retryDelayMs)
            }
        }
        return lastResult ?: fetcher() // fallback if maxAttempts=0
    }

    // Shared fetch/validate/error skeleton for the builtin providers. Each
    // provider keeps its own URL construction and field-path cascades; only
    // the plumbing is shared.
    private inline fun fetchBuiltinProvider(
        provider: String,
        url: String,
        resolverConfig: DnsResolverConfig,
        timeoutMs: Int,
        parse: (JSONObject) -> GeoIpSnapshot,
    ): ProviderSnapshot {
        return try {
            val json = fetchJson(url = url, resolverConfig = resolverConfig, timeoutMs = timeoutMs)
            if (!json.has("ip")) {
                ProviderSnapshot(provider, false, null, MISSING_IP_FIELD, json.toString())
            } else {
                ProviderSnapshot(
                    provider = provider,
                    isCustom = false,
                    snapshot = parse(json),
                    rawBody = json.toString(),
                )
            }
        } catch (error: Exception) {
            rethrowIfCancellation(error)
            ProviderSnapshot(provider, false, null, error.message)
        }
    }

    private fun fetchIpapiIs(resolverConfig: DnsResolverConfig, ip: String? = null, timeoutMs: Int = GEOIP_TIMEOUT_MS): ProviderSnapshot =
        fetchBuiltinProvider(
            provider = IPAPIIS_PROVIDER,
            url = ip?.let { "$IPAPIIS_URL?q=${urlEncode(it)}" } ?: IPAPIIS_URL,
            resolverConfig = resolverConfig,
            timeoutMs = timeoutMs,
        ) { json ->
            val location = json.optJSONObject("location")
            val company = json.optJSONObject("company")
            val datacenter = json.optJSONObject("datacenter")
            val asn = json.optJSONObject("asn")

            GeoIpSnapshot(
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
            )
        }

    private fun fetchIplocate(resolverConfig: DnsResolverConfig, ip: String? = null, timeoutMs: Int = GEOIP_TIMEOUT_MS): ProviderSnapshot =
        fetchBuiltinProvider(
            provider = IPLOCATE_PROVIDER,
            url = ip?.let { "$IPLOCATE_URL/${urlEncode(it)}" } ?: IPLOCATE_URL,
            resolverConfig = resolverConfig,
            timeoutMs = timeoutMs,
        ) { json ->
            val privacy = json.optJSONObject("privacy")
            val company = json.optJSONObject("company")
            val hosting = json.optJSONObject("hosting")
            val asn = json.optJSONObject("asn")

            GeoIpSnapshot(
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
            )
        }

    private fun fetchIpquery(resolverConfig: DnsResolverConfig, ip: String? = null, timeoutMs: Int = GEOIP_TIMEOUT_MS): ProviderSnapshot =
        fetchBuiltinProvider(
            provider = IPQUERY_PROVIDER,
            url = ip?.let { "$IPQUERY_URL${urlEncode(it)}" } ?: "${IPQUERY_URL}?format=json",
            resolverConfig = resolverConfig,
            timeoutMs = timeoutMs,
        ) { json ->
            val location = json.optJSONObject("location")
            val isp = json.optJSONObject("isp")
            val risk = json.optJSONObject("risk")

            GeoIpSnapshot(
                ip = firstMeaningful(json.optString("ip"), default = "N/A"),
                country = firstMeaningful(location?.optString("country"), default = "N/A"),
                countryCode = firstMeaningful(location?.optString("country_code"), default = ""),
                isp = firstMeaningful(
                    isp?.optString("isp"),
                    isp?.optString("org"),
                    default = "N/A",
                ),
                org = firstMeaningful(
                    isp?.optString("org"),
                    isp?.optString("isp"),
                    default = "N/A",
                ),
                asn = formatAsn(
                    code = isp?.optString("asn"),
                    name = firstMeaningful(
                        isp?.optString("org"),
                        isp?.optString("isp"),
                        default = "N/A",
                    ),
                ),
                isProxy = (risk?.optBoolean("is_proxy", false) == true) ||
                    (risk?.optBoolean("is_vpn", false) == true) ||
                    (risk?.optBoolean("is_tor", false) == true),
                isHosting = risk?.optBoolean("is_datacenter", false) == true,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            )
        }

    private fun fetchIplookup(resolverConfig: DnsResolverConfig, ip: String? = null, timeoutMs: Int = GEOIP_TIMEOUT_MS): ProviderSnapshot =
        fetchBuiltinProvider(
            provider = IPLOOKUP_PROVIDER,
            url = ip?.let { "$IPLOOKUP_URL/ip/${urlEncode(it)}" } ?: "$IPLOOKUP_URL/json",
            resolverConfig = resolverConfig,
            timeoutMs = timeoutMs,
        ) { json ->
            val geo = json.optJSONObject("geo")
            val network = json.optJSONObject("network")
            val privacy = json.optJSONObject("privacy")

            GeoIpSnapshot(
                ip = firstMeaningful(json.optString("ip"), default = "N/A"),
                country = firstMeaningful(geo?.optString("country"), default = "N/A"),
                countryCode = firstMeaningful(geo?.optString("country_code"), default = ""),
                isp = firstMeaningful(
                    network?.optString("isp"),
                    network?.optString("org"),
                    default = "N/A",
                ),
                org = firstMeaningful(
                    network?.optString("org"),
                    network?.optString("isp"),
                    default = "N/A",
                ),
                asn = formatAsn(
                    code = network?.opt("asn")?.toString(),
                    name = firstMeaningful(
                        network?.optString("org"),
                        network?.optString("isp"),
                        default = "N/A",
                    ),
                ),
                isProxy = (privacy?.optBoolean("proxy", false) == true) ||
                    (privacy?.optBoolean("vpn", false) == true) ||
                    (privacy?.optBoolean("tor", false) == true),
                isHosting = privacy?.optBoolean("hosting", false) == true,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            )
        }

    private fun fetchIpbot(resolverConfig: DnsResolverConfig, ip: String? = null, timeoutMs: Int = GEOIP_TIMEOUT_MS): ProviderSnapshot =
        fetchBuiltinProvider(
            provider = IPBOT_PROVIDER,
            url = ip?.let { "$IPBOT_URL${urlEncode(it)}" } ?: IPBOT_URL,
            resolverConfig = resolverConfig,
            timeoutMs = timeoutMs,
        ) { json ->
            val location = json.optJSONObject("location")
            val network = json.optJSONObject("network")
            val security = json.optJSONObject("security")
            val usageType = security?.optString("usage_type")?.trim()?.uppercase()
            val radarType = (network?.opt("radar") as? String)?.trim()?.lowercase()
            val threatLists = security?.optJSONArray("threat_lists")
            val proxyThreat = threatLists.containsAny("proxy", "proxies", "vpn", "tor")

            GeoIpSnapshot(
                ip = firstMeaningful(json.optString("ip"), default = "N/A"),
                country = firstMeaningful(location?.optString("country"), default = "N/A"),
                countryCode = firstMeaningful(location?.optString("country_code"), default = ""),
                isp = firstMeaningful(
                    network?.optString("org"),
                    default = "N/A",
                ),
                org = firstMeaningful(
                    network?.optString("org"),
                    default = "N/A",
                ),
                asn = formatAsn(
                    code = network?.optString("asn"),
                    name = firstMeaningful(network?.optString("org"), default = "N/A"),
                ),
                isProxy = (security?.optBoolean("is_proxy", false) == true) ||
                    proxyThreat ||
                    radarType == "vpn" ||
                    radarType == "proxy" ||
                    radarType == "tor",
                isHosting = (security?.optBoolean("is_datacenter", false) == true) ||
                    usageType == "DCH" ||
                    radarType == "datacenter",
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            )
        }

    private fun fetchJson(url: String, resolverConfig: DnsResolverConfig, timeoutMs: Int = GEOIP_TIMEOUT_MS): JSONObject {
        val executionContext = ScanExecutionContext.currentOrDefault()
        val response = ResolverNetworkStack.execute(
            url = url,
            method = "GET",
            headers = mapOf("Accept" to "application/json"),
            timeoutMs = timeoutMs,
            config = resolverConfig,
            cancellationSignal = executionContext.cancellationSignal,
        )
        check(response.code in 200..299) { "HTTP ${response.code}" }
        return JSONObject(response.body)
    }

    internal fun mergeSnapshots(
        baseProvider: ProviderSnapshot,
        providers: List<ProviderSnapshot>,
    ): GeoIpSnapshot {
        val compatibleProviders = providers.filter {
            it.isSuccess && isCompatibleIp(
                expectedIp = baseProvider.snapshot?.ip ?: "",
                candidateIp = it.snapshot?.ip ?: "",
            )
        }

        val orderedForFill = buildList {
            if (baseProvider.isSuccess) add(baseProvider)
            compatibleProviders
                .filterNot { it.provider == baseProvider.provider }
                .forEach(::add)
        }

        val hostingVotes = compatibleProviders.count { it.snapshot!!.isHosting }
        val hostingChecks = compatibleProviders.size
        val hostingSources = compatibleProviders
            .filter { it.snapshot!!.isHosting }
            .map { it.provider }
        val proxyVotes = compatibleProviders.count { it.snapshot!!.isProxy }
        val proxyChecks = compatibleProviders.size
        val proxySources = compatibleProviders
            .filter { it.snapshot!!.isProxy }
            .map { it.provider }

        return GeoIpSnapshot(
            ip = pickField(orderedForFill) { it.snapshot!!.ip },
            country = pickField(orderedForFill) { it.snapshot!!.country },
            countryCode = pickField(orderedForFill, default = "") { it.snapshot!!.countryCode },
            isp = pickField(orderedForFill) { it.snapshot!!.isp },
            org = pickField(orderedForFill) { it.snapshot!!.org },
            asn = pickField(orderedForFill) { it.snapshot!!.asn },
            isProxy = resolveProxy(
                compatibleProviders = compatibleProviders,
            ),
            isHosting = hostingVotes > hostingChecks / 2,
            hostingVotes = hostingVotes,
            hostingChecks = hostingChecks,
            hostingSources = hostingSources,
            proxyVotes = proxyVotes,
            proxyChecks = proxyChecks,
            proxySources = proxySources,
        )
    }

    internal fun evaluate(context: Context, snapshot: GeoIpSnapshot, responses: List<ProviderSnapshot>): CategoryResult {
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
            description = buildVoteDescription(
                prefix = context.getString(R.string.checker_geo_proxy_db, if (snapshot.isProxy) yesStr else noStr),
                votes = snapshot.proxyVotes,
                checks = snapshot.proxyChecks,
                sources = snapshot.proxySources,
            ),
            detected = snapshot.isProxy,
        )

        val countryCode = snapshot.countryCode.uppercase().ifBlank { null }
        val outsideRu = countryCode != null && countryCode != "RU"
        val asn = snapshot.asn.takeUnless { it.isBlank() || it == "N/A" }
        val geoFacts = GeoIpFacts(
            ip = snapshot.ip.takeUnless { it.isBlank() || it == "N/A" },
            countryCode = countryCode,
            asn = asn,
            asnCode = HomeNetworkCatalog.extractAsnCode(asn),
            isp = snapshot.isp.takeUnless { it.isBlank() || it == "N/A" },
            org = snapshot.org.takeUnless { it.isBlank() || it == "N/A" },
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
            geoIpResponses = responses.map { it.toGeoIpResponse() },
        )
    }

    private fun errorResult(message: String, responses: List<ProviderSnapshot> = emptyList()): CategoryResult {
        return CategoryResult(
            name = "GeoIP",
            detected = false,
            findings = listOf(Finding(message, isError = true)),
            geoFacts = GeoIpFacts(fetchError = true),
            geoIpResponses = responses.map { it.toGeoIpResponse() },
        )
    }

    internal fun noProviderResult(message: String, responses: List<ProviderSnapshot> = emptyList()): CategoryResult {
        return CategoryResult(
            name = "GeoIP",
            detected = false,
            findings = listOf(Finding(message)),
            geoFacts = GeoIpFacts(fetchError = true),
            geoIpResponses = responses.map { it.toGeoIpResponse() },
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
        return compatibleProviders.any { it.snapshot!!.isProxy }
    }

    private fun mergeProviderLists(
        primary: List<ProviderSnapshot>,
        fallback: List<ProviderSnapshot>,
    ): List<ProviderSnapshot> {
        val merged = LinkedHashMap<String, ProviderSnapshot>()
        primary.forEach { merged[it.provider] = it }
        fallback.forEach { merged.putIfAbsent(it.provider, it) }
        return merged.values.toList()
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

    private fun buildVoteDescription(
        prefix: String,
        votes: Int,
        checks: Int,
        sources: List<String>,
    ): String = buildString {
        append(prefix)
        if (checks > 0) {
            append(" ($votes/$checks")
            if (sources.isNotEmpty()) {
                append(": ")
                append(sources.joinToString(", "))
            }
            append(")")
        }
    }

    private fun org.json.JSONArray?.containsAny(vararg candidates: String): Boolean {
        if (this == null) return false
        val normalizedCandidates = candidates.map { it.lowercase() }.toSet()
        for (index in 0 until length()) {
            if (optString(index).trim().lowercase() in normalizedCandidates) return true
        }
        return false
    }

    private fun urlEncode(value: String): String {
        return URLEncoder.encode(value, Charsets.UTF_8.name())
    }
}
