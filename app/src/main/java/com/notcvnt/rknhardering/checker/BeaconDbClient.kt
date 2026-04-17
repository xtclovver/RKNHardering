package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.BuildConfig
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.rethrowIfCancellation
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

internal data class CellLookupCandidate(
    val radio: String,
    val mcc: String,
    val mnc: String,
    val areaCode: Long,
    val cellId: Long,
    val registered: Boolean,
    val signalStrength: Int? = null,
)

internal data class WifiLookupCandidate(
    val macAddress: String,
    val frequency: Int? = null,
    val signalStrength: Int? = null,
)

internal data class CellLookupResult(
    val countryCode: String?,
    val latitude: Double?,
    val longitude: Double?,
    val summary: String,
)

internal class BeaconDbClient(
    private val countryResolver: (Double, Double) -> String?,
    private val resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    private val userAgent: String = "RKNHardering/${BuildConfig.VERSION_NAME}",
    private val request: suspend (String, String, String) -> HttpResult = { url, body, agent ->
        defaultRequest(url, body, agent, resolverConfig)
    },
) {

    internal data class HttpResult(
        val code: Int,
        val body: String,
    )

    private data class ParsedLookupResponse(
        val latitude: Double,
        val longitude: Double,
        val fallback: String?,
    ) {
        val isExactMatch: Boolean
            get() = fallback.isNullOrBlank()
    }

    suspend fun lookup(
        cells: List<CellLookupCandidate>,
        wifiAccessPoints: List<WifiLookupCandidate>,
    ): CellLookupResult = withContext(Dispatchers.IO) {
        val supportedCells = cells.filter { it.radio in SUPPORTED_RADIOS }.take(MAX_CELL_TOWERS)
        val wifiForLookup = wifiAccessPoints.takeIf { it.size >= MIN_WIFI_ACCESS_POINTS }.orEmpty()
        if (supportedCells.isEmpty() && wifiForLookup.isEmpty()) {
            return@withContext CellLookupResult(
                countryCode = null,
                latitude = null,
                longitude = null,
                summary = "BeaconDB: insufficient radio data",
            )
        }

        val requestBody = buildRequestBody(supportedCells, wifiForLookup)
        val response = try {
            request(LOOKUP_URL, requestBody, userAgent)
        } catch (error: Exception) {
            rethrowIfCancellation(error)
            return@withContext CellLookupResult(
                countryCode = null,
                latitude = null,
                longitude = null,
                summary = "BeaconDB: ${error.message ?: "request failed"}",
            )
        }

        if (response.code !in 200..299) {
            return@withContext CellLookupResult(
                countryCode = null,
                latitude = null,
                longitude = null,
                summary = describeFailure(response),
            )
        }

        val parsed = parseResponse(response.body)
            ?: return@withContext CellLookupResult(
                countryCode = null,
                latitude = null,
                longitude = null,
                summary = describeFailure(response),
            )

        if (parsed.fallback == FALLBACK_IP) {
            return@withContext CellLookupResult(
                countryCode = null,
                latitude = null,
                longitude = null,
                summary = "BeaconDB: IP fallback ignored",
            )
        }

        val countryCode = if (parsed.isExactMatch) {
            runCatching {
                countryResolver(parsed.latitude, parsed.longitude)
            }.getOrNull()?.uppercase(Locale.US)
        } else {
            null
        }

        CellLookupResult(
            countryCode = countryCode,
            latitude = parsed.latitude,
            longitude = parsed.longitude,
            summary = when (parsed.fallback) {
                FALLBACK_LACF -> "BeaconDB: coarse cell area fallback"
                null, "" -> "BeaconDB: exact match"
                else -> "BeaconDB: fallback ${parsed.fallback}"
            },
        )
    }

    internal fun buildRequestBody(
        cells: List<CellLookupCandidate>,
        wifiAccessPoints: List<WifiLookupCandidate>,
    ): String {
        val supportedCells = cells.filter { it.radio in SUPPORTED_RADIOS }.take(MAX_CELL_TOWERS)
        val wifiForLookup = wifiAccessPoints.takeIf { it.size >= MIN_WIFI_ACCESS_POINTS }.orEmpty()
        val cellJson = supportedCells.joinToString(",") { candidate ->
            buildString {
                append("{")
                append("\"radioType\":\"").append(escapeJson(candidate.radio.lowercase(Locale.US))).append("\"")
                append(",\"mobileCountryCode\":").append(candidate.mcc.toInt())
                append(",\"mobileNetworkCode\":").append(candidate.mnc.toInt())
                append(",\"locationAreaCode\":").append(candidate.areaCode)
                append(",\"cellId\":").append(candidate.cellId)
                candidate.signalStrength?.let { append(",\"signalStrength\":").append(it) }
                append("}")
            }
        }
        val wifiJson = wifiForLookup.take(MAX_WIFI_ACCESS_POINTS).joinToString(",") { candidate ->
            buildString {
                append("{")
                append("\"macAddress\":\"").append(escapeJson(candidate.macAddress)).append("\"")
                candidate.frequency?.let { append(",\"frequency\":").append(it) }
                candidate.signalStrength?.let { append(",\"signalStrength\":").append(it) }
                append("}")
            }
        }

        return buildString {
            append("{")
            append("\"considerIp\":false")
            append(",\"fallbacks\":{\"lacf\":true,\"ipf\":false}")
            append(",\"cellTowers\":[")
            append(cellJson)
            append("]")
            if (wifiJson.isNotEmpty()) {
                append(",\"wifiAccessPoints\":[")
                append(wifiJson)
                append("]")
            }
            append("}")
        }
    }

    internal fun describeFailure(response: HttpResult): String {
        return when {
            response.code == 404 -> "BeaconDB: no matching location"
            response.code == 429 -> "BeaconDB: rate limited"
            response.code in 500..599 -> "BeaconDB: server error ${response.code}"
            response.code in 400..499 -> "BeaconDB: request rejected ${response.code}"
            response.body.trim().startsWith("<") -> "BeaconDB: non-JSON response"
            else -> "BeaconDB: lookup failed ${response.code}"
        }
    }

    private fun parseResponse(body: String): ParsedLookupResponse? {
        val trimmed = body.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("<")) return null

        val locationBody = LOCATION_BLOCK_REGEX.find(trimmed)?.groupValues?.get(1) ?: return null
        val latitude = DOUBLE_FIELD_REGEX("lat").find(locationBody)?.groupValues?.get(1)?.toDoubleOrNull() ?: return null
        val longitude = DOUBLE_FIELD_REGEX("lng").find(locationBody)?.groupValues?.get(1)?.toDoubleOrNull() ?: return null
        val fallback = STRING_FIELD_REGEX("fallback").find(trimmed)?.groupValues?.get(1)

        return ParsedLookupResponse(
            latitude = latitude,
            longitude = longitude,
            fallback = fallback,
        )
    }

    private fun escapeJson(value: String): String {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
    }

    private companion object {
        private const val LOOKUP_URL = "https://api.beacondb.net/v1/geolocate"
        private const val MAX_CELL_TOWERS = 6
        private const val MAX_WIFI_ACCESS_POINTS = 12
        private const val MIN_WIFI_ACCESS_POINTS = 2
        private const val FALLBACK_IP = "ipf"
        private const val FALLBACK_LACF = "lacf"
        private val SUPPORTED_RADIOS = setOf("gsm", "lte", "wcdma")
        private val LOCATION_BLOCK_REGEX = Regex("\"location\"\\s*:\\s*\\{([\\s\\S]*?)\\}")

        private fun DOUBLE_FIELD_REGEX(name: String): Regex {
            return Regex("\"$name\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)")
        }

        private fun STRING_FIELD_REGEX(name: String): Regex {
            return Regex("\"$name\"\\s*:\\s*\"([^\"]+)\"")
        }

        private fun defaultRequest(
            url: String,
            body: String,
            userAgent: String,
            resolverConfig: DnsResolverConfig,
        ): HttpResult {
            val executionContext = ScanExecutionContext.currentOrDefault()
            val response = ResolverNetworkStack.execute(
                url = url,
                method = "POST",
                headers = mapOf(
                    "Accept" to "application/json",
                    "Content-Type" to "application/json; charset=utf-8",
                    "User-Agent" to userAgent,
                ),
                body = body,
                bodyContentType = "application/json; charset=utf-8",
                timeoutMs = 8_000,
                config = resolverConfig,
                cancellationSignal = executionContext.cancellationSignal,
            )
            return HttpResult(code = response.code, body = response.body)
        }
    }
}
