package com.notcvnt.rknhardering.customcheck.mapper

import com.notcvnt.rknhardering.customcheck.ResponseMapping
import com.notcvnt.rknhardering.customcheck.ResponseType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

enum class MappingField {
    IP, COUNTRY_CODE, COUNTRY_NAME, ISP, ORG, ASN, IS_HOSTING, IS_PROXY
}

object EndpointResponseMapper {

    private val IPV4_REGEX = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
    private val IPV6_REGEX = Regex("""^[0-9a-fA-F:]+$""")
    private val COUNTRY_CODE_REGEX = Regex("""^[A-Z]{2}$""")
    private val ASN_STRING_REGEX = Regex("""^AS\d+(?:\s.*)?$""")

    data class TestResult(
        val success: Boolean,
        val statusCode: Int?,
        val rawBody: String?,
        val error: String?,
        val responseTimeMs: Long,
        val detectedType: ResponseType?,
        val suggestedMapping: ResponseMapping?,
    )

    suspend fun testEndpoint(url: String, timeoutMs: Int = 5000): TestResult =
        withContext(Dispatchers.IO) {
            val client = OkHttpClient.Builder()
                .connectTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
                .readTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
                .build()
            val start = System.currentTimeMillis()
            try {
                val request = Request.Builder().url(url).build()
                val response = client.newCall(request).execute()
                val elapsed = System.currentTimeMillis() - start
                val body = response.body?.string() ?: ""
                if (response.isSuccessful) {
                    val type = autoDetectResponseType(body)
                    val mapping = autoDetectMapping(body, type)
                    TestResult(
                        success = true,
                        statusCode = response.code,
                        rawBody = body,
                        error = null,
                        responseTimeMs = elapsed,
                        detectedType = type,
                        suggestedMapping = mapping,
                    )
                } else {
                    TestResult(
                        success = false,
                        statusCode = response.code,
                        rawBody = body,
                        error = "HTTP ${response.code}",
                        responseTimeMs = elapsed,
                        detectedType = null,
                        suggestedMapping = null,
                    )
                }
            } catch (e: Exception) {
                val elapsed = System.currentTimeMillis() - start
                TestResult(
                    success = false,
                    statusCode = null,
                    rawBody = null,
                    error = e.message ?: e.javaClass.simpleName,
                    responseTimeMs = elapsed,
                    detectedType = null,
                    suggestedMapping = null,
                )
            }
        }

    fun autoDetectResponseType(rawResponse: String): ResponseType {
        val trimmed = rawResponse.trim()
        // 1. Try JSON object
        try { JSONObject(trimmed); return ResponseType.JSON } catch (_: Exception) { /* not a JSON object, try next format */ }
        // 2. Try JSON array
        try { JSONArray(trimmed); return ResponseType.JSON } catch (_: Exception) { /* not a JSON array, try next format */ }
        // 3. key=value lines
        val lines = trimmed.lines().filter { it.isNotBlank() }
        val kvPattern = Regex("""^\w+=.+$""")
        if (lines.size >= 2 && lines.count { kvPattern.matches(it) } >= lines.size * 0.5) {
            return ResponseType.KEY_VALUE
        }
        // 4. Plain text IP
        if (looksLikeIp(trimmed)) return ResponseType.PLAIN_TEXT
        // 5. Fallback
        return ResponseType.REGEX
    }

    fun autoDetectMapping(rawResponse: String, responseType: ResponseType): ResponseMapping {
        return when (responseType) {
            ResponseType.JSON -> detectJsonMapping(rawResponse)
            ResponseType.KEY_VALUE -> detectKeyValueMapping(rawResponse)
            ResponseType.PLAIN_TEXT -> ResponseMapping(
                responseType = ResponseType.PLAIN_TEXT,
                ipPath = "",
            )
            ResponseType.REGEX -> ResponseMapping(responseType = ResponseType.REGEX)
        }
    }

    fun extractField(rawResponse: String, mapping: ResponseMapping, field: MappingField): String? {
        val path = when (field) {
            MappingField.IP -> mapping.ipPath
            MappingField.COUNTRY_CODE -> mapping.countryCodePath
            MappingField.COUNTRY_NAME -> mapping.countryNamePath
            MappingField.ISP -> mapping.ispPath
            MappingField.ORG -> mapping.orgPath
            MappingField.ASN -> mapping.asnPath
            MappingField.IS_HOSTING -> mapping.isHostingPath
            MappingField.IS_PROXY -> mapping.isProxyPath
        } ?: return null

        return when (mapping.responseType) {
            ResponseType.JSON -> {
                try {
                    val json = JSONObject(rawResponse.trim())
                    ResponseMappingParser.extractJsonPath(json, path)?.toString()
                } catch (_: Exception) {
                    null
                }
            }
            ResponseType.KEY_VALUE -> {
                ResponseMappingParser.extractKeyValue(rawResponse, path)
            }
            ResponseType.PLAIN_TEXT -> {
                // When path is empty and field is IP, return the whole trimmed body
                if (field == MappingField.IP && path.isEmpty()) rawResponse.trim() else null
            }
            ResponseType.REGEX -> {
                ResponseMappingParser.extractRegex(rawResponse, path)
            }
        }
    }

    fun extractAll(rawResponse: String, mapping: ResponseMapping): Map<MappingField, String?> {
        return MappingField.values().associateWith { field ->
            extractField(rawResponse, mapping, field)
        }
    }

    // --- Private helpers ---

    private fun looksLikeIp(s: String): Boolean {
        val t = s.trim()
        return IPV4_REGEX.matches(t) || (IPV6_REGEX.matches(t) && t.contains(':'))
    }

    private fun detectJsonMapping(rawResponse: String): ResponseMapping {
        val json = try { JSONObject(rawResponse.trim()) } catch (_: Exception) { return ResponseMapping(responseType = ResponseType.JSON) }
        val flat = flattenJson(json, "$")

        var ipPath: String? = null
        var countryCodePath: String? = null
        var countryNamePath: String? = null
        var ispPath: String? = null
        var orgPath: String? = null
        var asnPath: String? = null
        var isHostingPath: String? = null
        var isProxyPath: String? = null

        for ((path, value) in flat) {
            val key = path.substringAfterLast('.').substringAfterLast('[').removeSuffix("]").lowercase()
            val strVal = value?.toString() ?: continue

            if (ipPath == null && looksLikeIp(strVal)) {
                ipPath = path
            }
            if (countryCodePath == null && key in setOf("country_code", "cc", "countrycode", "country") && COUNTRY_CODE_REGEX.matches(strVal)) {
                countryCodePath = path
            }
            // only if it doesn't look like a 2-letter code itself
            if (countryNamePath == null &&
                key in setOf("country", "country_name", "countryname") &&
                !COUNTRY_CODE_REGEX.matches(strVal)
            ) {
                countryNamePath = path
            }
            if (ispPath == null && key in setOf("isp", "provider")) {
                ispPath = path
            }
            if (orgPath == null && key in setOf("org", "organization")) {
                orgPath = path
            }
            if (asnPath == null && key in setOf("asn", "as_number", "asnumber", "as")) {
                asnPath = path
            }
            if (asnPath == null && ASN_STRING_REGEX.matches(strVal)) {
                asnPath = path
            }
            if (isHostingPath == null && key in setOf("datacenter", "hosting", "is_hosting", "is_datacenter")) {
                isHostingPath = path
            }
            if (isProxyPath == null && key in setOf("proxy", "vpn", "is_proxy", "is_vpn")) {
                isProxyPath = path
            }
        }

        return ResponseMapping(
            responseType = ResponseType.JSON,
            ipPath = ipPath,
            countryCodePath = countryCodePath,
            countryNamePath = countryNamePath,
            ispPath = ispPath,
            orgPath = orgPath,
            asnPath = asnPath,
            isHostingPath = isHostingPath,
            isProxyPath = isProxyPath,
        )
    }

    private fun detectKeyValueMapping(rawResponse: String): ResponseMapping {
        val ipPath = if (ResponseMappingParser.extractKeyValue(rawResponse, "ip") != null) "ip" else null
        val countryCodePath = if (ResponseMappingParser.extractKeyValue(rawResponse, "loc") != null) "loc" else null
        return ResponseMapping(
            responseType = ResponseType.KEY_VALUE,
            ipPath = ipPath,
            countryCodePath = countryCodePath,
        )
    }

    // Flatten a JSONObject into a list of (jsonpath, value) pairs for all leaf nodes
    private fun flattenJson(obj: JSONObject, prefix: String): List<Pair<String, Any?>> {
        val result = mutableListOf<Pair<String, Any?>>()
        for (key in obj.keys()) {
            val path = "$prefix.$key"
            when (val v = obj.opt(key)) {
                is JSONObject -> result += flattenJson(v, path)
                is JSONArray -> result += flattenArray(v, path)
                else -> result += path to v
            }
        }
        return result
    }

    private fun flattenArray(arr: JSONArray, prefix: String): List<Pair<String, Any?>> {
        val result = mutableListOf<Pair<String, Any?>>()
        for (i in 0 until arr.length()) {
            val path = "$prefix[$i]"
            when (val v = arr.opt(i)) {
                is JSONObject -> result += flattenJson(v, path)
                is JSONArray -> result += flattenArray(v, path)
                else -> result += path to v
            }
        }
        return result
    }
}
