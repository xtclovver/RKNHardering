package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

object GeoIpChecker {

    internal data class GeoIpSnapshot(
        val ip: String,
        val country: String,
        val countryCode: String,
        val isp: String,
        val org: String,
        val asn: String,
        val isProxy: Boolean,
        // true if majority of sources say hosting
        val isHosting: Boolean,
        // how many sources voted hosting (out of 3)
        val hostingVotes: Int,
        val hostingSources: List<String>,
    )

    private const val IPAPI_URL =
        "http://ip-api.com/json/?fields=status,country,countryCode,isp,org,as,proxy,hosting,query"

    // https://api.ipapi.is/ — returns is_datacenter: bool for current IP
    private const val IPAPIIS_URL = "https://api.ipapi.is/"

    // https://www.iplocate.io/api/lookup — returns privacy.is_hosting: bool for current IP
    private const val IPLOCATE_URL = "https://www.iplocate.io/api/lookup"

    suspend fun check(): CategoryResult = withContext(Dispatchers.IO) {
        try {
            coroutineScope {
                val ipapiDeferred = async { fetchIpApi() }
                val ipapiIsDeferred = async { fetchIpapiIs() }
                val iplocateDeferred = async { fetchIplocate() }

                val ipapiResult = ipapiDeferred.await()
                    ?: return@coroutineScope errorResult("ip-api вернул ошибку")

                val ipapiIsHosting = ipapiIsDeferred.await()
                val iplocateHosting = iplocateDeferred.await()

                val votes = listOf(
                    ipapiResult.isHosting to "ip-api.com",
                    ipapiIsHosting to "ipapi.is",
                    iplocateHosting to "iplocate.io",
                )
                val hostingVotes = votes.count { it.first }
                val hostingSources = votes.filter { it.first }.map { it.second }
                val hostingByVoting = hostingVotes >= 2

                evaluate(
                    ipapiResult.copy(
                        isHosting = hostingByVoting,
                        hostingVotes = hostingVotes,
                        hostingSources = hostingSources,
                    ),
                )
            }
        } catch (e: Exception) {
            errorResult("Не удалось получить данные GeoIP: ${e.message}")
        }
    }

    private fun fetchIpApi(): GeoIpSnapshot? {
        return try {
            val json = fetchJson(IPAPI_URL)
            if (json.optString("status") != "success") return null
            GeoIpSnapshot(
                ip = json.optString("query", "N/A"),
                country = json.optString("country", "N/A"),
                countryCode = json.optString("countryCode", ""),
                isp = json.optString("isp", "N/A"),
                org = json.optString("org", "N/A"),
                asn = json.optString("as", "N/A"),
                isProxy = json.optBoolean("proxy", false),
                isHosting = json.optBoolean("hosting", false),
                hostingVotes = 0,
                hostingSources = emptyList(),
            )
        } catch (_: Exception) {
            null
        }
    }

    // Returns is_datacenter field
    private fun fetchIpapiIs(): Boolean {
        return try {
            val json = fetchJson(IPAPIIS_URL)
            json.optBoolean("is_datacenter", false)
        } catch (_: Exception) {
            false
        }
    }

    // Returns privacy.is_hosting field
    private fun fetchIplocate(): Boolean {
        return try {
            val json = fetchJson(IPLOCATE_URL)
            json.optJSONObject("privacy")?.optBoolean("is_hosting", false) ?: false
        } catch (_: Exception) {
            false
        }
    }

    private fun fetchJson(url: String): JSONObject {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        try {
            val body = connection.inputStream.bufferedReader().readText()
            return JSONObject(body)
        } finally {
            connection.disconnect()
        }
    }

    internal fun evaluate(snapshot: GeoIpSnapshot): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        findings.add(Finding("IP: ${snapshot.ip}"))
        findings.add(Finding("Страна: ${snapshot.country} (${snapshot.countryCode})"))
        findings.add(Finding("ISP: ${snapshot.isp}"))
        findings.add(Finding("Организация: ${snapshot.org}"))
        findings.add(Finding("ASN: ${snapshot.asn}"))

        val foreignIp = snapshot.countryCode.isNotEmpty() && snapshot.countryCode != "RU"
        val needsReview = foreignIp && !snapshot.isHosting && !snapshot.isProxy
        findings.add(
            Finding(
                description = "IP вне России: ${if (foreignIp) "да (${snapshot.countryCode})" else "нет"}",
                needsReview = needsReview,
                source = EvidenceSource.GEO_IP,
                confidence = needsReview.takeIf { it }?.let { EvidenceConfidence.LOW },
            ),
        )

        val hostingDesc = buildString {
            append("IP принадлежит хостинг-провайдеру: ${if (snapshot.isHosting) "да" else "нет"}")
            if (snapshot.hostingVotes > 0 || snapshot.hostingSources.isNotEmpty()) {
                append(" (${snapshot.hostingVotes}/3")
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
            description = "IP в базе известных прокси/VPN: ${if (snapshot.isProxy) "да" else "нет"}",
            detected = snapshot.isProxy,
        )

        return CategoryResult(
            name = "GeoIP",
            detected = snapshot.isHosting || snapshot.isProxy,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    private fun errorResult(message: String): CategoryResult {
        return CategoryResult(
            name = "GeoIP",
            detected = false,
            findings = listOf(Finding("Ошибка GeoIP: $message")),
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
}
