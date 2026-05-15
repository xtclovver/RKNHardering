package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.dnsoverhttps.DnsOverHttps
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.net.InetAddress
import java.util.concurrent.TimeUnit

object OperatorWhitelistProbe {
    private const val REQUEST_TIMEOUT_MS = 4_000L
    private const val PROBE_TIMEOUT_MS = 6_000L

    private val YANDEX_DOH_URL = "https://common.dot.dns.yandex.net/dns-query"
    private val YANDEX_BOOTSTRAP_IPS = listOf("77.88.8.8", "77.88.8.1", "77.88.8.88")

    @Volatile
    internal var executeOverride: ((String, String) -> Pair<Int, String>)? = null

    suspend fun probe(): OperatorWhitelistProbeResult {
        val startMs = System.currentTimeMillis()
        val errors = mutableMapOf<String, String>()

        val (googleOk, appleOk, firefoxOk, ruOk) = withTimeout(PROBE_TIMEOUT_MS) {
            coroutineScope {
                val googleDeferred = async { checkGoogle(errors) }
                val appleDeferred = async { checkApple(errors) }
                val firefoxDeferred = async { checkFirefox(errors) }
                val ruDeferred = async { checkRussianControl(errors) }
                arrayOf(
                    googleDeferred.await(),
                    appleDeferred.await(),
                    firefoxDeferred.await(),
                    ruDeferred.await(),
                )
            }
        }

        val allCaptiveFailed = !googleOk && !appleOk && !firefoxOk
        val whitelistDetected = allCaptiveFailed && ruOk

        return OperatorWhitelistProbeResult(
            whitelistDetected = whitelistDetected,
            googleReachable = googleOk,
            appleReachable = appleOk,
            firefoxReachable = firefoxOk,
            russianControlReachable = ruOk,
            errors = errors,
            durationMs = System.currentTimeMillis() - startMs,
        )
    }

    private fun buildClient(): OkHttpClient {
        val bootstrapAddresses = YANDEX_BOOTSTRAP_IPS.mapNotNull { ip ->
            runCatching { InetAddress.getByName(ip) }.getOrNull()
        }
        val baseClient = OkHttpClient.Builder().build()
        val doh = DnsOverHttps.Builder()
            .client(baseClient)
            .url(YANDEX_DOH_URL.toHttpUrl())
            .apply {
                if (bootstrapAddresses.isNotEmpty()) {
                    bootstrapDnsHosts(bootstrapAddresses)
                }
            }
            .build()
        return OkHttpClient.Builder()
            .dns(doh)
            .connectTimeout(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .callTimeout(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }

    private fun doRequest(url: String, method: String = "GET"): Pair<Int, String> {
        executeOverride?.let { return it(url, method) }
        val client = buildClient()
        val request = Request.Builder()
            .url(url)
            .method(method, null)
            .build()
        client.newCall(request).execute().use { response ->
            return response.code to (response.body?.string().orEmpty())
        }
    }

    private fun checkGoogle(errors: MutableMap<String, String>): Boolean {
        return runCatching {
            val (code, body) = doRequest("https://www.google.com/generate_204")
            code == 204 && body.isEmpty()
        }.getOrElse { e ->
            errors["google"] = e.message ?: e.javaClass.simpleName
            false
        }
    }

    private fun checkApple(errors: MutableMap<String, String>): Boolean {
        return runCatching {
            val (code, body) = doRequest("https://www.apple.com/library/test/success.html")
            code == 200 &&
                body.contains("<TITLE>Success</TITLE>", ignoreCase = false) &&
                body.contains("<BODY>Success</BODY>", ignoreCase = false)
        }.getOrElse { e ->
            errors["apple"] = e.message ?: e.javaClass.simpleName
            false
        }
    }

    private fun checkFirefox(errors: MutableMap<String, String>): Boolean {
        return runCatching {
            val (code, body) = doRequest("https://detectportal.firefox.com/success.txt")
            code == 200 && body.startsWith("success")
        }.getOrElse { e ->
            errors["firefox"] = e.message ?: e.javaClass.simpleName
            false
        }
    }

    private fun checkRussianControl(errors: MutableMap<String, String>): Boolean {
        return runCatching {
            val (code, _) = doRequest("https://yandex.ru/", method = "HEAD")
            code in 200..399
        }.getOrElse { e ->
            errors["yandex_ru"] = e.message ?: e.javaClass.simpleName
            false
        }
    }
}
