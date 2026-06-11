package com.notcvnt.rknhardering.probe

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Probes the localhost REST management API exposed by Clash / mihomo / sing-box
 * proxy cores. These cores listen on loopback (default ports 9090/19090/9091/9097)
 * and serve unauthenticated JSON over plain HTTP. The /connections endpoint leaks
 * the real destination IPs of active VPN-server tunnels.
 *
 * Parsing helpers live in the companion object (pure, statically testable);
 * networking is per-instance.
 */
class ClashApiClient(
    private val host: String = "127.0.0.1",
    private val timeoutMs: Long = 600,
) {
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
        .callTimeout(timeoutMs * 2, TimeUnit.MILLISECONDS)
        .build()

    fun fetchConfigs(port: Int): String? = httpGet(port, "/configs")
    fun fetchConnections(port: Int): String? = httpGet(port, "/connections")
    fun fetchProxies(port: Int): String? = httpGet(port, "/proxies")

    private fun httpGet(port: Int, path: String): String? {
        val bracketHost = if (host.contains(':')) "[$host]" else host
        val url = "http://$bracketHost:$port$path"
        return runCatching {
            client.newCall(Request.Builder().url(url).build()).execute().use { resp ->
                if (!resp.isSuccessful) null else resp.body?.string()
            }
        }.getOrNull()
    }

    companion object {
        fun isConfigResponseAlive(body: String?): Boolean {
            if (body.isNullOrBlank()) return false
            return runCatching { JSONObject(body); true }.getOrDefault(false)
        }

        fun parseConnectionsDestinationIps(body: String?): List<String> {
            if (body.isNullOrBlank()) return emptyList()
            return runCatching {
                val arr = JSONObject(body).optJSONArray("connections") ?: return emptyList()
                buildList {
                    for (i in 0 until arr.length()) {
                        val meta = arr.optJSONObject(i)?.optJSONObject("metadata") ?: continue
                        val ip = meta.optString("destinationIP").takeIf { it.isNotBlank() } ?: continue
                        add(ip)
                    }
                }
            }.getOrDefault(emptyList())
        }

        fun parseProxyNodes(body: String?): List<String> {
            if (body.isNullOrBlank()) return emptyList()
            return runCatching {
                val proxies = JSONObject(body).optJSONObject("proxies") ?: return emptyList()
                proxies.keys().asSequence().toList()
            }.getOrDefault(emptyList())
        }
    }
}
