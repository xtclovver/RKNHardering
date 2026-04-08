package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Detects whether a non-VPN (underlying) network is reachable from this app.
 *
 * When VPN runs in split-tunnel / per-app mode, apps excluded from the tunnel
 * (or any app that can bind to the underlying network) can reach the VPN gateway
 * and any external host directly, leaking the real IP and confirming VPN usage.
 *
 * The probe enumerates all networks, finds one without TRANSPORT_VPN, binds an
 * HTTPS request to it, and fetches the public IP. Success means split-tunnel
 * vulnerability is present.
 */
object UnderlyingNetworkProber {

    data class ProbeResult(
        val vpnActive: Boolean,
        val underlyingReachable: Boolean,
        val vpnIp: String? = null,
        val underlyingIp: String? = null,
        val vpnNetwork: Network? = null,
        val underlyingNetwork: Network? = null,
    )

    private data class IpEndpoint(
        val url: String,
        val ruBased: Boolean,
    )

    private val IP_ENDPOINTS = listOf(
        IpEndpoint("https://ifconfig.me/ip", ruBased = false),
        IpEndpoint("https://checkip.amazonaws.com", ruBased = false),
        IpEndpoint("https://ipv4-internet.yandex.net/api/v0/ip", ruBased = true),
        IpEndpoint("https://ipv6-internet.yandex.net/api/v0/ip", ruBased = true),
    )

    private const val TIMEOUT_MS = 7000

    @Suppress("DEPRECATION")
    suspend fun probe(context: Context): ProbeResult = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val allNetworks = cm.allNetworks
        var vpnNetwork: Network? = null
        val nonVpnNetworks = mutableListOf<Network>()

        for (network in allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetwork = network
            } else {
                nonVpnNetworks.add(network)
            }
        }

        if (vpnNetwork == null) {
            return@withContext ProbeResult(vpnActive = false, underlyingReachable = false)
        }

        if (nonVpnNetworks.isEmpty()) {
            return@withContext ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnNetwork = vpnNetwork,
            )
        }

        val vpnIp = fetchIpViaNetwork(vpnNetwork)
        var underlyingIp: String? = null
        var usedNetwork: Network? = null

        for (network in nonVpnNetworks) {
            underlyingIp = fetchIpViaNetwork(network)
            if (underlyingIp != null) {
                usedNetwork = network
                break
            }
        }

        ProbeResult(
            vpnActive = true,
            underlyingReachable = underlyingIp != null,
            vpnIp = vpnIp,
            underlyingIp = underlyingIp,
            vpnNetwork = vpnNetwork,
            underlyingNetwork = usedNetwork,
        )
    }

    private fun fetchIpViaNetwork(network: Network): String? {
        for (endpoint in IP_ENDPOINTS) {
            val ip = fetchSingleIp(network, endpoint.url)
            if (ip != null) return ip
        }
        return null
    }

    private fun fetchSingleIp(network: Network, endpoint: String): String? {
        return try {
            val url = URL(endpoint)
            val connection = network.openConnection(url) as? HttpsURLConnection ?: return null
            connection.instanceFollowRedirects = true
            connection.requestMethod = "GET"
            connection.useCaches = false
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.setRequestProperty("User-Agent", "curl/8.0")
            connection.setRequestProperty("Accept", "text/plain")

            try {
                val code = connection.responseCode
                if (code !in 200..299) return null
                val body = connection.inputStream.bufferedReader().use { it.readText() }.trim()
                body.takeIf { it.isNotBlank() && looksLikeIp(it) }
            } finally {
                connection.disconnect()
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun looksLikeIp(text: String): Boolean {
        val trimmed = text.trim()
        if (trimmed.length > 45) return false
        return trimmed.matches(Regex("""[\d.:a-fA-F]+"""))
    }
}
