package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException

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
    private data class BoundNetwork(
        val network: Network,
        val interfaceName: String?,
    )

    data class ProbeResult(
        val vpnActive: Boolean,
        val underlyingReachable: Boolean,
        val vpnIp: String? = null,
        val underlyingIp: String? = null,
        val vpnError: String? = null,
        val underlyingError: String? = null,
        val vpnNetwork: Network? = null,
        val underlyingNetwork: Network? = null,
        val activeNetworkIsVpn: Boolean? = null,
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
    suspend fun probe(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): ProbeResult = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        val activeNetworkIsVpn = activeNetwork
            ?.let(cm::getNetworkCapabilities)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

        val allNetworks = cm.allNetworks
        var vpnNetwork: BoundNetwork? = null
        val nonVpnNetworks = mutableListOf<BoundNetwork>()

        for (network in allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val boundNetwork = BoundNetwork(
                network = network,
                interfaceName = cm.getLinkProperties(network)?.interfaceName,
            )
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetwork = boundNetwork
            } else {
                nonVpnNetworks.add(boundNetwork)
            }
        }

        if (vpnNetwork == null) {
            return@withContext ProbeResult(
                vpnActive = false,
                underlyingReachable = false,
                activeNetworkIsVpn = activeNetworkIsVpn,
            )
        }

        val vpnResult = fetchIpViaNetwork(vpnNetwork, resolverConfig)
        val vpnIp = vpnResult.getOrNull()
        val vpnError = vpnResult.exceptionOrNull()?.message

        if (nonVpnNetworks.isEmpty()) {
            return@withContext ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = vpnIp,
                vpnError = vpnError,
                vpnNetwork = vpnNetwork.network,
                activeNetworkIsVpn = activeNetworkIsVpn,
            )
        }

        var underlyingIp: String? = null
        var underlyingError: String? = null
        var usedNetwork: Network? = null

        for (network in nonVpnNetworks) {
            val result = fetchIpViaNetwork(network, resolverConfig)
            underlyingIp = result.getOrNull()
            if (underlyingIp != null) {
                usedNetwork = network.network
                underlyingError = null
                break
            }
            underlyingError = result.exceptionOrNull()?.message ?: underlyingError
        }

        ProbeResult(
            vpnActive = true,
            underlyingReachable = underlyingIp != null,
            vpnIp = vpnIp,
            underlyingIp = underlyingIp,
            vpnError = vpnError,
            underlyingError = underlyingError,
            vpnNetwork = vpnNetwork.network,
            underlyingNetwork = usedNetwork,
            activeNetworkIsVpn = activeNetworkIsVpn,
        )
    }

    private fun fetchIpViaNetwork(
        boundNetwork: BoundNetwork,
        resolverConfig: DnsResolverConfig,
    ): Result<String> {
        var lastError: Exception? = null
        val primaryBinding = ResolverBinding.AndroidNetworkBinding(boundNetwork.network)
        for (endpoint in IP_ENDPOINTS) {
            val result = PublicIpClient.fetchIp(
                endpoint = endpoint.url,
                timeoutMs = TIMEOUT_MS,
                resolverConfig = resolverConfig,
                binding = primaryBinding,
            )
            if (result.isSuccess) return result
            lastError = result.exceptionOrNull() as? Exception ?: lastError
        }
        val fallbackBinding = boundNetwork.interfaceName
            ?.takeIf { it.isNotBlank() }
            ?.let { ResolverBinding.OsDeviceBinding(it, dnsMode = ResolverBinding.DnsMode.SYSTEM) }
        if (fallbackBinding == null) {
            val message = lastError?.message?.let {
                "$it; OS device bind fallback is unavailable because interfaceName is missing"
            } ?: "OS device bind fallback is unavailable because interfaceName is missing"
            return Result.failure(IOException(message))
        }

        // Fallback: keep system DNS semantics from the old second pass, but switch transport
        // binding to real SO_BINDTODEVICE instead of Android's Network.bindSocket().
        for (endpoint in IP_ENDPOINTS) {
            val result = PublicIpClient.fetchIp(
                endpoint = endpoint.url,
                timeoutMs = TIMEOUT_MS,
                resolverConfig = resolverConfig,
                binding = fallbackBinding,
            )
            if (result.isSuccess) return result
            lastError = result.exceptionOrNull() as? Exception ?: lastError
        }
        return Result.failure(lastError ?: IOException("All IP endpoints failed"))
    }
}
