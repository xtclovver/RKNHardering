package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy

object IfconfigClient {

    private val ENDPOINTS = listOf(
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
        "https://ipv4-internet.yandex.net/api/v0/ip",
        "https://ipv6-internet.yandex.net/api/v0/ip",
        "https://ip.mail.ru",
    )

    suspend fun fetchDirectIp(
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): Result<String> = fetchIpWithFallback(
        timeoutMs = timeoutMs,
        resolverConfig = resolverConfig,
    )

    suspend fun fetchIpViaProxy(
        endpoint: ProxyEndpoint,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): Result<String> = fetchIpWithFallback(
        timeoutMs = timeoutMs,
        resolverConfig = resolverConfig,
        proxy = Proxy(
            when (endpoint.type) {
                ProxyType.SOCKS5 -> Proxy.Type.SOCKS
                ProxyType.HTTP -> Proxy.Type.HTTP
            },
            InetSocketAddress(endpoint.host, endpoint.port),
        ),
    )

    suspend fun fetchIpViaNetwork(
        primaryBinding: ResolverBinding.AndroidNetworkBinding,
        fallbackBinding: ResolverBinding.OsDeviceBinding? = null,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): Result<String> = fetchIpWithFallback(
        timeoutMs = timeoutMs,
        resolverConfig = resolverConfig,
        binding = primaryBinding,
        fallbackBinding = fallbackBinding,
    )

    private suspend fun fetchIpWithFallback(
        timeoutMs: Int,
        resolverConfig: DnsResolverConfig,
        proxy: Proxy? = null,
        binding: ResolverBinding? = null,
        fallbackBinding: ResolverBinding.OsDeviceBinding? = null,
    ): Result<String> = withContext(Dispatchers.IO) {
        var lastError: Exception? = null
        for (ep in ENDPOINTS) {
            val result = PublicIpClient.fetchIp(
                endpoint = ep,
                timeoutMs = timeoutMs,
                proxy = proxy,
                resolverConfig = resolverConfig,
                binding = binding,
            )
            if (result.isSuccess) return@withContext result
            lastError = result.exceptionOrNull() as? Exception ?: lastError
        }
        if (fallbackBinding != null) {
            for (ep in ENDPOINTS) {
                val result = PublicIpClient.fetchIp(
                    endpoint = ep,
                    timeoutMs = timeoutMs,
                    proxy = proxy,
                    resolverConfig = resolverConfig,
                    binding = fallbackBinding,
                )
                if (result.isSuccess) return@withContext result
                lastError = result.exceptionOrNull() as? Exception ?: lastError
            }
        }
        Result.failure(lastError ?: IOException("All IP endpoints failed"))
    }
}
