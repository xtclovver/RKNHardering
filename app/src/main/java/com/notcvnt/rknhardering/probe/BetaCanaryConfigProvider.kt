package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.BuildConfig

internal object BetaCanaryConfigProvider {
    fun configuredEndpoint(): BetaCanaryEndpointConfig? {
        val ipv4 = BuildConfig.BETA_CANARY_IPV4.takeIf(String::isNotBlank)
        val ipv6 = BuildConfig.BETA_CANARY_IPV6.takeIf(String::isNotBlank)
        if (ipv4 == null && ipv6 == null) return null
        return BetaCanaryEndpointConfig(
            ipv4Address = ipv4,
            ipv6Address = ipv6,
            httpPort = BuildConfig.BETA_CANARY_HTTP_PORT,
            httpsPort = BuildConfig.BETA_CANARY_HTTPS_PORT.takeIf { it > 0 },
            tcpPort = BuildConfig.BETA_CANARY_TCP_PORT,
            udpPort = BuildConfig.BETA_CANARY_UDP_PORT,
            dnsPort = BuildConfig.BETA_CANARY_DNS_PORT,
            dnsZone = BuildConfig.BETA_CANARY_DNS_ZONE,
            tlsServerName = BuildConfig.BETA_CANARY_TLS_NAME.takeIf(String::isNotBlank),
            tlsSpkiSha256 = BuildConfig.BETA_CANARY_TLS_SPKI.takeIf(String::isNotBlank),
        )
    }
}
