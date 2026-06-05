package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.customcheck.CustomDomain
import com.notcvnt.rknhardering.model.DomainReachabilityResponse
import com.notcvnt.rknhardering.model.DomainReachabilityResult
import com.notcvnt.rknhardering.model.DomainReachabilityStepStatus
import com.notcvnt.rknhardering.network.DnsResolverConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket

/**
 * Checks domain reachability by performing a DNS → TCP → TLS handshake pipeline.
 *
 * This detects DPI-level blocking at each layer:
 * - DNS: NXDOMAIN / timeout → DNS-level blocking
 * - TCP: Connection refused / timeout → IP-level blocking
 * - TLS: Connection reset during handshake → DPI (SNI-based) blocking
 */
object DomainReachabilityChecker {

    private const val DEFAULT_PORT = 443
    private const val TCP_TIMEOUT_MS = 8_000
    private const val TLS_TIMEOUT_MS = 10_000
    private const val DNS_TIMEOUT_MS = 8_000
    private const val CONNECTION_RESET_DPI = "Connection Reset (DPI)"

    suspend fun check(
        context: Context,
        domains: List<CustomDomain>,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): DomainReachabilityResult = withContext(Dispatchers.IO) {
        if (domains.isEmpty()) return@withContext DomainReachabilityResult.empty()

        supervisorScope {
            val responses = domains.map { domain ->
                async {
                    checkSingleDomain(
                        domain = domain.domain,
                        label = domain.description.ifEmpty { domain.domain },
                        expectedDns = domain.expectedDnsAvailable,
                        expectedTcp = domain.expectedTcpAvailable,
                        expectedTls = domain.expectedTlsAvailable,
                    )
                }
            }.awaitAll()

            DomainReachabilityResult(responses = responses)
        }
    }

    internal suspend fun checkSingleDomain(
        domain: String,
        label: String,
        expectedDns: Boolean = true,
        expectedTcp: Boolean = true,
        expectedTls: Boolean = true,
    ): DomainReachabilityResponse = withContext(Dispatchers.IO) {
        // Step 1: DNS Resolution
        val dnsResult = resolveDns(domain)
        if (dnsResult.status == DomainReachabilityStepStatus.FAILED) {
            return@withContext DomainReachabilityResponse(
                domain = domain,
                label = label,
                dnsStatus = DomainReachabilityStepStatus.FAILED,
                dnsError = dnsResult.error,
                resolvedIps = emptyList(),
                expectedDnsAvailable = expectedDns,
                expectedTcpAvailable = expectedTcp,
                expectedTlsAvailable = expectedTls,
            )
        }

        val resolvedIps = dnsResult.ips
        val targetIp = resolvedIps.firstOrNull() ?: return@withContext DomainReachabilityResponse(
            domain = domain,
            label = label,
            dnsStatus = DomainReachabilityStepStatus.FAILED,
            dnsError = "No addresses resolved",
            expectedDnsAvailable = expectedDns,
            expectedTcpAvailable = expectedTcp,
            expectedTlsAvailable = expectedTls,
        )

        // Step 2: TCP Connect
        val tcpResult = checkTcp(targetIp, DEFAULT_PORT)
        if (tcpResult.status == DomainReachabilityStepStatus.FAILED) {
            return@withContext DomainReachabilityResponse(
                domain = domain,
                label = label,
                dnsStatus = DomainReachabilityStepStatus.OK,
                resolvedIps = resolvedIps,
                tcpStatus = DomainReachabilityStepStatus.FAILED,
                tcpError = tcpResult.error,
                expectedDnsAvailable = expectedDns,
                expectedTcpAvailable = expectedTcp,
                expectedTlsAvailable = expectedTls,
            )
        }

        // Step 3: TLS Handshake with SNI
        val tlsResult = checkTls(targetIp, DEFAULT_PORT, domain)
        DomainReachabilityResponse(
            domain = domain,
            label = label,
            dnsStatus = DomainReachabilityStepStatus.OK,
            resolvedIps = resolvedIps,
            tcpStatus = DomainReachabilityStepStatus.OK,
            tlsStatus = tlsResult.status,
            tlsError = tlsResult.error,
            expectedDnsAvailable = expectedDns,
            expectedTcpAvailable = expectedTcp,
            expectedTlsAvailable = expectedTls,
        )
    }

    private data class StepResult(
        val status: DomainReachabilityStepStatus,
        val error: String? = null,
        val ips: List<String> = emptyList(),
    )

    private suspend fun resolveDns(domain: String): StepResult = withContext(Dispatchers.IO) {
        try {
            val result = withTimeoutOrNull(DNS_TIMEOUT_MS.toLong()) {
                withContext(Dispatchers.IO) {
                    val addresses = InetAddress.getAllByName(domain)
                    addresses.map { it.hostAddress ?: it.toString() }
                }
            }
            if (result == null) {
                StepResult(DomainReachabilityStepStatus.FAILED, "DNS timeout")
            } else if (result.isEmpty()) {
                StepResult(DomainReachabilityStepStatus.FAILED, "NXDOMAIN")
            } else {
                StepResult(DomainReachabilityStepStatus.OK, ips = result)
            }
        } catch (e: java.net.UnknownHostException) {
            StepResult(DomainReachabilityStepStatus.FAILED, "NXDOMAIN")
        } catch (e: Exception) {
            StepResult(DomainReachabilityStepStatus.FAILED, e.message ?: e::class.java.simpleName)
        }
    }

    private suspend fun checkTcp(ip: String, port: Int): StepResult = withContext(Dispatchers.IO) {
        try {
            val result = withTimeoutOrNull(TCP_TIMEOUT_MS.toLong()) {
                withContext(Dispatchers.IO) {
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress(ip, port), TCP_TIMEOUT_MS)
                    }
                    true
                }
            }
            if (result == null) {
                StepResult(DomainReachabilityStepStatus.FAILED, "TCP timeout")
            } else {
                StepResult(DomainReachabilityStepStatus.OK)
            }
        } catch (e: java.net.ConnectException) {
            StepResult(DomainReachabilityStepStatus.FAILED, "Connection refused")
        } catch (e: java.net.SocketTimeoutException) {
            StepResult(DomainReachabilityStepStatus.FAILED, "TCP timeout")
        } catch (e: Exception) {
            StepResult(DomainReachabilityStepStatus.FAILED, e.message ?: e::class.java.simpleName)
        }
    }

    private suspend fun checkTls(ip: String, port: Int, sniHost: String): StepResult =
        withContext(Dispatchers.IO) {
            try {
                val result = withTimeoutOrNull(TLS_TIMEOUT_MS.toLong()) {
                    withContext(Dispatchers.IO) {
                        val sslContext = SSLContext.getInstance("TLS")
                        sslContext.init(null, arrayOf(TrustAllManager()), null)

                        val socket = Socket()
                        socket.connect(InetSocketAddress(ip, port), TCP_TIMEOUT_MS)
                        socket.soTimeout = TLS_TIMEOUT_MS

                        val sslSocket = sslContext.socketFactory.createSocket(
                            socket,
                            sniHost,
                            port,
                            true,
                        ) as SSLSocket

                        sslSocket.use { ssl ->
                            val params = SSLParameters()
                            params.serverNames = listOf(SNIHostName(sniHost))
                            ssl.sslParameters = params
                            ssl.startHandshake()
                        }
                        true
                    }
                }
                if (result == null) {
                    StepResult(DomainReachabilityStepStatus.FAILED, "TLS timeout")
                } else {
                    StepResult(DomainReachabilityStepStatus.OK)
                }
            } catch (e: javax.net.ssl.SSLHandshakeException) {
                // Certificate errors are fine — the handshake itself completed, meaning DPI didn't block
                StepResult(DomainReachabilityStepStatus.OK)
            } catch (e: java.net.SocketException) {
                val msg = e.message?.lowercase() ?: ""
                val error = when {
                    msg.contains("reset") -> CONNECTION_RESET_DPI
                    msg.contains("refused") -> "Connection Refused"
                    msg.contains("broken pipe") -> CONNECTION_RESET_DPI
                    else -> e.message ?: "SocketException"
                }
                StepResult(DomainReachabilityStepStatus.FAILED, error)
            } catch (e: java.io.EOFException) {
                StepResult(DomainReachabilityStepStatus.FAILED, CONNECTION_RESET_DPI)
            } catch (e: javax.net.ssl.SSLException) {
                val msg = e.message?.lowercase() ?: ""
                if (msg.contains("reset") || msg.contains("closed") || msg.contains("peer")) {
                    StepResult(DomainReachabilityStepStatus.FAILED, CONNECTION_RESET_DPI)
                } else {
                    // Other SSL errors (protocol, etc.) — handshake at least started
                    StepResult(DomainReachabilityStepStatus.OK)
                }
            } catch (e: Exception) {
                StepResult(
                    DomainReachabilityStepStatus.FAILED,
                    e.message ?: e::class.java.simpleName,
                )
            }
        }

    /**
     * Trust-all X509 manager — we don't care about certificate validity,
     * only whether the TLS handshake completes without DPI interference.
     */
    private class TrustAllManager : javax.net.ssl.X509TrustManager {
        override fun checkClientTrusted(
            chain: Array<out java.security.cert.X509Certificate>?,
            authType: String?,
        ) = Unit

        override fun checkServerTrusted(
            chain: Array<out java.security.cert.X509Certificate>?,
            authType: String?,
        ) = Unit

        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
    }
}
