package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.rethrowIfCancellation
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.DnsResolverMode
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.URL
import java.util.UUID

internal object NativeCurlTransportProbe {
    private const val DEFAULT_PORT = 443

    suspend fun fetchModeProbeResult(
        mode: PublicIpProbeMode,
        endpoints: List<IpEndpointSpec>,
        timeoutMs: Int,
        resolverConfig: DnsResolverConfig,
        binding: com.notcvnt.rknhardering.network.ResolverBinding.OsDeviceBinding,
        collectTrace: Boolean,
        executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
    ): PublicIpModeProbeResult {
        val endpointAttempts = if (collectTrace) mutableListOf<TunEndpointAttempt>() else null
        var lastError: String? = null
        var lastDiagnostics = PublicIpTransportDiagnostics(
            engine = TunProbeEngine.NATIVE_LIBCURL,
            resolveStrategy = TunProbeResolveStrategy.NATIVE_DEFAULT,
            nativeLibraryLoaded = NativeCurlBridge.isLibraryLoaded(),
            caBundleVersion = NativeCurlBridge.caBundleInfo()?.versionHash,
        )

        for (endpoint in endpoints) {
            executionContext.throwIfCancelled()
            val resolveConfig = try {
                resolveConfigFor(endpoint, resolverConfig, binding, executionContext)
            } catch (error: Exception) {
                rethrowIfCancellation(error, executionContext)
                val diagnostics = diagnosticsFor(
                    resolveStrategy = resolveStrategyFor(resolverConfig),
                    response = NativeCurlResponse(localError = error.renderMessage()),
                    resolvedAddresses = emptyList(),
                )
                endpointAttempts?.add(
                    TunEndpointAttempt(
                        endpoint = endpoint.url,
                        familyHint = endpoint.familyHint.name,
                        status = PublicIpProbeStatus.FAILED,
                        error = error.renderMessage(),
                    ),
                )
                lastError = error.renderMessage()
                lastDiagnostics = diagnostics
                continue
            }

            val requestId = "native-probe-${UUID.randomUUID()}"
            val cancellationRegistration = registerNativeCancellation(requestId, executionContext.cancellationSignal)
            val response = try {
                NativeCurlBridge.execute(
                    NativeCurlRequest(
                        url = endpoint.url,
                        interfaceName = binding.interfaceName,
                        resolveRules = resolveConfig.resolveRules,
                        ipResolveMode = ipResolveModeFor(endpoint.familyHint),
                        timeoutMs = timeoutMs,
                        connectTimeoutMs = timeoutMs,
                        caBundlePath = NativeCurlBridge.caBundleInfo()?.absolutePath.orEmpty(),
                        debugVerbose = collectTrace,
                    ),
                    requestId = requestId,
                )
            } finally {
                cancellationRegistration.dispose()
            }
            executionContext.throwIfCancelled()
            val diagnostics = diagnosticsFor(
                resolveStrategy = resolveConfig.strategy,
                response = response,
                resolvedAddresses = resolveConfig.resolvedAddresses,
            )
            lastDiagnostics = diagnostics
            val ipResult = response.toIpResult(endpoint.url)
            endpointAttempts?.add(
                TunEndpointAttempt(
                    endpoint = endpoint.url,
                    familyHint = endpoint.familyHint.name,
                    status = if (ipResult.isSuccess) PublicIpProbeStatus.SUCCEEDED else PublicIpProbeStatus.FAILED,
                    ip = ipResult.getOrNull(),
                    error = ipResult.exceptionOrNull().renderMessage(),
                ),
            )
            if (ipResult.isSuccess) {
                return PublicIpModeProbeResult(
                    mode = mode,
                    status = PublicIpProbeStatus.SUCCEEDED,
                    ip = ipResult.getOrNull(),
                    endpointAttempts = endpointAttempts.orEmpty(),
                    transportDiagnostics = diagnostics,
                )
            }
            lastError = ipResult.exceptionOrNull().renderMessage()
        }

        return PublicIpModeProbeResult(
            mode = mode,
            status = PublicIpProbeStatus.FAILED,
            error = lastError ?: "Native curl-compatible probe failed",
            endpointAttempts = endpointAttempts.orEmpty(),
            transportDiagnostics = lastDiagnostics,
        )
    }

    private data class ResolveConfig(
        val strategy: TunProbeResolveStrategy,
        val resolveRules: List<NativeCurlResolveRule>,
        val resolvedAddresses: List<String>,
    )

    private fun resolveConfigFor(
        endpoint: IpEndpointSpec,
        resolverConfig: DnsResolverConfig,
        binding: com.notcvnt.rknhardering.network.ResolverBinding.OsDeviceBinding,
        executionContext: ScanExecutionContext,
    ): ResolveConfig {
        if (resolverConfig.mode == DnsResolverMode.SYSTEM) {
            return ResolveConfig(
                strategy = TunProbeResolveStrategy.NATIVE_DEFAULT,
                resolveRules = emptyList(),
                resolvedAddresses = emptyList(),
            )
        }

        val host = URL(endpoint.url).host
        val port = URL(endpoint.url).port.takeIf { it > 0 } ?: DEFAULT_PORT
        val resolvedAddresses = ResolverNetworkStack.lookup(
            hostname = host,
            config = resolverConfig,
            binding = binding,
            cancellationSignal = executionContext.cancellationSignal,
        )
            .filter { address ->
                when (endpoint.familyHint) {
                    IpEndpointFamilyHint.GENERIC -> true
                    IpEndpointFamilyHint.IPV4 -> address is Inet4Address
                    IpEndpointFamilyHint.IPV6 -> address is Inet6Address
                }
            }
            .mapNotNull { it.hostAddress }
            .distinct()

        if (resolvedAddresses.isEmpty()) {
            throw IOException("Resolver returned no addresses for $host")
        }

        return ResolveConfig(
            strategy = TunProbeResolveStrategy.KOTLIN_INJECTED,
            resolveRules = listOf(NativeCurlResolveRule(host = host, port = port, addresses = resolvedAddresses)),
            resolvedAddresses = resolvedAddresses,
        )
    }

    private fun diagnosticsFor(
        resolveStrategy: TunProbeResolveStrategy,
        response: NativeCurlResponse,
        resolvedAddresses: List<String>,
    ): PublicIpTransportDiagnostics {
        return PublicIpTransportDiagnostics(
            engine = TunProbeEngine.NATIVE_LIBCURL,
            resolveStrategy = resolveStrategy,
            curlCode = response.curlCode,
            httpCode = response.httpCode,
            nativeLibraryLoaded = NativeCurlBridge.isLibraryLoaded(),
            caBundleVersion = NativeCurlBridge.caBundleInfo()?.versionHash,
            resolvedAddressesUsed = response.resolvedAddressesUsed.ifEmpty { resolvedAddresses },
        )
    }

    private fun ipResolveModeFor(familyHint: IpEndpointFamilyHint): NativeCurlIpResolveMode {
        return when (familyHint) {
            IpEndpointFamilyHint.GENERIC -> NativeCurlIpResolveMode.WHATEVER
            IpEndpointFamilyHint.IPV4 -> NativeCurlIpResolveMode.V4
            IpEndpointFamilyHint.IPV6 -> NativeCurlIpResolveMode.V6
        }
    }

    private fun resolveStrategyFor(config: DnsResolverConfig): TunProbeResolveStrategy {
        return if (config.mode == DnsResolverMode.SYSTEM) {
            TunProbeResolveStrategy.NATIVE_DEFAULT
        } else {
            TunProbeResolveStrategy.KOTLIN_INJECTED
        }
    }

    private fun NativeCurlResponse.toIpResult(endpoint: String): Result<String> {
        localError?.let { return Result.failure(IOException(it)) }
        errorBuffer?.takeIf { it.isNotBlank() }?.let { return Result.failure(IOException(it)) }
        val code = httpCode ?: 0
        if (code !in 200..299) {
            return Result.failure(IOException(PublicIpClient.formatHttpError(code, body)))
        }
        val ip = PublicIpClient.extractIp(body, endpoint)
            ?: return Result.failure(IOException("Response does not look like an IP: ${body.trim()}"))
        return Result.success(ip)
    }

    private fun Throwable?.renderMessage(): String {
        return this?.message
            ?: this?.javaClass?.simpleName
            ?: "unknown error"
    }

    private fun registerNativeCancellation(
        requestId: String,
        cancellationSignal: ScanCancellationSignal,
    ): ScanCancellationSignal.Registration {
        return cancellationSignal.register {
            NativeCurlBridge.cancelRequest(requestId)
        }
    }
}
