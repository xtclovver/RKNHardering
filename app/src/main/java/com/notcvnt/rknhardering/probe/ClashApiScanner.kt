package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.registerSocket
import com.notcvnt.rknhardering.rethrowIfCancellation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

data class ClashApiEndpoint(val host: String, val port: Int)

data class ClashApiScanResult(
    val endpoint: ClashApiEndpoint,
    val leakedDestIps: List<String>,
    val proxyNodes: List<String>,
    val configAvailable: Boolean,
)

/**
 * Scans loopback for an exposed Clash / mihomo / sing-box REST management API.
 * Mirrors [XrayApiScanner]'s structure: a small fixed port list, optional
 * override lambdas for testing, and cooperative cancellation via
 * [ScanExecutionContext].
 */
class ClashApiScanner(
    private val loopbackHosts: List<String> = listOf("127.0.0.1", "::1"),
    private val scanPorts: List<Int> = DEFAULT_PORTS,
    private val connectTimeoutMs: Int = 200,
    private val isTcpPortOpenOverride: ((String, Int) -> Boolean)? = null,
    private val probeApiOverride: (suspend (String, Int) -> ClashApiScanResult?)? = null,
) {
    companion object {
        val DEFAULT_PORTS: List<Int> = listOf(9090, 19090, 9091, 9097)
    }

    private val clients = loopbackHosts.associateWith { ClashApiClient(it) }

    suspend fun findClashApi(
        onProgress: suspend (Int, Int) -> Unit,
    ): ClashApiScanResult? = withContext(Dispatchers.IO) {
        val total = scanPorts.size * loopbackHosts.size
        var scanned = 0
        for (host in loopbackHosts) {
            for (port in scanPorts) {
                ScanExecutionContext.currentOrDefault().throwIfCancelled()
                scanned++
                onProgress(scanned, total)
                if (!isTcpPortOpen(host, port)) continue
                val result = probeApi(host, port)
                if (result != null) return@withContext result
            }
        }
        null
    }

    private suspend fun probeApi(host: String, port: Int): ClashApiScanResult? {
        probeApiOverride?.let { return it(host, port) }
        val client = clients.getValue(host)
        val configs = client.fetchConfigs(port)
        if (!ClashApiClient.isConfigResponseAlive(configs)) return null
        val connections = client.fetchConnections(port)
        val proxies = client.fetchProxies(port)
        return ClashApiScanResult(
            endpoint = ClashApiEndpoint(host, port),
            leakedDestIps = ClashApiClient.parseConnectionsDestinationIps(connections),
            proxyNodes = ClashApiClient.parseProxyNodes(proxies),
            configAvailable = true,
        )
    }

    private fun isTcpPortOpen(host: String, port: Int): Boolean {
        isTcpPortOpenOverride?.let { return it(host, port) }
        val executionContext = ScanExecutionContext.currentOrDefault()
        return try {
            Socket().use { socket ->
                val registration = executionContext.cancellationSignal.registerSocket(socket)
                try {
                    socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
                } finally {
                    registration.dispose()
                }
            }
            true
        } catch (error: Exception) {
            rethrowIfCancellation(error, executionContext)
            false
        }
    }
}
