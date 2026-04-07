package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.coroutineContext
import kotlin.math.max

data class XrayApiEndpoint(
    val host: String,
    val port: Int,
)

data class XrayOutboundSummary(
    val tag: String,
    val protocolName: String?,
    val address: String?,
    val port: Int?,
    val uuid: String?,
    val sni: String?,
    val publicKey: String?,
    val senderSettingsType: String?,
    val proxySettingsType: String?,
)

data class XrayApiScanResult(
    val endpoint: XrayApiEndpoint,
    val outbounds: List<XrayOutboundSummary>,
)

data class XrayScanProgress(
    val host: String,
    val scanned: Int,
    val total: Int,
    val currentPort: Int,
)

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class XrayApiScanner(
    private val loopbackHosts: List<String> = listOf("127.0.0.1", "::1"),
    private val scanRange: IntRange = 1024..65535,
    private val connectTimeoutMs: Int = 200,
    private val grpcDeadlineMs: Long = 2000,
    private val maxConcurrency: Int = 100,
    private val progressUpdateEvery: Int = 512,
) {
    private val clients = loopbackHosts.associateWith { XrayApiClient(it) }

    suspend fun findXrayApi(
        onProgress: suspend (XrayScanProgress) -> Unit,
    ): XrayApiScanResult? = withContext(Dispatchers.IO) {
        val portsTotal = (scanRange.last - scanRange.first + 1).coerceAtLeast(0)
        val total = portsTotal * loopbackHosts.size

        var scannedOffset = 0
        for (host in loopbackHosts) {
            val result = scanHost(
                host = host,
                scannedOffset = scannedOffset,
                total = total,
                onProgress = onProgress,
            )
            if (result != null) return@withContext result
            scannedOffset += portsTotal
        }

        null
    }

    private suspend fun scanHost(
        host: String,
        scannedOffset: Int,
        total: Int,
        onProgress: suspend (XrayScanProgress) -> Unit,
    ): XrayApiScanResult? = coroutineScope {
        val portsTotal = (scanRange.last - scanRange.first + 1).coerceAtLeast(0)
        if (portsTotal <= 0) return@coroutineScope null

        val scanned = AtomicInteger(0)
        val found = AtomicReference<XrayApiScanResult?>(null)

        val dispatcher = Dispatchers.IO.limitedParallelism(max(1, maxConcurrency))

        onProgress(
            XrayScanProgress(
                host = host,
                scanned = scannedOffset,
                total = total,
                currentPort = scanRange.first,
            ),
        )

        val jobs = (0 until maxConcurrency).map { workerIndex ->
            launch(dispatcher) {
                var port = scanRange.first + workerIndex
                while (port <= scanRange.last) {
                    coroutineContext.ensureActive()
                    if (found.get() != null) return@launch

                    val count = scanned.incrementAndGet()
                    if (count % progressUpdateEvery == 0) {
                        onProgress(
                            XrayScanProgress(
                                host = host,
                                scanned = scannedOffset + count,
                                total = total,
                                currentPort = port,
                            ),
                        )
                    }

                    if (isTcpPortOpen(host, port)) {
                        val result = tryListOutbounds(host, port)
                        if (result != null) {
                            found.compareAndSet(null, result)
                            return@launch
                        }
                    }

                    port += maxConcurrency
                }
            }
        }

        jobs.joinAll()

        onProgress(
            XrayScanProgress(
                host = host,
                scanned = scannedOffset + portsTotal,
                total = total,
                currentPort = scanRange.last,
            ),
        )

        found.get()
    }

    private suspend fun tryListOutbounds(host: String, port: Int): XrayApiScanResult? {
        val client = clients.getValue(host)
        client.listOutbounds(port, deadlineMs = grpcDeadlineMs).getOrNull()?.let { return it }
        val retryDeadline = (grpcDeadlineMs * 3).coerceAtLeast(2000)
        return client.listOutbounds(port, deadlineMs = retryDeadline).getOrNull()
    }

    private fun isTcpPortOpen(host: String, port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
            }
            true
        } catch (_: Exception) {
            false
        }
    }
}
