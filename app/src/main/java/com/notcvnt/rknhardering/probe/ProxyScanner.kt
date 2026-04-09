package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.coroutineContext
import kotlin.math.max

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class ProxyScanner(
    private val loopbackHosts: List<String> = listOf("127.0.0.1", "::1"),
    private val popularPorts: List<Int> = DEFAULT_POPULAR_PORTS,
    private val scanRange: IntRange = 1024..65535,
    private val connectTimeoutMs: Int = 80,
    private val readTimeoutMs: Int = 120,
    private val maxConcurrency: Int = 200,
    private val progressUpdateEvery: Int = 256,
) {

    companion object {
        val DEFAULT_POPULAR_PORTS: List<Int> = (
            VpnAppCatalog.localhostProxyPorts + listOf(1081, 7890, 7891)
            ).distinct().sorted()
    }

    suspend fun findOpenProxyEndpoint(
        mode: ScanMode,
        manualPort: Int?,
        onProgress: suspend (ScanProgress) -> Unit,
    ): ProxyEndpoint? {
        return when (mode) {
            ScanMode.MANUAL -> {
                val port = manualPort ?: return null
                onProgress(
                    ScanProgress(
                        phase = ScanPhase.POPULAR_PORTS,
                        scanned = 1,
                        total = 1,
                        currentPort = port,
                    ),
                )
                tryPort(port)
            }

            ScanMode.AUTO -> {
                val foundOnPopular = scanPopularPorts(onProgress)
                if (foundOnPopular != null) return foundOnPopular
                scanFullRange(onProgress)
            }

            ScanMode.POPULAR_ONLY -> {
                scanPopularPorts(onProgress)
            }
        }
    }

    private suspend fun scanPopularPorts(
        onProgress: suspend (ScanProgress) -> Unit,
    ): ProxyEndpoint? {
        for ((index, port) in popularPorts.withIndex()) {
            coroutineContext.ensureActive()
            onProgress(
                ScanProgress(
                    phase = ScanPhase.POPULAR_PORTS,
                    scanned = index + 1,
                    total = popularPorts.size,
                    currentPort = port,
                ),
            )
            val found = tryPort(port)
            if (found != null) return found
        }
        return null
    }

    private suspend fun scanFullRange(
        onProgress: suspend (ScanProgress) -> Unit,
    ): ProxyEndpoint? = withContext(Dispatchers.IO) {
        coroutineScope {
            val popularSet = popularPorts.toHashSet()
            val total = scanRange.count { it !in popularSet }
            val scanned = AtomicInteger(0)
            val found = AtomicReference<ProxyEndpoint?>(null)

            val dispatcher = Dispatchers.IO.limitedParallelism(max(1, maxConcurrency))

            onProgress(
                ScanProgress(
                    phase = ScanPhase.FULL_RANGE,
                    scanned = 0,
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
                        if (port !in popularSet) {
                            val count = scanned.incrementAndGet()
                            if (count % progressUpdateEvery == 0) {
                                onProgress(
                                    ScanProgress(
                                        phase = ScanPhase.FULL_RANGE,
                                        scanned = count,
                                        total = total,
                                        currentPort = port,
                                    ),
                                )
                            }

                            val candidate = tryPort(port)
                            if (candidate != null) {
                                found.compareAndSet(null, candidate)
                                return@launch
                            }
                        }
                        port += maxConcurrency
                    }
                }
            }
            jobs.joinAll()

            found.get()
        }
    }

    private suspend fun tryPort(port: Int): ProxyEndpoint? = withContext(Dispatchers.IO) {
        for (host in loopbackHosts) {
            val type = ProxyProber.probeNoAuthProxyType(
                host = host,
                port = port,
                connectTimeoutMs = connectTimeoutMs,
                readTimeoutMs = readTimeoutMs,
            ) ?: continue

            return@withContext ProxyEndpoint(host, port, type)
        }
        null
    }
}
