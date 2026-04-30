package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.vpn.VpnAppCatalog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.ConcurrentHashMap
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
    private val probePort: suspend (String, Int, Int, Int) -> ProxyProber.ProbeResult? =
        { host, port, connectTimeout, readTimeout ->
            ProxyProber.probeProxyType(
                host = host,
                port = port,
                connectTimeoutMs = connectTimeout,
                readTimeoutMs = readTimeout,
            )
        },
) {

    companion object {
        val DEFAULT_POPULAR_PORTS: List<Int> = (
            VpnAppCatalog.localhostProxyPorts + listOf(1081, 7890, 7891)
            ).distinct().sorted()
    }

    private val filteredPopularPorts = popularPorts.filter { it in scanRange }

    suspend fun findOpenProxyEndpoint(
        mode: ScanMode,
        manualPort: Int?,
        onProgress: suspend (ScanProgress) -> Unit,
        preferredType: ProxyType? = null,
    ): ProxyEndpoint? = findOpenProxyEndpoints(
        mode = mode,
        manualPort = manualPort,
        onProgress = onProgress,
        preferredType = preferredType,
    ).firstOrNull()

    suspend fun findOpenProxyEndpoints(
        mode: ScanMode,
        manualPort: Int?,
        onProgress: suspend (ScanProgress) -> Unit,
        preferredType: ProxyType? = null,
    ): List<ProxyEndpoint> {
        return when (mode) {
            ScanMode.MANUAL -> {
                val port = manualPort ?: return emptyList()
                onProgress(
                    ScanProgress(
                        phase = ScanPhase.POPULAR_PORTS,
                        scanned = 1,
                        total = 1,
                        currentPort = port,
                    ),
                )
                listOfNotNull(tryPort(port, preferredType))
            }

            ScanMode.AUTO -> {
                scanPopularPorts(onProgress, preferredType) + scanFullRange(onProgress, preferredType)
            }

            ScanMode.POPULAR_ONLY -> scanPopularPorts(onProgress, preferredType)
        }
    }

    private suspend fun scanPopularPorts(
        onProgress: suspend (ScanProgress) -> Unit,
        preferredType: ProxyType?,
    ): List<ProxyEndpoint> {
        val found = mutableListOf<ProxyEndpoint>()
        for ((index, port) in filteredPopularPorts.withIndex()) {
            coroutineContext.ensureActive()
            onProgress(
                ScanProgress(
                    phase = ScanPhase.POPULAR_PORTS,
                    scanned = index + 1,
                    total = filteredPopularPorts.size,
                    currentPort = port,
                ),
            )
            tryPort(port, preferredType)?.let(found::add)
        }
        return found
    }

    private suspend fun scanFullRange(
        onProgress: suspend (ScanProgress) -> Unit,
        preferredType: ProxyType?,
    ): List<ProxyEndpoint> = withContext(Dispatchers.IO) {
        coroutineScope {
            val popularSet = filteredPopularPorts.toHashSet()
            val total = scanRange.count { it !in popularSet }
            val scanned = AtomicInteger(0)
            val found = ConcurrentHashMap<Int, ProxyEndpoint>()

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

                            val candidate = tryPort(port, preferredType)
                            if (candidate != null) {
                                found.putIfAbsent(port, candidate)
                            }
                        }
                        port += maxConcurrency
                    }
                }
            }
            jobs.joinAll()

            found.entries
                .sortedBy { it.key }
                .map { it.value }
        }
    }

    private suspend fun tryPort(port: Int, preferredType: ProxyType?): ProxyEndpoint? = withContext(Dispatchers.IO) {
        for (host in loopbackHosts) {
            val result = probePort(host, port, connectTimeoutMs, readTimeoutMs) ?: continue
            if (preferredType != null && result.type != preferredType) continue

            return@withContext ProxyEndpoint(host, port, result.type, result.authRequired)
        }
        null
    }
}
