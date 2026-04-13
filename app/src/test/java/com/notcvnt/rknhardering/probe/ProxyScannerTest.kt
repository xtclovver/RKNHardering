package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class ProxyScannerTest {

    @Test
    fun `auto scan does not touch popular ports outside strict custom range`() = runBlocking {
        val probedPorts = mutableListOf<Int>()
        val scanner = ProxyScanner(
            popularPorts = listOf(1080, 7890),
            scanRange = 50000..50002,
            maxConcurrency = 1,
            progressUpdateEvery = 1,
            probePort = { _, port, _, _ ->
                probedPorts += port
                null
            },
        )

        scanner.findOpenProxyEndpoint(
            mode = ScanMode.AUTO,
            manualPort = null,
            onProgress = {},
        )

        assertEquals(listOf(50000, 50001, 50002), probedPorts.distinct())
        assertFalse(probedPorts.contains(1080))
        assertFalse(probedPorts.contains(7890))
    }

    @Test
    fun `popular only scan respects filtered popular ports within range`() = runBlocking {
        val probedPorts = mutableListOf<Int>()
        val scanner = ProxyScanner(
            popularPorts = listOf(1080, 7890),
            scanRange = 1024..1100,
            probePort = { _, port, _, _ ->
                probedPorts += port
                null
            },
        )

        scanner.findOpenProxyEndpoint(
            mode = ScanMode.POPULAR_ONLY,
            manualPort = null,
            onProgress = {},
        )

        assertEquals(listOf(1080), probedPorts.distinct())
    }
}
