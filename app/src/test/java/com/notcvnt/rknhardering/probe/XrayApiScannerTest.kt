package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayApiScannerTest {

    @Test
    fun `custom scan range does not probe ports outside selected range`() = runBlocking {
        val probedPorts = mutableListOf<Int>()
        val scanner = XrayApiScanner(
            loopbackHosts = listOf("127.0.0.1"),
            scanRange = 50000..50002,
            maxConcurrency = 1,
            progressUpdateEvery = 1,
            isTcpPortOpenOverride = { _, port ->
                probedPorts += port
                false
            },
        )

        val result = scanner.findXrayApi(onProgress = {})

        assertNull(result)
        assertEquals(listOf(50000, 50001, 50002), probedPorts)
        assertFalse(probedPorts.contains(10085))
    }

    @Test
    fun `popular scan probes only configured xray api ports`() = runBlocking {
        val probedPorts = mutableListOf<Int>()
        val scanner = XrayApiScanner(
            loopbackHosts = listOf("127.0.0.1"),
            scanPorts = listOf(8080, 10085, 8080),
            maxConcurrency = 1,
            progressUpdateEvery = 1,
            isTcpPortOpenOverride = { _, port ->
                probedPorts += port
                false
            },
        )

        val result = scanner.findXrayApi(onProgress = {})

        assertNull(result)
        assertEquals(listOf(8080, 10085), probedPorts)
    }

    @Test
    fun `stats service detects xray api when handler service is unavailable`() = runBlocking {
        val scanner = XrayApiScanner(
            loopbackHosts = listOf("::1"),
            scanPorts = listOf(10085),
            maxConcurrency = 1,
            isTcpPortOpenOverride = { host, port -> host == "::1" && port == 10085 },
            tryListOutboundsOverride = { _, _, _ -> null },
            tryQueryStatsOverride = { host, port, _ ->
                if (host == "::1" && port == 10085) {
                    XrayStatsSummary(
                        statCount = 2,
                        sampleNames = listOf("outbound>>>proxy>>>traffic>>>uplink"),
                    )
                } else {
                    null
                }
            },
        )

        val result = scanner.findXrayApi(onProgress = {})

        assertEquals("::1", result?.endpoint?.host)
        assertEquals(10085, result?.endpoint?.port)
        assertFalse(result?.handlerAvailable ?: true)
        assertEquals(2, result?.stats?.statCount)
        assertTrue(result?.outbounds?.isEmpty() == true)
    }
}
