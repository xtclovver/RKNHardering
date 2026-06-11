package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class ClashApiScannerTest {

    @Test
    fun `finds clash api with leaked destination ips`() = runBlocking {
        val scanner = ClashApiScanner(
            loopbackHosts = listOf("127.0.0.1"),
            scanPorts = listOf(9090),
            isTcpPortOpenOverride = { host, port -> host == "127.0.0.1" && port == 9090 },
            probeApiOverride = { host, port ->
                if (host == "127.0.0.1" && port == 9090) {
                    ClashApiScanResult(
                        endpoint = ClashApiEndpoint(host, port),
                        leakedDestIps = listOf("203.0.113.7"),
                        proxyNodes = listOf("node-jp"),
                        configAvailable = true,
                    )
                } else null
            },
        )
        val result = scanner.findClashApi(onProgress = { _, _ -> })
        assertNotNull(result)
        assertEquals(listOf("203.0.113.7"), result!!.leakedDestIps)
    }

    @Test
    fun `returns null when no clash api present`() = runBlocking {
        val scanner = ClashApiScanner(
            loopbackHosts = listOf("127.0.0.1"),
            scanPorts = listOf(9090),
            isTcpPortOpenOverride = { _, _ -> false },
            probeApiOverride = { _, _ -> null },
        )
        assertEquals(null, scanner.findClashApi(onProgress = { _, _ -> }))
    }
}
