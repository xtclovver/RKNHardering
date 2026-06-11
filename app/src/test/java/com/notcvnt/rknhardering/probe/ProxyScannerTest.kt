package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean

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

    @Test
    fun `preferred proxy type keeps scanning until matching port is found`() = runBlocking {
        val probedPorts = mutableListOf<Int>()
        val scanner = ProxyScanner(
            popularPorts = listOf(8080, 1080),
            scanRange = 1024..9000,
            probePort = { _, port, _, _ ->
                probedPorts += port
                when (port) {
                    8080 -> ProxyProber.ProbeResult(ProxyType.HTTP, authRequired = false)
                    1080 -> ProxyProber.ProbeResult(ProxyType.SOCKS5, authRequired = false)
                    else -> null
                }
            },
        )

        val result = scanner.findOpenProxyEndpoint(
            mode = ScanMode.POPULAR_ONLY,
            manualPort = null,
            onProgress = {},
            preferredType = ProxyType.SOCKS5,
        )

        assertEquals(listOf(8080, 1080), probedPorts.distinct())
        assertEquals(ProxyEndpoint("127.0.0.1", 1080, ProxyType.SOCKS5), result)
    }

    @Test
    fun `auto scan returns all found proxy endpoints`() = runBlocking {
        val scanner = ProxyScanner(
            popularPorts = listOf(1080, 2080),
            scanRange = 1080..2082,
            maxConcurrency = 1,
            progressUpdateEvery = 1,
            probePort = { _, port, _, _ ->
                when (port) {
                    1080 -> ProxyProber.ProbeResult(ProxyType.SOCKS5, authRequired = false)
                    2080 -> ProxyProber.ProbeResult(ProxyType.HTTP, authRequired = false)
                    2082 -> ProxyProber.ProbeResult(ProxyType.SOCKS5, authRequired = false)
                    else -> null
                }
            },
        )

        val result = scanner.findOpenProxyEndpoints(
            mode = ScanMode.AUTO,
            manualPort = null,
            onProgress = {},
        )

        assertEquals(
            listOf(
                ProxyEndpoint("127.0.0.1", 1080, ProxyType.SOCKS5),
                ProxyEndpoint("127.0.0.1", 2080, ProxyType.HTTP),
                ProxyEndpoint("127.0.0.1", 2082, ProxyType.SOCKS5),
            ),
            result,
        )
    }

    @Test
    fun `scan skips non proxy ports and duplicate loopback hosts for the same port`() = runBlocking {
        val scanner = ProxyScanner(
            loopbackHosts = listOf("127.0.0.1", "::1"),
            popularPorts = listOf(1080),
            scanRange = 1080..1082,
            maxConcurrency = 1,
            progressUpdateEvery = 1,
            probePort = { host, port, _, _ ->
                when {
                    port == 1080 -> ProxyProber.ProbeResult(ProxyType.SOCKS5, authRequired = false)
                    port == 1082 && host == "::1" -> ProxyProber.ProbeResult(ProxyType.HTTP, authRequired = false)
                    else -> null
                }
            },
        )

        val result = scanner.findOpenProxyEndpoints(
            mode = ScanMode.AUTO,
            manualPort = null,
            onProgress = {},
        )

        assertEquals(
            listOf(
                ProxyEndpoint("127.0.0.1", 1080, ProxyType.SOCKS5),
                ProxyEndpoint("::1", 1082, ProxyType.HTTP),
            ),
            result,
        )
    }

    @Test
    fun `auth required proxy is returned with authRequired flag set`() = runBlocking {
        val scanner = ProxyScanner(
            popularPorts = listOf(10808, 10809),
            scanRange = 10808..10809,
            probePort = { _, port, _, _ ->
                when (port) {
                    10808 -> ProxyProber.ProbeResult(ProxyType.SOCKS5, authRequired = true)
                    10809 -> ProxyProber.ProbeResult(ProxyType.HTTP, authRequired = true)
                    else -> null
                }
            },
        )

        val result = scanner.findOpenProxyEndpoints(
            mode = ScanMode.POPULAR_ONLY,
            manualPort = null,
            onProgress = {},
        )

        assertEquals(2, result.size)
        assertEquals(ProxyEndpoint("127.0.0.1", 10808, ProxyType.SOCKS5, authRequired = true), result[0])
        assertEquals(ProxyEndpoint("127.0.0.1", 10809, ProxyType.HTTP, authRequired = true), result[1])
    }

    // (a) Security gate: with authProbeEnabled=false (the default), the offensive
    // auth/UDP probes must never run, even for a SOCKS5 endpoint on loopback.
    @Test
    fun `auth probes are not invoked when authProbeEnabled is false`() = runBlocking {
        val socks5AuthInvoked = AtomicBoolean(false)
        val udpAssociateInvoked = AtomicBoolean(false)
        val scanner = ProxyScanner(
            popularPorts = listOf(1080),
            scanRange = 1080..1080,
            // authProbeEnabled defaults to false; assert no auth probe runs.
            probePort = { _, port, _, _ ->
                if (port == 1080) ProxyProber.ProbeResult(ProxyType.SOCKS5, authRequired = true) else null
            },
            probeSocks5Auth = { _, _, _, _, _, _ ->
                socks5AuthInvoked.set(true)
                true
            },
            probeUdpAssociate = { _, _, _, _ ->
                udpAssociateInvoked.set(true)
                true
            },
        )

        val result = scanner.findOpenProxyEndpoints(
            mode = ScanMode.POPULAR_ONLY,
            manualPort = null,
            onProgress = {},
        )

        assertFalse(socks5AuthInvoked.get())
        assertFalse(udpAssociateInvoked.get())
        assertEquals(1, result.size)
        assertFalse(result[0].weakAuthCracked)
        assertFalse(result[0].udpAssociateOpen)
    }

    // (b) Loopback guard: even with authProbeEnabled=true, a non-loopback host must
    // not be probed. loopbackHosts is injected with a non-loopback address (8.8.8.8)
    // so the scan reaches it, and maybeProbeAuth's isLoopback(...) check rejects it.
    @Test
    fun `auth probes are not invoked for non loopback host even when enabled`() = runBlocking {
        val socks5AuthInvoked = AtomicBoolean(false)
        val udpAssociateInvoked = AtomicBoolean(false)
        val scanner = ProxyScanner(
            loopbackHosts = listOf("8.8.8.8"),
            popularPorts = listOf(1080),
            scanRange = 1080..1080,
            authProbeEnabled = true,
            probePort = { _, port, _, _ ->
                if (port == 1080) ProxyProber.ProbeResult(ProxyType.SOCKS5, authRequired = true) else null
            },
            probeSocks5Auth = { _, _, _, _, _, _ ->
                socks5AuthInvoked.set(true)
                true
            },
            probeUdpAssociate = { _, _, _, _ ->
                udpAssociateInvoked.set(true)
                true
            },
        )

        val result = scanner.findOpenProxyEndpoints(
            mode = ScanMode.POPULAR_ONLY,
            manualPort = null,
            onProgress = {},
        )

        assertFalse(socks5AuthInvoked.get())
        assertFalse(udpAssociateInvoked.get())
        assertEquals(1, result.size)
        assertEquals("8.8.8.8", result[0].host)
        assertFalse(result[0].weakAuthCracked)
        assertFalse(result[0].udpAssociateOpen)
    }

    // (c) Happy path: authProbeEnabled=true on a loopback SOCKS5 endpoint with
    // authRequired -> weak-cred brute and UDP ASSOCIATE probes run; their results
    // flow into the endpoint.
    @Test
    fun `auth probes mark weakAuthCracked and udpAssociateOpen on loopback socks5`() = runBlocking {
        val socks5AuthInvoked = AtomicBoolean(false)
        val udpAssociateInvoked = AtomicBoolean(false)
        val scanner = ProxyScanner(
            popularPorts = listOf(1080),
            scanRange = 1080..1080,
            authProbeEnabled = true,
            probePort = { _, port, _, _ ->
                if (port == 1080) ProxyProber.ProbeResult(ProxyType.SOCKS5, authRequired = true) else null
            },
            probeSocks5Auth = { _, _, _, _, _, _ ->
                socks5AuthInvoked.set(true)
                true
            },
            probeUdpAssociate = { _, _, _, _ ->
                udpAssociateInvoked.set(true)
                true
            },
        )

        val result = scanner.findOpenProxyEndpoints(
            mode = ScanMode.POPULAR_ONLY,
            manualPort = null,
            onProgress = {},
        )

        assertTrue(socks5AuthInvoked.get())
        assertTrue(udpAssociateInvoked.get())
        assertEquals(1, result.size)
        assertEquals("127.0.0.1", result[0].host)
        assertTrue(result[0].weakAuthCracked)
        assertTrue(result[0].udpAssociateOpen)
    }
}
