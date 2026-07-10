package com.notcvnt.rknhardering.diagnostics

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverHttpResponse
import com.notcvnt.rknhardering.network.ResolverNetworkStack
import com.notcvnt.rknhardering.probe.SystemPingProber
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class DiagnosticCaptureIntegrationTest {
    @After
    fun tearDown() {
        ResolverNetworkStack.resetForTests()
        SystemPingProber.runCommandOverride = null
    }

    @Test
    fun `http captures actual status duration and used response body`() = runBlocking {
        val collector = DiagnosticTraceCollector(privacyMode = false)
        val executionContext = ScanExecutionContext(diagnosticCollector = collector)
        ResolverNetworkStack.okHttpExecuteOverride = {
            ResolverHttpResponse(207, "body-used token=do-not-store")
        }

        val response = kotlinx.coroutines.withContext(executionContext.asCoroutineContext()) {
            ResolverNetworkStack.execute(
                url = "https://example.test/value",
                method = "GET",
                timeoutMs = 1_000,
                config = DnsResolverConfig.system(),
                cancellationSignal = executionContext.cancellationSignal,
            )
        }

        assertEquals(207, response.code)
        val entry = collector.snapshot().entries.single()
        assertEquals("HTTP 207", entry.status)
        assertTrue(entry.durationMs != null)
        assertTrue(entry.body.contains("body-used"))
        assertFalse(entry.body.contains("do-not-store"))
    }

    @Test
    fun `ping captures exact command exit stdout and stderr from current run`() = runBlocking {
        val collector = DiagnosticTraceCollector(privacyMode = false)
        val executionContext = ScanExecutionContext(diagnosticCollector = collector)
        SystemPingProber.runCommandOverride = {
            SystemPingProber.CommandResult(
                exitCode = 0,
                output = "3 packets transmitted, 2 received\nrtt min/avg/max = 10/20/30 ms",
                stderr = "diagnostic stderr",
            )
        }

        val result = kotlinx.coroutines.withContext(executionContext.asCoroutineContext()) {
            SystemPingProber.probe("203.0.113.5", executionContext = executionContext)
        }

        assertEquals(2, result.received)
        val entry = collector.snapshot().entries.single()
        assertTrue(entry.body.contains("command=ping -4 -n -c 3 -W 4 203.0.113.5"))
        assertTrue(entry.body.contains("exitCode=0"))
        assertTrue(entry.body.contains("3 packets transmitted"))
        assertTrue(entry.body.contains("diagnostic stderr"))
    }
}
