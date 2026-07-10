package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.diagnostics.DiagnosticTraceCollector
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeSignsBridgeDiagnosticTest {
    @After
    fun tearDown() {
        NativeSignsBridge.resetForTests()
    }

    @Test
    fun `captures raw jni and proc values from original invocation`() = runBlocking {
        val interfaceRow = "tun0|7|65|AF_INET|203.0.113.8|255.255.255.0|1400|65534"
        val procRoute = "Iface Destination Gateway Flags\ntun0 00000000 0100000A 0003"
        NativeSignsBridge.isLibraryLoadedOverride = { true }
        NativeSignsBridge.getIfAddrsOverride = { arrayOf(interfaceRow) }
        NativeSignsBridge.netlinkRouteDumpOverride = { emptyArray() }
        NativeSignsBridge.readProcFileOverride = { path, _ ->
            procRoute.takeIf { path.endsWith("/route") }
        }
        val collector = DiagnosticTraceCollector(privacyMode = false)
        val executionContext = ScanExecutionContext(diagnosticCollector = collector)

        withContext(executionContext.asCoroutineContext()) {
            NativeInterfaceProbe.collectInterfaces()
            NativeInterfaceProbe.collectRoutes()
        }

        val snapshot = collector.snapshot()
        assertTrue(snapshot.entries.single { it.source == "getifaddrs" }.body.contains(interfaceRow))
        assertTrue(snapshot.entries.any { it.source == "readProcFile" && it.body.contains(procRoute) })
    }
}
