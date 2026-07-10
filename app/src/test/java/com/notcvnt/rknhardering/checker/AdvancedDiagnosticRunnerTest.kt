package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.ScanExecutionContext
import com.notcvnt.rknhardering.customcheck.DirectSignsConfig
import com.notcvnt.rknhardering.customcheck.GeoIpConfig
import com.notcvnt.rknhardering.customcheck.IndirectSignsConfig
import com.notcvnt.rknhardering.customcheck.IpComparisonConfig
import com.notcvnt.rknhardering.customcheck.LocationSignalsConfig
import com.notcvnt.rknhardering.diagnostics.DiagnosticTraceCollector
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class AdvancedDiagnosticRunnerTest {
    @After
    fun tearDown() {
        VpnCheckRunner.dependenciesOverride = null
    }

    @Test
    fun `runner snapshot contains native result returned by current invocation`() = runBlocking {
        val marker = "JNI current-run getifaddrs result"
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            tunInterfaceInfoCollector = { TunInterfaceInfo(false, null, null) },
            nativeCheck = {
                CategoryResult(
                    name = "Native",
                    detected = false,
                    findings = listOf(Finding(marker, isInformational = true)),
                )
            },
        )
        val collector = DiagnosticTraceCollector(privacyMode = false)
        val context: Context = ApplicationProvider.getApplicationContext()

        val result = VpnCheckRunner.run(
            context = context,
            settings = CheckSettings(
                splitTunnelEnabled = false,
                networkRequestsEnabled = false,
                nativeSignsEnabled = true,
                icmpSpoofingEnabled = false,
                geoIp = GeoIpConfig(enabled = false),
                ipComparison = IpComparisonConfig(enabled = false),
                directSigns = DirectSignsConfig(enabled = false),
                indirectSigns = IndirectSignsConfig(enabled = false),
                locationSignals = LocationSignalsConfig(enabled = false),
            ),
            executionContext = ScanExecutionContext(diagnosticCollector = collector),
        )

        val nativeEntry = result.diagnosticSnapshot!!.entries.single { it.source == "NativeSignsChecker" }
        assertTrue(nativeEntry.body.contains(marker))
    }
}
