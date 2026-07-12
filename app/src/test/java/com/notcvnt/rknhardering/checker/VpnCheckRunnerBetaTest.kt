package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.customcheck.DirectSignsConfig
import com.notcvnt.rknhardering.customcheck.IndirectSignsConfig
import com.notcvnt.rknhardering.customcheck.LocationSignalsConfig
import com.notcvnt.rknhardering.model.BetaCheckResult
import com.notcvnt.rknhardering.model.CategoryResult
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class VpnCheckRunnerBetaTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        VpnCheckRunner.dependenciesOverride = null
    }

    @Test
    fun `beta disabled does not invoke dependency`() = runBlocking {
        var calls = 0
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            betaChecks = BetaChecksDependency {
                calls++
                BetaCheckResult.disabled()
            },
        )

        val result = VpnCheckRunner.run(context, quietSettings(betaEnabled = false))

        assertEquals(0, calls)
        assertFalse(result.betaChecks.category.detected)
    }

    @Test
    fun `beta settings are snapshotted and global network gate reaches dependency`() = runBlocking {
        var request: BetaChecksRequest? = null
        val updates = mutableListOf<CheckUpdate>()
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            betaChecks = BetaChecksDependency { captured ->
                request = captured
                BetaCheckResult(
                    category = CategoryResult("β Beta", detected = false, findings = emptyList()),
                )
            },
        )

        VpnCheckRunner.run(context, quietSettings(betaEnabled = true)) { updates += it }

        assertTrue(request?.settings?.enabled == true)
        assertFalse(request?.networkRequestsEnabled ?: true)
        assertTrue(updates.any { it is CheckUpdate.BetaChecksReady })
    }

    @Test
    fun `beta checker failure is visible and neutral`() = runBlocking {
        VpnCheckRunner.dependenciesOverride = VpnCheckRunner.Dependencies(
            betaChecks = BetaChecksDependency { error("broken beta probe") },
        )

        val result = VpnCheckRunner.run(context, quietSettings(betaEnabled = true))

        assertTrue(result.betaChecks.category.hasError)
        assertFalse(result.betaChecks.category.detected)
        assertEquals(1, result.betaChecks.availabilitySummary[com.notcvnt.rknhardering.model.ProbeAvailability.ERROR])
    }

    private fun quietSettings(betaEnabled: Boolean) = CheckSettings(
        networkRequestsEnabled = false,
        splitTunnelEnabled = false,
        nativeSignsEnabled = false,
        directSigns = DirectSignsConfig(enabled = false),
        indirectSigns = IndirectSignsConfig(enabled = false),
        locationSignals = LocationSignalsConfig(enabled = false),
        beta = BetaCheckSettings(enabled = betaEnabled),
    )
}
