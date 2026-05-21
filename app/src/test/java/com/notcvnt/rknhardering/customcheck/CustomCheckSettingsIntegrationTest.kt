package com.notcvnt.rknhardering.customcheck

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.checker.CheckSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

@RunWith(RobolectricTestRunner::class)
class CustomCheckSettingsIntegrationTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        File(context.filesDir, "custom_checks").deleteRecursively()
        context.getSharedPreferences("custom_check_prefs", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @Test
    fun `saved profile with splitTunnel disabled and cdnPulling enabled is returned by getActiveProfile`() {
        val profile = CustomCheckProfile(
            id = "integ-test-id",
            name = "Integration Profile",
            checksConfig = ChecksConfig(
                splitTunnel = SplitTunnelConfig(enabled = false),
                cdnPulling = CdnPullingConfig(enabled = true),
            ),
        )

        CustomCheckRepository.save(context, profile)
        CustomCheckRepository.setActiveProfileId(context, profile.id)

        val loaded = CustomCheckRunner.getActiveProfile(context)
        assertNotNull(loaded)
        assertEquals("integ-test-id", loaded!!.id)
    }

    @Test
    fun `toCheckSettings reflects splitTunnel disabled from saved profile`() {
        val profile = CustomCheckProfile(
            id = "integ-test-id",
            name = "Integration Profile",
            checksConfig = ChecksConfig(
                splitTunnel = SplitTunnelConfig(enabled = false),
                cdnPulling = CdnPullingConfig(enabled = true),
            ),
        )

        CustomCheckRepository.save(context, profile)
        CustomCheckRepository.setActiveProfileId(context, profile.id)

        val loaded = CustomCheckRunner.getActiveProfile(context)!!
        val result = CustomCheckRunner.toCheckSettings(loaded, CheckSettings())

        assertFalse(result.splitTunnelEnabled)
    }

    @Test
    fun `toCheckSettings reflects cdnPulling enabled from saved profile`() {
        val profile = CustomCheckProfile(
            id = "integ-test-id",
            name = "Integration Profile",
            checksConfig = ChecksConfig(
                splitTunnel = SplitTunnelConfig(enabled = false),
                cdnPulling = CdnPullingConfig(enabled = true),
            ),
        )

        CustomCheckRepository.save(context, profile)
        CustomCheckRepository.setActiveProfileId(context, profile.id)

        val loaded = CustomCheckRunner.getActiveProfile(context)!!
        val result = CustomCheckRunner.toCheckSettings(loaded, CheckSettings())

        assertTrue(result.cdnPullingEnabled)
    }
}
