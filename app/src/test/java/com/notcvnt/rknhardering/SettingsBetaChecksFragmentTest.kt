package com.notcvnt.rknhardering

import android.content.Context
import android.content.res.Configuration
import android.os.Looper
import android.view.View
import android.widget.TextView
import android.widget.RadioButton
import androidx.appcompat.app.AlertDialog
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.materialswitch.MaterialSwitch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowDialog
import java.util.Locale

@RunWith(RobolectricTestRunner::class)
class SettingsBetaChecksFragmentTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        AppUiSettings.prefs(context).edit().clear().commit()
        ShadowDialog.reset()
    }

    @Test
    fun `beta defaults keep master off and recommended children selected`() {
        val scenario = betaFragment()

        assertFalse(scenario.switch(R.id.switchBetaChecks).isChecked)
        assertChildState(scenario, R.id.switchBetaHookTiming, checked = false, visible = true)
        assertChildState(scenario, R.id.switchBetaSocketOracles, checked = true, visible = true)
        assertChildState(scenario, R.id.switchBetaProfileIsolation, checked = true, visible = true)
        assertChildState(scenario, R.id.switchBetaHiddenAndroidApis, checked = true, visible = true)
        assertChildState(scenario, R.id.switchBetaKernelNetlink, checked = true, visible = true)
        assertChildState(scenario, R.id.switchBetaSandboxIntegrity, checked = true, visible = true)
        assertChildState(scenario, R.id.switchBetaBpfNetfilter, checked = false, visible = true)
        assertChildState(scenario, R.id.switchBetaAggressiveScan, checked = false, visible = true)
    }

    @Test
    fun `first enable requires warning acceptance and later enable does not warn again`() {
        val scenario = betaFragment()
        val prefs = AppUiSettings.prefs(scenario.activity)
        val master = scenario.switch(R.id.switchBetaChecks)

        master.performClick()

        assertFalse(master.isChecked)
        assertFalse(prefs.getBoolean(SettingsPrefs.PREF_BETA_CHECKS_ENABLED, false))
        val dialog = ShadowDialog.getLatestDialog() as AlertDialog
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(master.isChecked)
        assertTrue(prefs.getBoolean(SettingsPrefs.PREF_BETA_CHECKS_ENABLED, false))
        assertTrue(prefs.getBoolean(SettingsPrefs.PREF_BETA_WARNING_ACCEPTED, false))

        master.performClick()
        ShadowDialog.reset()
        master.performClick()

        assertTrue(master.isChecked)
        assertNull(ShadowDialog.getLatestDialog())
    }

    @Test
    fun `turning master off preserves child choices`() {
        val prefs = AppUiSettings.prefs(context)
        prefs.edit()
            .putBoolean(SettingsPrefs.PREF_BETA_WARNING_ACCEPTED, true)
            .putBoolean(SettingsPrefs.PREF_BETA_CHECKS_ENABLED, true)
            .commit()
        val scenario = betaFragment()
        val master = scenario.switch(R.id.switchBetaChecks)
        val socketOracles = scenario.switch(R.id.switchBetaSocketOracles)
        val profileIsolation = scenario.switch(R.id.switchBetaProfileIsolation)

        socketOracles.performClick()
        profileIsolation.performClick()
        master.performClick()

        assertFalse(master.isChecked)
        assertFalse(socketOracles.isChecked)
        assertFalse(profileIsolation.isChecked)
        assertFalse(socketOracles.isEnabled)
        assertFalse(profileIsolation.isEnabled)
        assertFalse(prefs.getBoolean(SettingsPrefs.PREF_BETA_SOCKET_ORACLES, true))
        assertFalse(prefs.getBoolean(SettingsPrefs.PREF_BETA_PROFILE_ISOLATION, true))

        master.performClick()

        assertFalse(socketOracles.isChecked)
        assertFalse(profileIsolation.isChecked)
        assertTrue(socketOracles.isEnabled)
        assertTrue(profileIsolation.isEnabled)
    }

    @Test
    fun `hook timing choice persists independently from aggressive mode`() {
        val prefs = AppUiSettings.prefs(context)
        prefs.edit()
            .putBoolean(SettingsPrefs.PREF_BETA_WARNING_ACCEPTED, true)
            .putBoolean(SettingsPrefs.PREF_BETA_CHECKS_ENABLED, true)
            .commit()
        val scenario = betaFragment()
        val hookTiming = scenario.switch(R.id.switchBetaHookTiming)
        val aggressive = scenario.switch(R.id.switchBetaAggressiveScan)

        hookTiming.performClick()

        assertTrue(hookTiming.isChecked)
        assertFalse(aggressive.isChecked)
        assertTrue(prefs.getBoolean(SettingsPrefs.PREF_BETA_HOOK_TIMING, false))
        assertTrue(betaFragment().switch(R.id.switchBetaHookTiming).isChecked)
    }

    @Test
    fun `privileged probes require separate consent and persist explicit provider`() {
        val prefs = AppUiSettings.prefs(context)
        prefs.edit()
            .putBoolean(SettingsPrefs.PREF_BETA_WARNING_ACCEPTED, true)
            .putBoolean(SettingsPrefs.PREF_BETA_CHECKS_ENABLED, true)
            .commit()
        val scenario = betaFragment()
        val privileged = scenario.switch(R.id.switchBetaPrivilegedChecks)

        privileged.performClick()

        assertFalse(privileged.isChecked)
        assertFalse(prefs.getBoolean(SettingsPrefs.PREF_BETA_PRIVILEGED_CHECKS_ENABLED, false))
        val dialog = ShadowDialog.getLatestDialog() as AlertDialog
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(privileged.isChecked)
        assertTrue(prefs.getBoolean(SettingsPrefs.PREF_BETA_PRIVILEGED_WARNING_ACCEPTED, false))
        assertTrue(prefs.getBoolean(SettingsPrefs.PREF_BETA_PRIVILEGED_CHECKS_ENABLED, false))
        assertEquals("SHIZUKU", prefs.getString(SettingsPrefs.PREF_BETA_PRIVILEGED_PROVIDER, null))

        scenario.root.findViewById<RadioButton>(R.id.radioBetaProviderRoot).performClick()
        assertEquals("ROOT", prefs.getString(SettingsPrefs.PREF_BETA_PRIVILEGED_PROVIDER, null))

        scenario.switch(R.id.switchBetaChecks).performClick()
        assertFalse(privileged.isEnabled)
        assertTrue(privileged.isChecked)
    }

    @Test
    fun `every localized beta title has exactly one beta prefix`() {
        val titleResources = listOf(
            R.string.settings_cat_beta_checks,
            R.string.settings_beta_checks_enabled,
            R.string.settings_beta_hook_timing,
            R.string.settings_beta_hidden_android_apis,
            R.string.settings_beta_kernel_netlink,
            R.string.settings_beta_privileged_checks,
            R.string.settings_beta_socket_oracles,
            R.string.settings_beta_profile_isolation,
            R.string.settings_beta_sandbox_integrity,
            R.string.settings_beta_bpf_netfilter,
            R.string.settings_beta_aggressive_scan,
        )

        listOf(Locale.ENGLISH, Locale("ru"), Locale("fa"), Locale.SIMPLIFIED_CHINESE).forEach { locale ->
            val localizedContext = context.createConfigurationContext(
                Configuration(context.resources.configuration).apply { setLocale(locale) },
            )
            titleResources.forEach { titleRes ->
                val title = localizedContext.getString(titleRes)
                assertTrue("$locale: $title", title.startsWith(BETA_PREFIX))
                assertEquals("$locale: $title", 1, BETA_PREFIX.toRegex().findAll(title).count())
            }
        }
    }

    @Test
    fun `root beta row shows description and opens beta settings`() {
        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        val root = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer)!!
            .requireView()
        val row = root.findViewById<View>(R.id.rowBetaChecks)

        assertEquals(
            activity.getString(R.string.settings_cat_beta_checks),
            row.findViewById<TextView>(R.id.rowTitle).text.toString(),
        )
        assertEquals(
            activity.getString(R.string.settings_cat_beta_checks_desc),
            row.findViewById<TextView>(R.id.rowValue).text.toString(),
        )

        row.performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(
            activity.supportFragmentManager.findFragmentById(R.id.settingsFragmentContainer) is
                SettingsBetaChecksFragment,
        )
    }

    private fun betaFragment(): BetaScenario {
        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        activity.supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, SettingsBetaChecksFragment())
            .commitNow()
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer) as SettingsBetaChecksFragment
        return BetaScenario(activity, fragment.requireView())
    }

    private fun assertChildState(scenario: BetaScenario, switchId: Int, checked: Boolean, visible: Boolean) {
        val switch = scenario.switch(switchId)
        assertEquals(checked, switch.isChecked)
        assertFalse(switch.isEnabled)
        assertEquals(visible, (switch.parent as View).visibility == View.VISIBLE)
    }

    private data class BetaScenario(
        val activity: SettingsActivity,
        val root: View,
    ) {
        fun switch(id: Int): MaterialSwitch = root.findViewById(id)
    }

    private companion object {
        const val BETA_PREFIX = "β "
    }
}
