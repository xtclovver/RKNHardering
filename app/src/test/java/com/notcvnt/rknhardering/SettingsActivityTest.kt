package com.notcvnt.rknhardering

import android.content.Context
import android.graphics.Typeface
import android.os.Looper
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.chip.Chip
import com.google.android.material.materialswitch.MaterialSwitch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowDialog

@RunWith(RobolectricTestRunner::class)
class SettingsActivityTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        AppUiSettings.prefs(context).edit().clear().commit()
        ShadowDialog.reset()
    }

    @Test
    fun `cdn pulling warning highlights meduza domain in bold red`() {
        val message = buildCdnPullingWarningMessage(context) as Spanned
        val text = message.toString()
        val start = text.indexOf("meduza.io")
        val end = start + "meduza.io".length

        assertTrue(start >= 0)
        assertEquals(
            ContextCompat.getColor(context, R.color.status_red),
            message.getSpans(start, end, ForegroundColorSpan::class.java).first().foregroundColor,
        )
        assertTrue(
            message.getSpans(start, end, StyleSpan::class.java).any { it.style == Typeface.BOLD },
        )
    }

    @Test
    fun `cdn pulling warning cancel keeps switch and pref disabled`() {
        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        activity.supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, SettingsNetworkFragment())
            .commitNow()
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer) as SettingsNetworkFragment
        val switch = fragment.requireView().findViewById<MaterialSwitch>(R.id.switchCdnPulling)

        switch.performClick()
        val dialog = ShadowDialog.getLatestDialog() as AlertDialog
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertFalse(switch.isChecked)
        assertFalse(
            AppUiSettings.prefs(activity).getBoolean(SettingsActivity.PREF_CDN_PULLING_ENABLED, false),
        )
    }

    @Test
    fun `cdn pulling warning confirm enables switch and saves pref`() {
        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        activity.supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, SettingsNetworkFragment())
            .commitNow()
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer) as SettingsNetworkFragment
        val switch = fragment.requireView().findViewById<MaterialSwitch>(R.id.switchCdnPulling)

        switch.performClick()
        val dialog = ShadowDialog.getLatestDialog() as AlertDialog
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(switch.isChecked)
        assertTrue(
            AppUiSettings.prefs(activity).getBoolean(SettingsActivity.PREF_CDN_PULLING_ENABLED, false),
        )
    }

    @Test
    fun `settings root shows live values from shared preferences`() {
        AppUiSettings.prefs(context).edit {
            putBoolean(SettingsPrefs.PREF_SPLIT_TUNNEL_ENABLED, false)
            putBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, false)
            putString(SettingsPrefs.PREF_DNS_RESOLVER_MODE, "doh")
            putBoolean(SettingsPrefs.PREF_PRIVACY_MODE, true)
            putString(SettingsPrefs.PREF_THEME, "system")
            putString(SettingsPrefs.PREF_LANGUAGE, "ru")
            putString(SettingsPrefs.PREF_COLOR_VISION_MODE, ColorVisionMode.BLUE_YELLOW.prefValue)
        }

        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer) as SettingsCategoriesFragment
        val root = fragment.requireView()

        assertEquals(
            activity.getString(R.string.settings_value_off),
            rowValue(root, R.id.rowSplitTunnel),
        )
        assertEquals(
            activity.getString(R.string.settings_value_network_disabled),
            rowValue(root, R.id.rowNetwork),
        )
        assertEquals(
            activity.getString(R.string.settings_dns_mode_doh),
            rowValue(root, R.id.rowDns),
        )
        assertEquals(
            activity.getString(R.string.settings_value_privacy_masking),
            rowValue(root, R.id.rowPrivacy),
        )
        assertEquals(
            activity.getString(
                R.string.settings_value_appearance_format,
                activity.getString(R.string.settings_theme_system),
                "RU",
            ),
            rowValue(root, R.id.rowAppearance),
        )
        assertEquals(
            activity.getString(R.string.settings_color_vision_blue_yellow),
            rowValue(root, R.id.rowAccessibility),
        )
        assertEquals("v${BuildConfig.VERSION_NAME}", rowValue(root, R.id.rowAbout))
    }

    @Test
    fun `accessibility fragment saves color vision mode`() {
        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        activity.supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, SettingsAccessibilityFragment())
            .commitNow()
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer) as SettingsAccessibilityFragment
        val chip = fragment.requireView().findViewById<Chip>(R.id.chipColorVisionRedGreen)

        chip.performClick()

        assertEquals(
            ColorVisionMode.RED_GREEN.prefValue,
            AppUiSettings.prefs(activity).getString(SettingsPrefs.PREF_COLOR_VISION_MODE, null),
        )
    }

    @Test
    fun `network disable also turns off auto update and locks switch`() {
        AppUpdateChecker.setAutoUpdateEnabled(context, true)

        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        activity.supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, SettingsNetworkFragment())
            .commitNow()
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer) as SettingsNetworkFragment
        val root = fragment.requireView()
        val networkSwitch = root.findViewById<MaterialSwitch>(R.id.switchNetworkRequests)
        val autoUpdateSwitch = root.findViewById<MaterialSwitch>(R.id.switchAutoUpdate)

        assertTrue(autoUpdateSwitch.isChecked)

        networkSwitch.performClick()
        val dialog = ShadowDialog.getLatestDialog() as AlertDialog
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        assertFalse(autoUpdateSwitch.isChecked)
        assertFalse(autoUpdateSwitch.isEnabled)
        assertFalse(AppUpdateChecker.isAutoUpdateEnabled(activity))
    }

    @Test
    fun `auto update switch saves preference when network requests are enabled`() {
        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        activity.supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, SettingsNetworkFragment())
            .commitNow()
        val fragment = activity.supportFragmentManager
            .findFragmentById(R.id.settingsFragmentContainer) as SettingsNetworkFragment
        val autoUpdateSwitch = fragment.requireView().findViewById<MaterialSwitch>(R.id.switchAutoUpdate)

        autoUpdateSwitch.performClick()

        assertTrue(autoUpdateSwitch.isChecked)
        assertTrue(AppUpdateChecker.isAutoUpdateEnabled(activity))
        assertTrue(AppUpdateChecker.isAutoUpdateChoiceMade(activity))
    }

    private fun rowValue(root: android.view.View, rowId: Int): String {
        return root.findViewById<android.view.View>(rowId)
            .findViewById<TextView>(R.id.rowValue)
            .text
            .toString()
    }
}
