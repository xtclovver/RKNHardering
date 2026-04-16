package com.notcvnt.rknhardering

import android.content.Context
import android.graphics.Typeface
import android.os.Looper
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import androidx.appcompat.app.AlertDialog
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
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
}
