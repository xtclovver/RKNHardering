package com.notcvnt.rknhardering

import android.graphics.Typeface
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.appbar.MaterialToolbar

internal fun buildCdnPullingWarningMessage(context: android.content.Context): CharSequence {
    val message = SpannableStringBuilder(
        context.getString(R.string.settings_cdn_pulling_warning_message),
    )
    val meduzaDomain = "meduza.io"
    val start = message.indexOf(meduzaDomain)
    if (start >= 0) {
        val end = start + meduzaDomain.length
        message.setSpan(
            ForegroundColorSpan(ContextCompat.getColor(context, R.color.status_red)),
            start,
            end,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
        )
        message.setSpan(
            StyleSpan(Typeface.BOLD),
            start,
            end,
            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
        )
    }
    return message
}

class SettingsActivity : AppCompatActivity() {

    private lateinit var toolbar: MaterialToolbar

    override fun onCreate(savedInstanceState: Bundle?) {
        AppUiSettings.applySavedTheme(this)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_settings)

        toolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { onBackPressedDispatcher.onBackPressed() }

        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(R.id.settingsFragmentContainer, SettingsCategoriesFragment())
                .commit()
        }

        supportFragmentManager.addOnBackStackChangedListener {
            updateToolbarTitle()
        }
        updateToolbarTitle()
    }

    fun navigateTo(fragment: Fragment, titleRes: Int) {
        supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, fragment)
            .addToBackStack(null)
            .commit()
        supportActionBar?.title = getString(titleRes)
    }

    private fun updateToolbarTitle() {
        val isRoot = supportFragmentManager.backStackEntryCount == 0
        if (isRoot) {
            supportActionBar?.title = getString(R.string.settings_title)
        }
        // Стрелка назад всегда видна: на root — закрывает Activity, во фрагменте — возврат назад
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
    }

    companion object {
        const val PREF_SPLIT_TUNNEL_ENABLED = SettingsPrefs.PREF_SPLIT_TUNNEL_ENABLED
        const val PREF_PROXY_SCAN_ENABLED = SettingsPrefs.PREF_PROXY_SCAN_ENABLED
        const val PREF_XRAY_API_SCAN_ENABLED = SettingsPrefs.PREF_XRAY_API_SCAN_ENABLED
        const val PREF_PORT_RANGE = SettingsPrefs.PREF_PORT_RANGE
        const val PREF_PORT_RANGE_START = SettingsPrefs.PREF_PORT_RANGE_START
        const val PREF_PORT_RANGE_END = SettingsPrefs.PREF_PORT_RANGE_END
        const val PREF_NETWORK_REQUESTS_ENABLED = SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED
        const val PREF_AUTO_UPDATE_ENABLED = SettingsPrefs.PREF_AUTO_UPDATE_ENABLED
        const val PREF_AUTO_UPDATE_CHOICE_MADE = SettingsPrefs.PREF_AUTO_UPDATE_CHOICE_MADE
        const val PREF_CDN_PULLING_ENABLED = SettingsPrefs.PREF_CDN_PULLING_ENABLED
        const val PREF_CDN_PULLING_MEDUZA_ENABLED = SettingsPrefs.PREF_CDN_PULLING_MEDUZA_ENABLED
        const val PREF_CALL_TRANSPORT_PROBE_ENABLED = SettingsPrefs.PREF_CALL_TRANSPORT_PROBE_ENABLED
        const val PREF_TUN_PROBE_DEBUG_ENABLED = SettingsPrefs.PREF_TUN_PROBE_DEBUG_ENABLED
        const val PREF_TUN_PROBE_MODE_OVERRIDE = SettingsPrefs.PREF_TUN_PROBE_MODE_OVERRIDE
        const val PREF_DNS_RESOLVER_MODE = SettingsPrefs.PREF_DNS_RESOLVER_MODE
        const val PREF_DNS_RESOLVER_PRESET = SettingsPrefs.PREF_DNS_RESOLVER_PRESET
        const val PREF_DNS_RESOLVER_DIRECT_SERVERS = SettingsPrefs.PREF_DNS_RESOLVER_DIRECT_SERVERS
        const val PREF_DNS_RESOLVER_DOH_URL = SettingsPrefs.PREF_DNS_RESOLVER_DOH_URL
        const val PREF_DNS_RESOLVER_DOH_BOOTSTRAP = SettingsPrefs.PREF_DNS_RESOLVER_DOH_BOOTSTRAP
        const val PREF_PRIVACY_MODE = SettingsPrefs.PREF_PRIVACY_MODE
        const val PREF_THEME = SettingsPrefs.PREF_THEME
        const val PREF_LANGUAGE = SettingsPrefs.PREF_LANGUAGE
        const val PREF_COLOR_VISION_MODE = SettingsPrefs.PREF_COLOR_VISION_MODE
        const val EXTRA_REQUEST_PERMISSIONS = "extra_request_permissions"

        fun applyTheme(theme: String) {
            when (theme) {
                "light" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)
                "dark" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
                else -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
            }
        }
    }
}
