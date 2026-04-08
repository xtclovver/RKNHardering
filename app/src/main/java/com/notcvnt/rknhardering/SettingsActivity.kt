package com.notcvnt.rknhardering

import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.ChipGroup
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText

class SettingsActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences

    private lateinit var switchSplitTunnel: MaterialSwitch
    private lateinit var cardPortRange: MaterialCardView
    private lateinit var chipGroupPortRange: ChipGroup
    private lateinit var customPortRangeContainer: LinearLayout
    private lateinit var editPortStart: TextInputEditText
    private lateinit var editPortEnd: TextInputEditText
    private lateinit var switchNetworkRequests: MaterialSwitch
    private lateinit var switchPrivacyMode: MaterialSwitch
    private lateinit var chipGroupTheme: ChipGroup

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_settings)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        prefs = getSharedPreferences("rknhardering_prefs", MODE_PRIVATE)

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        bindViews()
        loadSettings()
        setupListeners()
    }

    private fun bindViews() {
        switchSplitTunnel = findViewById(R.id.switchSplitTunnel)
        cardPortRange = findViewById(R.id.cardPortRange)
        chipGroupPortRange = findViewById(R.id.chipGroupPortRange)
        customPortRangeContainer = findViewById(R.id.customPortRangeContainer)
        editPortStart = findViewById(R.id.editPortStart)
        editPortEnd = findViewById(R.id.editPortEnd)
        switchNetworkRequests = findViewById(R.id.switchNetworkRequests)
        switchPrivacyMode = findViewById(R.id.switchPrivacyMode)
        chipGroupTheme = findViewById(R.id.chipGroupTheme)
    }

    private fun loadSettings() {
        switchSplitTunnel.isChecked = prefs.getBoolean(PREF_SPLIT_TUNNEL_ENABLED, true)
        switchNetworkRequests.isChecked = prefs.getBoolean(PREF_NETWORK_REQUESTS_ENABLED, true)
        switchPrivacyMode.isChecked = prefs.getBoolean(PREF_PRIVACY_MODE, false)

        updatePortRangeEnabled(switchSplitTunnel.isChecked)

        val portRange = prefs.getString(PREF_PORT_RANGE, "full") ?: "full"
        val chipId = when (portRange) {
            "popular" -> R.id.chipPortPopular
            "extended" -> R.id.chipPortExtended
            "full" -> R.id.chipPortFull
            "custom" -> R.id.chipPortCustom
            else -> R.id.chipPortFull
        }
        chipGroupPortRange.check(chipId)
        customPortRangeContainer.visibility = if (portRange == "custom") View.VISIBLE else View.GONE

        editPortStart.setText(prefs.getInt(PREF_PORT_RANGE_START, 1024).toString())
        editPortEnd.setText(prefs.getInt(PREF_PORT_RANGE_END, 65535).toString())

        val theme = prefs.getString(PREF_THEME, "system") ?: "system"
        val themeChipId = when (theme) {
            "light" -> R.id.chipThemeLight
            "dark" -> R.id.chipThemeDark
            else -> R.id.chipThemeSystem
        }
        chipGroupTheme.check(themeChipId)
    }

    private fun setupListeners() {
        switchSplitTunnel.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean(PREF_SPLIT_TUNNEL_ENABLED, isChecked).apply()
            updatePortRangeEnabled(isChecked)
        }

        switchNetworkRequests.setOnCheckedChangeListener { _, isChecked ->
            if (!isChecked) {
                AlertDialog.Builder(this)
                    .setTitle(R.string.settings_network_disable_title)
                    .setMessage(R.string.settings_network_disable_message)
                    .setPositiveButton(R.string.settings_network_disable_confirm) { _, _ ->
                        prefs.edit().putBoolean(PREF_NETWORK_REQUESTS_ENABLED, false).apply()
                    }
                    .setNegativeButton(android.R.string.cancel) { _, _ ->
                        switchNetworkRequests.isChecked = true
                    }
                    .setOnCancelListener {
                        switchNetworkRequests.isChecked = true
                    }
                    .show()
            } else {
                prefs.edit().putBoolean(PREF_NETWORK_REQUESTS_ENABLED, true).apply()
            }
        }

        switchPrivacyMode.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean(PREF_PRIVACY_MODE, isChecked).apply()
        }

        chipGroupPortRange.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val value = when (checkedIds.first()) {
                R.id.chipPortPopular -> "popular"
                R.id.chipPortExtended -> "extended"
                R.id.chipPortFull -> "full"
                R.id.chipPortCustom -> "custom"
                else -> "full"
            }
            prefs.edit().putString(PREF_PORT_RANGE, value).apply()
            customPortRangeContainer.visibility = if (value == "custom") View.VISIBLE else View.GONE
        }

        editPortStart.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomPortRange()
        }
        editPortEnd.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomPortRange()
        }

        chipGroupTheme.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val value = when (checkedIds.first()) {
                R.id.chipThemeLight -> "light"
                R.id.chipThemeDark -> "dark"
                else -> "system"
            }
            prefs.edit().putString(PREF_THEME, value).apply()
            applyTheme(value)
        }

        findViewById<MaterialCardView>(R.id.cardPermissions).setOnClickListener {
            reRequestPermissions()
        }

        findViewById<MaterialCardView>(R.id.cardGithub).setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.github_repo_url))))
        }
    }

    private fun updatePortRangeEnabled(enabled: Boolean) {
        cardPortRange.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardPortRange, enabled)
    }

    private fun setViewAndChildrenEnabled(view: View, enabled: Boolean) {
        view.isEnabled = enabled
        if (view is android.view.ViewGroup) {
            for (i in 0 until view.childCount) {
                setViewAndChildrenEnabled(view.getChildAt(i), enabled)
            }
        }
    }

    private fun saveCustomPortRange() {
        val start = editPortStart.text.toString().toIntOrNull()?.coerceIn(1024, 65535) ?: 1024
        val end = editPortEnd.text.toString().toIntOrNull()?.coerceIn(1024, 65535) ?: 65535
        val validStart = minOf(start, end)
        val validEnd = maxOf(start, end)
        prefs.edit()
            .putInt(PREF_PORT_RANGE_START, validStart)
            .putInt(PREF_PORT_RANGE_END, validEnd)
            .apply()
        editPortStart.setText(validStart.toString())
        editPortEnd.setText(validEnd.toString())
    }

    private fun reRequestPermissions() {
        val intent = Intent(this, MainActivity::class.java).apply {
            putExtra(EXTRA_REQUEST_PERMISSIONS, true)
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        startActivity(intent)
        finish()
    }

    companion object {
        const val PREF_SPLIT_TUNNEL_ENABLED = "pref_split_tunnel_enabled"
        const val PREF_PORT_RANGE = "pref_port_range"
        const val PREF_PORT_RANGE_START = "pref_port_range_start"
        const val PREF_PORT_RANGE_END = "pref_port_range_end"
        const val PREF_NETWORK_REQUESTS_ENABLED = "pref_network_requests_enabled"
        const val PREF_PRIVACY_MODE = "pref_privacy_mode"
        const val PREF_THEME = "pref_theme"
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
