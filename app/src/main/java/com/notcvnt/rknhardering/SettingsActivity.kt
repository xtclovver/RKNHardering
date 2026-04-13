package com.notcvnt.rknhardering

import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.ChipGroup
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.DnsResolverMode
import com.notcvnt.rknhardering.network.DnsResolverPreset
import com.notcvnt.rknhardering.network.DnsResolverPresets
import com.notcvnt.rknhardering.probe.PortScanPlanner
import java.text.NumberFormat
import java.util.Locale

class SettingsActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences

    private lateinit var switchSplitTunnel: MaterialSwitch
    private lateinit var cardPortRange: MaterialCardView
    private lateinit var chipGroupPortRange: ChipGroup
    private lateinit var customPortRangeContainer: LinearLayout
    private lateinit var editPortStart: TextInputEditText
    private lateinit var editPortEnd: TextInputEditText
    private lateinit var textPortRangePreview: TextView
    private lateinit var switchNetworkRequests: MaterialSwitch
    private lateinit var cardCallTransportProbe: MaterialCardView
    private lateinit var switchCallTransportProbe: MaterialSwitch
    private lateinit var cardResolver: MaterialCardView
    private lateinit var chipGroupResolverMode: ChipGroup
    private lateinit var chipGroupResolverPreset: ChipGroup
    private lateinit var inputResolverDirectServersLayout: TextInputLayout
    private lateinit var inputResolverDohUrlLayout: TextInputLayout
    private lateinit var inputResolverBootstrapLayout: TextInputLayout
    private lateinit var editResolverDirectServers: TextInputEditText
    private lateinit var editResolverDohUrl: TextInputEditText
    private lateinit var editResolverBootstrap: TextInputEditText
    private lateinit var switchPrivacyMode: MaterialSwitch
    private lateinit var chipGroupTheme: ChipGroup
    private lateinit var chipGroupLanguage: ChipGroup

    override fun onCreate(savedInstanceState: Bundle?) {
        AppUiSettings.applySavedTheme(this)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_settings)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        prefs = AppUiSettings.prefs(this)

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
        textPortRangePreview = findViewById(R.id.textPortRangePreview)
        switchNetworkRequests = findViewById(R.id.switchNetworkRequests)
        cardCallTransportProbe = findViewById(R.id.cardCallTransportProbe)
        switchCallTransportProbe = findViewById(R.id.switchCallTransportProbe)
        cardResolver = findViewById(R.id.cardResolver)
        chipGroupResolverMode = findViewById(R.id.chipGroupResolverMode)
        chipGroupResolverPreset = findViewById(R.id.chipGroupResolverPreset)
        inputResolverDirectServersLayout = findViewById(R.id.inputResolverDirectServersLayout)
        inputResolverDohUrlLayout = findViewById(R.id.inputResolverDohUrlLayout)
        inputResolverBootstrapLayout = findViewById(R.id.inputResolverBootstrapLayout)
        editResolverDirectServers = findViewById(R.id.editResolverDirectServers)
        editResolverDohUrl = findViewById(R.id.editResolverDohUrl)
        editResolverBootstrap = findViewById(R.id.editResolverBootstrap)
        switchPrivacyMode = findViewById(R.id.switchPrivacyMode)
        chipGroupTheme = findViewById(R.id.chipGroupTheme)
        chipGroupLanguage = findViewById(R.id.chipGroupLanguage)
    }

    private fun loadSettings() {
        switchSplitTunnel.isChecked = prefs.getBoolean(PREF_SPLIT_TUNNEL_ENABLED, true)
        switchNetworkRequests.isChecked = prefs.getBoolean(PREF_NETWORK_REQUESTS_ENABLED, true)
        switchCallTransportProbe.isChecked = prefs.getBoolean(PREF_CALL_TRANSPORT_PROBE_ENABLED, false)
        switchPrivacyMode.isChecked = prefs.getBoolean(PREF_PRIVACY_MODE, false)

        updatePortRangeEnabled(switchSplitTunnel.isChecked)
        updateCallTransportEnabled(switchNetworkRequests.isChecked)

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

        editPortStart.setText(formatPortInputValue(prefs.getInt(PREF_PORT_RANGE_START, 1024)))
        editPortEnd.setText(formatPortInputValue(prefs.getInt(PREF_PORT_RANGE_END, 65535)))
        updatePortRangePreview()

        loadResolverSettings()

        val theme = prefs.getString(PREF_THEME, "system") ?: "system"
        val themeChipId = when (theme) {
            "light" -> R.id.chipThemeLight
            "dark" -> R.id.chipThemeDark
            else -> R.id.chipThemeSystem
        }
        chipGroupTheme.check(themeChipId)

        val language = prefs.getString(PREF_LANGUAGE, "").orEmpty()
        val languageChipId = when (language) {
            "en" -> R.id.chipLangEn
            "ru" -> R.id.chipLangRu
            "fa" -> R.id.chipLangFa
            "zh-CN" -> R.id.chipLangZh
            else -> R.id.chipLangSystem
        }
        chipGroupLanguage.check(languageChipId)
    }

    private fun setupListeners() {
        switchSplitTunnel.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(PREF_SPLIT_TUNNEL_ENABLED, isChecked) }
            updatePortRangeEnabled(isChecked)
        }

        switchNetworkRequests.setOnCheckedChangeListener { _, isChecked ->
            updateCallTransportEnabled(isChecked)
            if (!isChecked) {
                AlertDialog.Builder(this)
                    .setTitle(R.string.settings_network_disable_title)
                    .setMessage(R.string.settings_network_disable_message)
                    .setPositiveButton(R.string.settings_network_disable_confirm) { _, _ ->
                        prefs.edit { putBoolean(PREF_NETWORK_REQUESTS_ENABLED, false) }
                    }
                    .setNegativeButton(android.R.string.cancel) { _, _ ->
                        switchNetworkRequests.isChecked = true
                    }
                    .setOnCancelListener {
                        switchNetworkRequests.isChecked = true
                    }
                    .show()
            } else {
                prefs.edit { putBoolean(PREF_NETWORK_REQUESTS_ENABLED, true) }
            }
        }

        switchCallTransportProbe.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(PREF_CALL_TRANSPORT_PROBE_ENABLED, isChecked) }
        }

        switchPrivacyMode.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(PREF_PRIVACY_MODE, isChecked) }
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
            prefs.edit { putString(PREF_PORT_RANGE, value) }
            customPortRangeContainer.visibility = if (value == "custom") View.VISIBLE else View.GONE
            updatePortRangePreview()
        }

        chipGroupResolverMode.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            saveCustomResolverFields()
            prefs.edit {
                putString(PREF_DNS_RESOLVER_MODE, selectedResolverMode().prefValue)
            }
            refreshResolverUi(restoreCustomValues = true)
        }

        chipGroupResolverPreset.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            saveCustomResolverFields()
            prefs.edit {
                putString(PREF_DNS_RESOLVER_PRESET, selectedResolverPreset().prefValue)
            }
            refreshResolverUi(restoreCustomValues = true)
        }

        editPortStart.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomPortRange()
        }
        editPortEnd.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomPortRange()
        }
        editPortStart.doAfterTextChanged {
            updatePortRangePreview()
        }
        editPortEnd.doAfterTextChanged {
            updatePortRangePreview()
        }
        editResolverDirectServers.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomResolverFields()
        }
        editResolverDohUrl.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomResolverFields()
        }
        editResolverBootstrap.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomResolverFields()
        }

        chipGroupTheme.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val value = when (checkedIds.first()) {
                R.id.chipThemeLight -> "light"
                R.id.chipThemeDark -> "dark"
                else -> "system"
            }
            prefs.edit { putString(PREF_THEME, value) }
            applyTheme(value)
        }

        chipGroupLanguage.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val value = when (checkedIds.first()) {
                R.id.chipLangEn -> "en"
                R.id.chipLangRu -> "ru"
                R.id.chipLangFa -> "fa"
                R.id.chipLangZh -> "zh-CN"
                else -> ""
            }
            prefs.edit { putString(PREF_LANGUAGE, value) }
            AppUiSettings.applyLanguage(value)
        }

        findViewById<MaterialCardView>(R.id.cardPermissions).setOnClickListener {
            reRequestPermissions()
        }

        findViewById<MaterialCardView>(R.id.cardGithub).setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, getString(R.string.github_repo_url).toUri()))
        }
    }

    private fun updatePortRangeEnabled(enabled: Boolean) {
        cardPortRange.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardPortRange, enabled)
    }

    private fun updateCallTransportEnabled(enabled: Boolean) {
        cardCallTransportProbe.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardCallTransportProbe, enabled)
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
        val normalizedRange = PortScanPlanner.normalizeCustomRange(
            start = editPortStart.text.toString().toIntOrNull() ?: PortScanPlanner.MIN_PORT,
            end = editPortEnd.text.toString().toIntOrNull() ?: PortScanPlanner.MAX_PORT,
        )
        prefs.edit {
            putInt(PREF_PORT_RANGE_START, normalizedRange.first)
            putInt(PREF_PORT_RANGE_END, normalizedRange.last)
        }
        editPortStart.setText(formatPortInputValue(normalizedRange.first))
        editPortEnd.setText(formatPortInputValue(normalizedRange.last))
    }

    private fun updatePortRangePreview() {
        val previewRanges = PortScanPlanner.buildPreviewRanges(
            portRange = selectedPortRange(),
            portRangeStart = currentCustomPortRange().first,
            portRangeEnd = currentCustomPortRange().last,
        )
        val portsText = previewRanges.joinToString(", ") { range ->
            if (range.first == range.last) {
                range.first.toString()
            } else {
                "${range.first}-${range.last}"
            }
        }
        val portsCount = previewRanges.sumOf { it.last - it.first + 1 }
        val formattedCount = NumberFormat.getIntegerInstance().format(portsCount)
        val portCountLabel = resources.getQuantityString(R.plurals.settings_port_word, portsCount, formattedCount)
        textPortRangePreview.text = getString(R.string.settings_port_range_preview, portsText, portCountLabel)
    }

    private fun selectedPortRange(): String {
        return when (chipGroupPortRange.checkedChipId) {
            R.id.chipPortPopular -> "popular"
            R.id.chipPortExtended -> "extended"
            R.id.chipPortCustom -> "custom"
            else -> "full"
        }
    }

    private fun currentCustomPortRange(): IntRange {
        return PortScanPlanner.normalizeCustomRange(
            start = editPortStart.text.toString().toIntOrNull() ?: PortScanPlanner.MIN_PORT,
            end = editPortEnd.text.toString().toIntOrNull() ?: PortScanPlanner.MAX_PORT,
        )
    }

    private fun loadResolverSettings() {
        val mode = DnsResolverMode.fromPref(
            prefs.getString(PREF_DNS_RESOLVER_MODE, DnsResolverMode.SYSTEM.prefValue),
        )
        chipGroupResolverMode.check(
            when (mode) {
                DnsResolverMode.SYSTEM -> R.id.chipResolverSystem
                DnsResolverMode.DIRECT -> R.id.chipResolverDirect
                DnsResolverMode.DOH -> R.id.chipResolverDoh
            },
        )

        val preset = DnsResolverPreset.fromPref(
            prefs.getString(PREF_DNS_RESOLVER_PRESET, DnsResolverPreset.CUSTOM.prefValue),
        )
        chipGroupResolverPreset.check(
            when (preset) {
                DnsResolverPreset.CUSTOM -> R.id.chipResolverPresetCustom
                DnsResolverPreset.CLOUDFLARE -> R.id.chipResolverPresetCloudflare
                DnsResolverPreset.GOOGLE -> R.id.chipResolverPresetGoogle
                DnsResolverPreset.YANDEX -> R.id.chipResolverPresetYandex
            },
        )

        loadCustomResolverFields()
        refreshResolverUi(restoreCustomValues = false)
    }

    private fun loadCustomResolverFields() {
        editResolverDirectServers.setText(prefs.getString(PREF_DNS_RESOLVER_DIRECT_SERVERS, "").orEmpty())
        editResolverDohUrl.setText(prefs.getString(PREF_DNS_RESOLVER_DOH_URL, "").orEmpty())
        editResolverBootstrap.setText(prefs.getString(PREF_DNS_RESOLVER_DOH_BOOTSTRAP, "").orEmpty())
    }

    private fun saveCustomResolverFields() {
        // Presets reuse the same text fields for display, so only persist while custom is active.
        if (persistedResolverPreset() != DnsResolverPreset.CUSTOM) return
        prefs.edit {
            putString(PREF_DNS_RESOLVER_DIRECT_SERVERS, editResolverDirectServers.text?.toString().orEmpty().trim())
            putString(PREF_DNS_RESOLVER_DOH_URL, editResolverDohUrl.text?.toString().orEmpty().trim())
            putString(PREF_DNS_RESOLVER_DOH_BOOTSTRAP, editResolverBootstrap.text?.toString().orEmpty().trim())
        }
    }

    private fun formatPortInputValue(value: Int): String {
        return String.format(Locale.US, "%d", value)
    }

    private fun persistedResolverPreset(): DnsResolverPreset {
        return DnsResolverPreset.fromPref(
            prefs.getString(PREF_DNS_RESOLVER_PRESET, DnsResolverPreset.CUSTOM.prefValue),
        )
    }

    private fun refreshResolverUi(restoreCustomValues: Boolean) {
        val mode = selectedResolverMode()
        val preset = selectedResolverPreset()
        val customPreset = preset == DnsResolverPreset.CUSTOM
        val presetSpec = DnsResolverPresets.spec(preset)

        chipGroupResolverPreset.visibility = if (mode == DnsResolverMode.SYSTEM) View.GONE else View.VISIBLE
        inputResolverDirectServersLayout.visibility = if (mode == DnsResolverMode.DIRECT) View.VISIBLE else View.GONE
        inputResolverDohUrlLayout.visibility = if (mode == DnsResolverMode.DOH) View.VISIBLE else View.GONE
        inputResolverBootstrapLayout.visibility = if (mode == DnsResolverMode.DOH) View.VISIBLE else View.GONE

        when {
            mode == DnsResolverMode.DIRECT && !customPreset && presetSpec != null -> {
                setTextIfDifferent(
                    editResolverDirectServers,
                    DnsResolverConfig.serializeAddressList(presetSpec.directServers),
                )
            }
            mode == DnsResolverMode.DOH && !customPreset && presetSpec != null -> {
                setTextIfDifferent(editResolverDohUrl, presetSpec.dohUrl)
                setTextIfDifferent(
                    editResolverBootstrap,
                    DnsResolverConfig.serializeAddressList(presetSpec.dohBootstrapHosts),
                )
            }
            customPreset && restoreCustomValues -> {
                loadCustomResolverFields()
            }
        }

        setViewAndChildrenEnabled(inputResolverDirectServersLayout, customPreset)
        setViewAndChildrenEnabled(inputResolverDohUrlLayout, customPreset)
        setViewAndChildrenEnabled(inputResolverBootstrapLayout, customPreset)
        cardResolver.alpha = 1.0f
    }

    private fun selectedResolverMode(): DnsResolverMode {
        return when (chipGroupResolverMode.checkedChipId) {
            R.id.chipResolverDirect -> DnsResolverMode.DIRECT
            R.id.chipResolverDoh -> DnsResolverMode.DOH
            else -> DnsResolverMode.SYSTEM
        }
    }

    private fun selectedResolverPreset(): DnsResolverPreset {
        return when (chipGroupResolverPreset.checkedChipId) {
            R.id.chipResolverPresetCloudflare -> DnsResolverPreset.CLOUDFLARE
            R.id.chipResolverPresetGoogle -> DnsResolverPreset.GOOGLE
            R.id.chipResolverPresetYandex -> DnsResolverPreset.YANDEX
            else -> DnsResolverPreset.CUSTOM
        }
    }

    private fun setTextIfDifferent(view: TextInputEditText, value: String) {
        if (view.text?.toString() != value) {
            view.setText(value)
        }
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
        const val PREF_CALL_TRANSPORT_PROBE_ENABLED = "pref_call_transport_probe_enabled"
        const val PREF_DNS_RESOLVER_MODE = "pref_dns_resolver_mode"
        const val PREF_DNS_RESOLVER_PRESET = "pref_dns_resolver_preset"
        const val PREF_DNS_RESOLVER_DIRECT_SERVERS = "pref_dns_resolver_direct_servers"
        const val PREF_DNS_RESOLVER_DOH_URL = "pref_dns_resolver_doh_url"
        const val PREF_DNS_RESOLVER_DOH_BOOTSTRAP = "pref_dns_resolver_doh_bootstrap"
        const val PREF_PRIVACY_MODE = "pref_privacy_mode"
        const val PREF_THEME = "pref_theme"
        const val PREF_LANGUAGE = "pref_language"
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
