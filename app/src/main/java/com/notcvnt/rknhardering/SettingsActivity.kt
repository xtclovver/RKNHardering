package com.notcvnt.rknhardering

import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
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
import com.notcvnt.rknhardering.probe.ProxyScanner
import java.text.NumberFormat

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
        textPortRangePreview = findViewById(R.id.textPortRangePreview)
        switchNetworkRequests = findViewById(R.id.switchNetworkRequests)
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
        updatePortRangePreview()

        loadResolverSettings()

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
            updatePortRangePreview()
        }

        chipGroupResolverMode.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            saveCustomResolverFields()
            prefs.edit()
                .putString(PREF_DNS_RESOLVER_MODE, selectedResolverMode().prefValue)
                .apply()
            refreshResolverUi(restoreCustomValues = true)
        }

        chipGroupResolverPreset.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            saveCustomResolverFields()
            prefs.edit()
                .putString(PREF_DNS_RESOLVER_PRESET, selectedResolverPreset().prefValue)
                .apply()
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

    private fun updatePortRangePreview() {
        val mergedPorts = mergePortRanges(
            buildScanPortRanges(
                portRange = selectedPortRange(),
                customRange = currentCustomPortRange(),
            ),
        )
        val portsText = mergedPorts.joinToString(", ") { range ->
            if (range.first == range.last) {
                range.first.toString()
            } else {
                "${range.first}-${range.last}"
            }
        }
        val portsCount = mergedPorts.sumOf { it.last - it.first + 1 }
        val formattedCount = NumberFormat.getIntegerInstance().format(portsCount)
        textPortRangePreview.text = "Будут сканироваться proxy-порты localhost: $portsText ($formattedCount ${portWord(portsCount)})"
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
        val start = editPortStart.text.toString().toIntOrNull()?.coerceIn(1024, 65535) ?: 1024
        val end = editPortEnd.text.toString().toIntOrNull()?.coerceIn(1024, 65535) ?: 65535
        return minOf(start, end)..maxOf(start, end)
    }

    private fun buildScanPortRanges(portRange: String, customRange: IntRange): List<IntRange> {
        val ranges = ProxyScanner.DEFAULT_POPULAR_PORTS
            .map { it..it }
            .toMutableList()
        when (portRange) {
            "extended" -> ranges += 1024..15000
            "full" -> ranges += 1024..65535
            "custom" -> ranges += customRange
        }
        return ranges
    }

    private fun mergePortRanges(ranges: List<IntRange>): List<IntRange> {
        if (ranges.isEmpty()) return emptyList()

        val sortedRanges = ranges.sortedBy { it.first }
        val mergedRanges = mutableListOf<IntRange>()
        var currentStart = sortedRanges.first().first
        var currentEnd = sortedRanges.first().last

        for (range in sortedRanges.drop(1)) {
            if (range.first <= currentEnd + 1) {
                currentEnd = maxOf(currentEnd, range.last)
            } else {
                mergedRanges += currentStart..currentEnd
                currentStart = range.first
                currentEnd = range.last
            }
        }

        mergedRanges += currentStart..currentEnd
        return mergedRanges
    }

    private fun portWord(count: Int): String {
        val mod100 = count % 100
        val mod10 = count % 10
        return when {
            mod100 in 11..14 -> "портов"
            mod10 == 1 -> "порт"
            mod10 in 2..4 -> "порта"
            else -> "портов"
        }
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
        prefs.edit()
            .putString(PREF_DNS_RESOLVER_DIRECT_SERVERS, editResolverDirectServers.text?.toString().orEmpty().trim())
            .putString(PREF_DNS_RESOLVER_DOH_URL, editResolverDohUrl.text?.toString().orEmpty().trim())
            .putString(PREF_DNS_RESOLVER_DOH_BOOTSTRAP, editResolverBootstrap.text?.toString().orEmpty().trim())
            .apply()
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
        const val PREF_DNS_RESOLVER_MODE = "pref_dns_resolver_mode"
        const val PREF_DNS_RESOLVER_PRESET = "pref_dns_resolver_preset"
        const val PREF_DNS_RESOLVER_DIRECT_SERVERS = "pref_dns_resolver_direct_servers"
        const val PREF_DNS_RESOLVER_DOH_URL = "pref_dns_resolver_doh_url"
        const val PREF_DNS_RESOLVER_DOH_BOOTSTRAP = "pref_dns_resolver_doh_bootstrap"
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
