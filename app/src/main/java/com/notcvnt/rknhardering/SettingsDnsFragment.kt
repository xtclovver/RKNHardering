package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import com.google.android.material.chip.ChipGroup
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.DnsResolverMode
import com.notcvnt.rknhardering.network.DnsResolverPreset
import com.notcvnt.rknhardering.network.DnsResolverPresets

internal class SettingsDnsFragment : Fragment(R.layout.fragment_settings_dns) {

    private lateinit var prefs: SharedPreferences

    private lateinit var chipGroupResolverMode: ChipGroup
    private lateinit var chipGroupResolverPreset: ChipGroup
    private lateinit var inputResolverDirectServersLayout: TextInputLayout
    private lateinit var inputResolverDohUrlLayout: TextInputLayout
    private lateinit var inputResolverBootstrapLayout: TextInputLayout
    private lateinit var editResolverDirectServers: TextInputEditText
    private lateinit var editResolverDohUrl: TextInputEditText
    private lateinit var editResolverBootstrap: TextInputEditText

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        bindViews(view)
        loadResolverSettings()
        setupListeners()
    }

    private fun bindViews(view: View) {
        chipGroupResolverMode = view.findViewById(R.id.chipGroupResolverMode)
        chipGroupResolverPreset = view.findViewById(R.id.chipGroupResolverPreset)
        inputResolverDirectServersLayout = view.findViewById(R.id.inputResolverDirectServersLayout)
        inputResolverDohUrlLayout = view.findViewById(R.id.inputResolverDohUrlLayout)
        inputResolverBootstrapLayout = view.findViewById(R.id.inputResolverBootstrapLayout)
        editResolverDirectServers = view.findViewById(R.id.editResolverDirectServers)
        editResolverDohUrl = view.findViewById(R.id.editResolverDohUrl)
        editResolverBootstrap = view.findViewById(R.id.editResolverBootstrap)
    }

    private fun loadResolverSettings() {
        val mode = DnsResolverMode.fromPref(
            prefs.getString(SettingsPrefs.PREF_DNS_RESOLVER_MODE, DnsResolverMode.SYSTEM.prefValue),
        )
        chipGroupResolverMode.check(
            when (mode) {
                DnsResolverMode.SYSTEM -> R.id.chipResolverSystem
                DnsResolverMode.DIRECT -> R.id.chipResolverDirect
                DnsResolverMode.DOH -> R.id.chipResolverDoh
            },
        )

        val preset = DnsResolverPreset.fromPref(
            prefs.getString(SettingsPrefs.PREF_DNS_RESOLVER_PRESET, DnsResolverPreset.CUSTOM.prefValue),
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

    private fun setupListeners() {
        chipGroupResolverMode.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            saveCustomResolverFields()
            prefs.edit { putString(SettingsPrefs.PREF_DNS_RESOLVER_MODE, selectedResolverMode().prefValue) }
            refreshResolverUi(restoreCustomValues = true)
        }

        chipGroupResolverPreset.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            saveCustomResolverFields()
            prefs.edit { putString(SettingsPrefs.PREF_DNS_RESOLVER_PRESET, selectedResolverPreset().prefValue) }
            refreshResolverUi(restoreCustomValues = true)
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
    }

    private fun loadCustomResolverFields() {
        editResolverDirectServers.setText(prefs.getString(SettingsPrefs.PREF_DNS_RESOLVER_DIRECT_SERVERS, "").orEmpty())
        editResolverDohUrl.setText(prefs.getString(SettingsPrefs.PREF_DNS_RESOLVER_DOH_URL, "").orEmpty())
        editResolverBootstrap.setText(prefs.getString(SettingsPrefs.PREF_DNS_RESOLVER_DOH_BOOTSTRAP, "").orEmpty())
    }

    private fun saveCustomResolverFields() {
        if (persistedResolverPreset() != DnsResolverPreset.CUSTOM) return
        prefs.edit {
            putString(SettingsPrefs.PREF_DNS_RESOLVER_DIRECT_SERVERS, editResolverDirectServers.text?.toString().orEmpty().trim())
            putString(SettingsPrefs.PREF_DNS_RESOLVER_DOH_URL, editResolverDohUrl.text?.toString().orEmpty().trim())
            putString(SettingsPrefs.PREF_DNS_RESOLVER_DOH_BOOTSTRAP, editResolverBootstrap.text?.toString().orEmpty().trim())
        }
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
                setTextIfDifferent(editResolverDirectServers, DnsResolverConfig.serializeAddressList(presetSpec.directServers))
            }
            mode == DnsResolverMode.DOH && !customPreset && presetSpec != null -> {
                setTextIfDifferent(editResolverDohUrl, presetSpec.dohUrl)
                setTextIfDifferent(editResolverBootstrap, DnsResolverConfig.serializeAddressList(presetSpec.dohBootstrapHosts))
            }
            customPreset && restoreCustomValues -> {
                loadCustomResolverFields()
            }
        }

        setViewAndChildrenEnabled(inputResolverDirectServersLayout, customPreset)
        setViewAndChildrenEnabled(inputResolverDohUrlLayout, customPreset)
        setViewAndChildrenEnabled(inputResolverBootstrapLayout, customPreset)
    }

    private fun persistedResolverPreset(): DnsResolverPreset = DnsResolverPreset.fromPref(
        prefs.getString(SettingsPrefs.PREF_DNS_RESOLVER_PRESET, DnsResolverPreset.CUSTOM.prefValue),
    )

    private fun selectedResolverMode(): DnsResolverMode = when (chipGroupResolverMode.checkedChipId) {
        R.id.chipResolverDirect -> DnsResolverMode.DIRECT
        R.id.chipResolverDoh -> DnsResolverMode.DOH
        else -> DnsResolverMode.SYSTEM
    }

    private fun selectedResolverPreset(): DnsResolverPreset = when (chipGroupResolverPreset.checkedChipId) {
        R.id.chipResolverPresetCloudflare -> DnsResolverPreset.CLOUDFLARE
        R.id.chipResolverPresetGoogle -> DnsResolverPreset.GOOGLE
        R.id.chipResolverPresetYandex -> DnsResolverPreset.YANDEX
        else -> DnsResolverPreset.CUSTOM
    }

    private fun setTextIfDifferent(view: TextInputEditText, value: String) {
        if (view.text?.toString() != value) view.setText(value)
    }
}
