package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.edit
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import com.google.android.material.card.MaterialCardView
import com.google.android.material.chip.ChipGroup
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.notcvnt.rknhardering.probe.PortScanPlanner
import com.notcvnt.rknhardering.probe.TunProbeModeOverride
import java.text.NumberFormat
import java.util.Locale

internal class SettingsSplitTunnelFragment : Fragment(R.layout.fragment_settings_split_tunnel) {

    private lateinit var prefs: SharedPreferences

    private lateinit var switchSplitTunnel: MaterialSwitch
    private lateinit var switchTunProbeDebug: MaterialSwitch
    private lateinit var cardTunProbeMode: MaterialCardView
    private lateinit var cardProxyScan: MaterialCardView
    private lateinit var switchProxyScan: MaterialSwitch
    private lateinit var cardXrayApiScan: MaterialCardView
    private lateinit var switchXrayApiScan: MaterialSwitch
    private lateinit var cardPortRange: MaterialCardView
    private lateinit var chipGroupPortRange: ChipGroup
    private lateinit var customPortRangeContainer: LinearLayout
    private lateinit var editPortStart: TextInputEditText
    private lateinit var editPortEnd: TextInputEditText
    private lateinit var textPortRangePreview: TextView
    private lateinit var chipGroupTunProbeMode: ChipGroup

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        bindViews(view)
        loadSettings()
        setupListeners()
    }

    private fun bindViews(view: View) {
        switchSplitTunnel = view.findViewById(R.id.switchSplitTunnel)
        switchTunProbeDebug = view.findViewById(R.id.switchTunProbeDebug)
        cardTunProbeMode = view.findViewById(R.id.cardTunProbeMode)
        cardProxyScan = view.findViewById(R.id.cardProxyScan)
        switchProxyScan = view.findViewById(R.id.switchProxyScan)
        cardXrayApiScan = view.findViewById(R.id.cardXrayApiScan)
        switchXrayApiScan = view.findViewById(R.id.switchXrayApiScan)
        cardPortRange = view.findViewById(R.id.cardPortRange)
        chipGroupPortRange = view.findViewById(R.id.chipGroupPortRange)
        customPortRangeContainer = view.findViewById(R.id.customPortRangeContainer)
        editPortStart = view.findViewById(R.id.editPortStart)
        editPortEnd = view.findViewById(R.id.editPortEnd)
        textPortRangePreview = view.findViewById(R.id.textPortRangePreview)
        chipGroupTunProbeMode = view.findViewById(R.id.chipGroupTunProbeMode)
    }

    private fun loadSettings() {
        switchSplitTunnel.isChecked = prefs.getBoolean(SettingsPrefs.PREF_SPLIT_TUNNEL_ENABLED, true)
        switchTunProbeDebug.isChecked = prefs.getBoolean(SettingsPrefs.PREF_TUN_PROBE_DEBUG_ENABLED, false)
        switchProxyScan.isChecked = prefs.getBoolean(SettingsPrefs.PREF_PROXY_SCAN_ENABLED, true)
        switchXrayApiScan.isChecked = prefs.getBoolean(SettingsPrefs.PREF_XRAY_API_SCAN_ENABLED, true)

        updateLocalScanTogglesEnabled(switchSplitTunnel.isChecked)
        updateTunProbeModeEnabled(switchSplitTunnel.isChecked)
        updatePortRangeEnabled(switchSplitTunnel.isChecked && isAnyLocalScanEnabled())
        loadTunProbeSettings()

        val portRange = prefs.getString(SettingsPrefs.PREF_PORT_RANGE, "full") ?: "full"
        val chipId = when (portRange) {
            "popular" -> R.id.chipPortPopular
            "extended" -> R.id.chipPortExtended
            "full" -> R.id.chipPortFull
            "custom" -> R.id.chipPortCustom
            else -> R.id.chipPortFull
        }
        chipGroupPortRange.check(chipId)
        customPortRangeContainer.visibility = if (portRange == "custom") View.VISIBLE else View.GONE

        editPortStart.setText(formatPortInputValue(prefs.getInt(SettingsPrefs.PREF_PORT_RANGE_START, 1024)))
        editPortEnd.setText(formatPortInputValue(prefs.getInt(SettingsPrefs.PREF_PORT_RANGE_END, 65535)))
        updatePortRangePreview()
    }

    private fun setupListeners() {
        switchSplitTunnel.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(SettingsPrefs.PREF_SPLIT_TUNNEL_ENABLED, isChecked) }
            updateLocalScanTogglesEnabled(isChecked)
            updateTunProbeModeEnabled(isChecked)
            updatePortRangeEnabled(isChecked && isAnyLocalScanEnabled())
        }

        switchTunProbeDebug.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(SettingsPrefs.PREF_TUN_PROBE_DEBUG_ENABLED, isChecked) }
        }

        switchProxyScan.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(SettingsPrefs.PREF_PROXY_SCAN_ENABLED, isChecked) }
            updatePortRangeEnabled(switchSplitTunnel.isChecked && (isChecked || switchXrayApiScan.isChecked))
            updatePortRangePreview()
        }

        switchXrayApiScan.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(SettingsPrefs.PREF_XRAY_API_SCAN_ENABLED, isChecked) }
            updatePortRangeEnabled(switchSplitTunnel.isChecked && (isChecked || switchProxyScan.isChecked))
            updatePortRangePreview()
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
            prefs.edit { putString(SettingsPrefs.PREF_PORT_RANGE, value) }
            customPortRangeContainer.visibility = if (value == "custom") View.VISIBLE else View.GONE
            updatePortRangePreview()
        }

        chipGroupTunProbeMode.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            prefs.edit {
                putString(SettingsPrefs.PREF_TUN_PROBE_MODE_OVERRIDE, selectedTunProbeModeOverride().prefValue)
            }
        }

        editPortStart.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomPortRange()
        }
        editPortEnd.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveCustomPortRange()
        }
        editPortStart.doAfterTextChanged { updatePortRangePreview() }
        editPortEnd.doAfterTextChanged { updatePortRangePreview() }
    }

    private fun updateLocalScanTogglesEnabled(enabled: Boolean) {
        cardProxyScan.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardProxyScan, enabled)
        cardXrayApiScan.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardXrayApiScan, enabled)
    }

    private fun updateTunProbeModeEnabled(enabled: Boolean) {
        cardTunProbeMode.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardTunProbeMode, enabled)
    }

    private fun updatePortRangeEnabled(enabled: Boolean) {
        cardPortRange.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardPortRange, enabled)
    }

    private fun loadTunProbeSettings() {
        val mode = TunProbeModeOverride.fromPref(
            prefs.getString(SettingsPrefs.PREF_TUN_PROBE_MODE_OVERRIDE, TunProbeModeOverride.AUTO.prefValue),
        )
        chipGroupTunProbeMode.check(
            when (mode) {
                TunProbeModeOverride.AUTO -> R.id.chipTunProbeModeAuto
                TunProbeModeOverride.STRICT_SAME_PATH -> R.id.chipTunProbeModeStrict
                TunProbeModeOverride.CURL_COMPATIBLE -> R.id.chipTunProbeModeCurl
            },
        )
    }

    private fun saveCustomPortRange() {
        val normalizedRange = PortScanPlanner.normalizeCustomRange(
            start = editPortStart.text.toString().toIntOrNull() ?: PortScanPlanner.MIN_PORT,
            end = editPortEnd.text.toString().toIntOrNull() ?: PortScanPlanner.MAX_PORT,
        )
        prefs.edit {
            putInt(SettingsPrefs.PREF_PORT_RANGE_START, normalizedRange.first)
            putInt(SettingsPrefs.PREF_PORT_RANGE_END, normalizedRange.last)
        }
        editPortStart.setText(formatPortInputValue(normalizedRange.first))
        editPortEnd.setText(formatPortInputValue(normalizedRange.last))
    }

    private fun updatePortRangePreview() {
        if (!isAnyLocalScanEnabled()) {
            textPortRangePreview.text = getString(R.string.settings_port_range_preview_disabled)
            return
        }
        val previewRanges = PortScanPlanner.buildPreviewRanges(
            portRange = selectedPortRange(),
            portRangeStart = currentCustomPortRange().first,
            portRangeEnd = currentCustomPortRange().last,
        )
        val portsText = previewRanges.joinToString(", ") { range ->
            if (range.first == range.last) range.first.toString() else "${range.first}-${range.last}"
        }
        val portsCount = previewRanges.sumOf { it.last - it.first + 1 }
        val formattedCount = NumberFormat.getIntegerInstance().format(portsCount)
        val portCountLabel = resources.getQuantityString(R.plurals.settings_port_word, portsCount, formattedCount)
        val previewFormat = when {
            switchProxyScan.isChecked && switchXrayApiScan.isChecked -> R.string.settings_port_range_preview_proxy_xray
            switchProxyScan.isChecked -> R.string.settings_port_range_preview_proxy_only
            else -> R.string.settings_port_range_preview_xray_only
        }
        textPortRangePreview.text = getString(previewFormat, portsText, portCountLabel)
    }

    private fun isAnyLocalScanEnabled(): Boolean =
        switchProxyScan.isChecked || switchXrayApiScan.isChecked

    private fun selectedPortRange(): String = when (chipGroupPortRange.checkedChipId) {
        R.id.chipPortPopular -> "popular"
        R.id.chipPortExtended -> "extended"
        R.id.chipPortCustom -> "custom"
        else -> "full"
    }

    private fun currentCustomPortRange(): IntRange = PortScanPlanner.normalizeCustomRange(
        start = editPortStart.text.toString().toIntOrNull() ?: PortScanPlanner.MIN_PORT,
        end = editPortEnd.text.toString().toIntOrNull() ?: PortScanPlanner.MAX_PORT,
    )

    private fun selectedTunProbeModeOverride(): TunProbeModeOverride = when (chipGroupTunProbeMode.checkedChipId) {
        R.id.chipTunProbeModeStrict -> TunProbeModeOverride.STRICT_SAME_PATH
        R.id.chipTunProbeModeCurl -> TunProbeModeOverride.CURL_COMPATIBLE
        else -> TunProbeModeOverride.AUTO
    }

    private fun formatPortInputValue(value: Int): String = String.format(Locale.US, "%d", value)
}
