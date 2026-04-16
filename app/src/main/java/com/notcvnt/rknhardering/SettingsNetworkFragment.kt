package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import com.google.android.material.card.MaterialCardView
import com.google.android.material.materialswitch.MaterialSwitch

internal class SettingsNetworkFragment : Fragment(R.layout.fragment_settings_network) {

    private lateinit var prefs: SharedPreferences

    private lateinit var switchNetworkRequests: MaterialSwitch
    private lateinit var cardCdnPulling: MaterialCardView
    private lateinit var switchCdnPulling: MaterialSwitch
    private lateinit var cardCdnPullingMeduza: MaterialCardView
    private lateinit var switchCdnPullingMeduza: MaterialSwitch
    private lateinit var cardCallTransportProbe: MaterialCardView
    private lateinit var switchCallTransportProbe: MaterialSwitch

    private var suppressCdnPullingToggleCallback = false
    private var cdnWarningDialog: AlertDialog? = null

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        bindViews(view)
        loadSettings()
        setupListeners()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        cdnWarningDialog?.dismiss()
        cdnWarningDialog = null
    }

    private fun bindViews(view: View) {
        switchNetworkRequests = view.findViewById(R.id.switchNetworkRequests)
        cardCdnPulling = view.findViewById(R.id.cardCdnPulling)
        switchCdnPulling = view.findViewById(R.id.switchCdnPulling)
        cardCdnPullingMeduza = view.findViewById(R.id.cardCdnPullingMeduza)
        switchCdnPullingMeduza = view.findViewById(R.id.switchCdnPullingMeduza)
        cardCallTransportProbe = view.findViewById(R.id.cardCallTransportProbe)
        switchCallTransportProbe = view.findViewById(R.id.switchCallTransportProbe)
    }

    private fun loadSettings() {
        switchNetworkRequests.isChecked = prefs.getBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true)
        switchCdnPulling.isChecked = prefs.getBoolean(SettingsPrefs.PREF_CDN_PULLING_ENABLED, false)
        switchCdnPullingMeduza.isChecked = prefs.getBoolean(SettingsPrefs.PREF_CDN_PULLING_MEDUZA_ENABLED, true)
        switchCallTransportProbe.isChecked = prefs.getBoolean(SettingsPrefs.PREF_CALL_TRANSPORT_PROBE_ENABLED, false)

        updateCdnPullingEnabled(switchNetworkRequests.isChecked)
        updateCdnPullingMeduzaVisible(switchCdnPulling.isChecked)
        updateCallTransportEnabled(switchNetworkRequests.isChecked)
    }

    private fun setupListeners() {
        switchNetworkRequests.setOnCheckedChangeListener { _, isChecked ->
            updateCdnPullingEnabled(isChecked)
            updateCallTransportEnabled(isChecked)
            if (!isChecked) {
                AlertDialog.Builder(requireContext())
                    .setTitle(R.string.settings_network_disable_title)
                    .setMessage(R.string.settings_network_disable_message)
                    .setPositiveButton(R.string.settings_network_disable_confirm) { _, _ ->
                        prefs.edit { putBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, false) }
                    }
                    .setNegativeButton(android.R.string.cancel) { _, _ ->
                        switchNetworkRequests.isChecked = true
                    }
                    .setOnCancelListener {
                        switchNetworkRequests.isChecked = true
                    }
                    .show()
            } else {
                prefs.edit { putBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true) }
            }
        }

        switchCdnPulling.setOnCheckedChangeListener { _, isChecked ->
            if (suppressCdnPullingToggleCallback) return@setOnCheckedChangeListener
            if (isChecked) {
                showCdnPullingWarning()
            } else {
                prefs.edit { putBoolean(SettingsPrefs.PREF_CDN_PULLING_ENABLED, false) }
                updateCdnPullingMeduzaVisible(false)
            }
        }

        switchCdnPullingMeduza.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(SettingsPrefs.PREF_CDN_PULLING_MEDUZA_ENABLED, isChecked) }
        }

        switchCallTransportProbe.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(SettingsPrefs.PREF_CALL_TRANSPORT_PROBE_ENABLED, isChecked) }
        }
    }

    private fun updateCdnPullingEnabled(enabled: Boolean) {
        cardCdnPulling.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardCdnPulling, enabled)
        if (!enabled) updateCdnPullingMeduzaVisible(false)
    }

    private fun updateCdnPullingMeduzaVisible(visible: Boolean) {
        cardCdnPullingMeduza.visibility = if (visible) View.VISIBLE else View.GONE
    }

    private fun updateCallTransportEnabled(enabled: Boolean) {
        cardCallTransportProbe.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardCallTransportProbe, enabled)
    }

    private fun showCdnPullingWarning() {
        cdnWarningDialog = AlertDialog.Builder(requireContext())
            .setTitle(R.string.settings_cdn_pulling_warning_title)
            .setMessage(buildCdnPullingWarningMessage(requireContext()))
            .setPositiveButton(R.string.settings_cdn_pulling_warning_confirm) { _, _ ->
                prefs.edit { putBoolean(SettingsPrefs.PREF_CDN_PULLING_ENABLED, true) }
                updateCdnPullingMeduzaVisible(true)
            }
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                setCdnPullingSwitch(false)
            }
            .setOnCancelListener {
                setCdnPullingSwitch(false)
            }
            .show()
    }

    private fun setCdnPullingSwitch(checked: Boolean) {
        suppressCdnPullingToggleCallback = true
        switchCdnPulling.isChecked = checked
        suppressCdnPullingToggleCallback = false
    }
}
