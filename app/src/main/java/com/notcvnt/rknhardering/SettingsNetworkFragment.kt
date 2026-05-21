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
    private lateinit var cardAutoUpdate: MaterialCardView
    private lateinit var switchAutoUpdate: MaterialSwitch

    private var suppressAutoUpdateToggleCallback = false
    private var suppressNetworkRequestsToggleCallback = false
    private var networkDisableDialog: AlertDialog? = null

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        bindViews(view)
        loadSettings()
        setupListeners()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        networkDisableDialog?.dismiss()
        networkDisableDialog = null
    }

    private fun bindViews(view: View) {
        switchNetworkRequests = view.findViewById(R.id.switchNetworkRequests)
        cardAutoUpdate = view.findViewById(R.id.cardAutoUpdate)
        switchAutoUpdate = view.findViewById(R.id.switchAutoUpdate)
    }

    private fun loadSettings() {
        val networkRequestsEnabled = prefs.getBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true)
        switchNetworkRequests.isChecked = networkRequestsEnabled
        setAutoUpdateSwitch(networkRequestsEnabled && AppUpdateChecker.isAutoUpdateEnabled(requireContext()))
        updateAutoUpdateEnabled(networkRequestsEnabled)
    }

    private fun setupListeners() {
        switchNetworkRequests.setOnCheckedChangeListener { _, isChecked ->
            if (suppressNetworkRequestsToggleCallback) return@setOnCheckedChangeListener
            if (!isChecked) {
                showNetworkDisableConfirmation()
            } else {
                prefs.edit { putBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, true) }
                updateAutoUpdateEnabled(true)
            }
        }

        switchAutoUpdate.setOnCheckedChangeListener { _, isChecked ->
            if (suppressAutoUpdateToggleCallback) return@setOnCheckedChangeListener
            AppUpdateChecker.setAutoUpdateEnabled(requireContext(), isChecked)
        }
    }

    private fun updateAutoUpdateEnabled(enabled: Boolean) {
        cardAutoUpdate.alpha = if (enabled) 1.0f else 0.5f
        setViewAndChildrenEnabled(cardAutoUpdate, enabled)
        if (!enabled) {
            AppUpdateChecker.setAutoUpdateEnabled(requireContext(), false, markChoiceMade = false)
            setAutoUpdateSwitch(false)
        } else {
            setAutoUpdateSwitch(AppUpdateChecker.isAutoUpdateEnabled(requireContext()))
        }
    }

    private fun setAutoUpdateSwitch(checked: Boolean) {
        suppressAutoUpdateToggleCallback = true
        switchAutoUpdate.isChecked = checked
        suppressAutoUpdateToggleCallback = false
    }

    private fun showNetworkDisableConfirmation() {
        networkDisableDialog = AlertDialog.Builder(requireContext())
            .setTitle(R.string.settings_network_disable_title)
            .setMessage(R.string.settings_network_disable_message)
            .setPositiveButton(R.string.settings_network_disable_confirm) { _, _ ->
                prefs.edit { putBoolean(SettingsPrefs.PREF_NETWORK_REQUESTS_ENABLED, false) }
                updateAutoUpdateEnabled(false)
            }
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                setNetworkRequestsSwitch(true)
            }
            .setOnCancelListener {
                setNetworkRequestsSwitch(true)
            }
            .show()
    }

    private fun setNetworkRequestsSwitch(checked: Boolean) {
        suppressNetworkRequestsToggleCallback = true
        switchNetworkRequests.isChecked = checked
        suppressNetworkRequestsToggleCallback = false
    }
}
