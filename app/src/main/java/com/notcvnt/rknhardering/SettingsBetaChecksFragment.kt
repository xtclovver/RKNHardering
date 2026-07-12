package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import android.widget.RadioGroup
import androidx.appcompat.app.AlertDialog
import androidx.core.content.edit
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import com.google.android.material.materialswitch.MaterialSwitch
import com.notcvnt.rknhardering.model.PrivilegedProbeProvider
import com.notcvnt.rknhardering.probe.privileged.ShizukuPermissionController
import com.notcvnt.rknhardering.probe.privileged.ShizukuPermissionState

internal class SettingsBetaChecksFragment : Fragment(R.layout.fragment_settings_beta_checks) {

    private lateinit var prefs: SharedPreferences
    private lateinit var masterSwitch: MaterialSwitch
    private lateinit var childContainer: View
    private lateinit var privilegedSwitch: MaterialSwitch
    private lateinit var privilegedProviderGroup: RadioGroup
    private var suppressMasterCallback = false
    private var suppressPrivilegedCallback = false
    private var warningDialog: AlertDialog? = null

    private val childSwitches = listOf(
        ChildSwitch(R.id.switchBetaHiddenAndroidApis, SettingsPrefs.PREF_BETA_HIDDEN_ANDROID_APIS, true, available = true),
        ChildSwitch(R.id.switchBetaKernelNetlink, SettingsPrefs.PREF_BETA_KERNEL_NETLINK, true, available = true),
        ChildSwitch(R.id.switchBetaSocketOracles, SettingsPrefs.PREF_BETA_SOCKET_ORACLES, true, available = true),
        ChildSwitch(R.id.switchBetaProfileIsolation, SettingsPrefs.PREF_BETA_PROFILE_ISOLATION, true, available = true),
        ChildSwitch(R.id.switchBetaSandboxIntegrity, SettingsPrefs.PREF_BETA_SANDBOX_INTEGRITY, true, available = true),
        ChildSwitch(R.id.switchBetaBpfNetfilter, SettingsPrefs.PREF_BETA_BPF_NETFILTER, false, available = true),
        ChildSwitch(R.id.switchBetaAggressiveScan, SettingsPrefs.PREF_BETA_AGGRESSIVE_SCAN, false, available = true),
    )

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        masterSwitch = view.findViewById(R.id.switchBetaChecks)
        childContainer = view.findViewById(R.id.betaChildChecks)
        privilegedSwitch = view.findViewById(R.id.switchBetaPrivilegedChecks)
        privilegedProviderGroup = view.findViewById(R.id.groupBetaPrivilegedProvider)

        loadSettings(view)
        setupListeners(view)
    }

    override fun onDestroyView() {
        warningDialog?.dismiss()
        warningDialog = null
        super.onDestroyView()
    }

    private fun loadSettings(root: View) {
        val masterEnabled = prefs.getBoolean(SettingsPrefs.PREF_BETA_CHECKS_ENABLED, false)
        setMasterChecked(masterEnabled)
        childSwitches.forEach { child ->
            val childSwitch = root.findViewById<MaterialSwitch>(child.switchId)
            (childSwitch.parent as View).isVisible = child.available
            childSwitch.isChecked = prefs.getBoolean(child.preference, child.defaultValue)
        }
        privilegedSwitch.isChecked = prefs.getBoolean(SettingsPrefs.PREF_BETA_PRIVILEGED_CHECKS_ENABLED, false)
        val provider = prefs.getString(SettingsPrefs.PREF_BETA_PRIVILEGED_PROVIDER, null)
            ?.let { runCatching { PrivilegedProbeProvider.valueOf(it) }.getOrNull() }
            ?: PrivilegedProbeProvider.NONE
        privilegedProviderGroup.check(
            if (provider == PrivilegedProbeProvider.ROOT) {
                R.id.radioBetaProviderRoot
            } else {
                R.id.radioBetaProviderShizuku
            },
        )
        updateChildrenEnabled(masterEnabled)
    }

    private fun setupListeners(root: View) {
        masterSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (suppressMasterCallback) return@setOnCheckedChangeListener
            if (isChecked && !prefs.getBoolean(SettingsPrefs.PREF_BETA_WARNING_ACCEPTED, false)) {
                setMasterChecked(false)
                showFirstEnableWarning()
            } else {
                setMasterEnabled(isChecked)
            }
        }

        childSwitches.forEach { child ->
            root.findViewById<MaterialSwitch>(child.switchId).setOnCheckedChangeListener { _, isChecked ->
                prefs.edit { putBoolean(child.preference, isChecked) }
            }
        }
        privilegedSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (suppressPrivilegedCallback) return@setOnCheckedChangeListener
            if (isChecked && !prefs.getBoolean(SettingsPrefs.PREF_BETA_PRIVILEGED_WARNING_ACCEPTED, false)) {
                setPrivilegedChecked(false)
                showPrivilegedWarning()
            } else {
                persistPrivilegedEnabled(isChecked)
            }
        }
        privilegedProviderGroup.setOnCheckedChangeListener { _, checkedId ->
            val provider = if (checkedId == R.id.radioBetaProviderRoot) {
                PrivilegedProbeProvider.ROOT
            } else {
                PrivilegedProbeProvider.SHIZUKU
            }
            prefs.edit { putString(SettingsPrefs.PREF_BETA_PRIVILEGED_PROVIDER, provider.name) }
            if (provider == PrivilegedProbeProvider.SHIZUKU && privilegedSwitch.isChecked) {
                requestShizukuPermissionIfSelected()
            }
        }
    }

    private fun showFirstEnableWarning() {
        if (warningDialog?.isShowing == true) return
        warningDialog = AlertDialog.Builder(requireContext())
            .setTitle(R.string.settings_beta_warning_title)
            .setMessage(R.string.settings_beta_warning_message)
            .setPositiveButton(R.string.settings_beta_warning_confirm) { _, _ ->
                prefs.edit { putBoolean(SettingsPrefs.PREF_BETA_WARNING_ACCEPTED, true) }
                setMasterEnabled(true)
                setMasterChecked(true)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
            .also { it.show() }
    }

    private fun setMasterEnabled(enabled: Boolean) {
        prefs.edit { putBoolean(SettingsPrefs.PREF_BETA_CHECKS_ENABLED, enabled) }
        updateChildrenEnabled(enabled)
    }

    private fun showPrivilegedWarning() {
        if (warningDialog?.isShowing == true) return
        warningDialog = AlertDialog.Builder(requireContext())
            .setTitle(R.string.settings_beta_privileged_warning_title)
            .setMessage(R.string.settings_beta_privileged_warning_message)
            .setPositiveButton(R.string.settings_beta_warning_confirm) { _, _ ->
                val providerUnset = prefs.getString(SettingsPrefs.PREF_BETA_PRIVILEGED_PROVIDER, null) == null
                prefs.edit {
                    putBoolean(SettingsPrefs.PREF_BETA_PRIVILEGED_WARNING_ACCEPTED, true)
                    if (providerUnset) {
                        putString(SettingsPrefs.PREF_BETA_PRIVILEGED_PROVIDER, PrivilegedProbeProvider.SHIZUKU.name)
                    }
                }
                persistPrivilegedEnabled(true)
                setPrivilegedChecked(true)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
            .also { it.show() }
    }

    private fun persistPrivilegedEnabled(enabled: Boolean) {
        prefs.edit { putBoolean(SettingsPrefs.PREF_BETA_PRIVILEGED_CHECKS_ENABLED, enabled) }
        updatePrivilegedProviderEnabled(masterSwitch.isChecked && enabled)
        if (enabled) requestShizukuPermissionIfSelected()
    }

    private fun requestShizukuPermissionIfSelected() {
        if (privilegedProviderGroup.checkedRadioButtonId != R.id.radioBetaProviderShizuku) return
        if (ShizukuPermissionController.state() == ShizukuPermissionState.RATIONALE_REQUIRED) {
            if (warningDialog?.isShowing == true) return
            warningDialog = AlertDialog.Builder(requireContext())
                .setTitle(R.string.settings_beta_shizuku_permission_title)
                .setMessage(R.string.settings_beta_shizuku_permission_rationale)
                .setPositiveButton(R.string.settings_beta_warning_confirm) { _, _ ->
                    ShizukuPermissionController.requestAfterConsent(SHIZUKU_PERMISSION_REQUEST_CODE)
                }
                .setNegativeButton(android.R.string.cancel, null)
                .create()
                .also { it.show() }
        } else {
            ShizukuPermissionController.requestAfterConsent(SHIZUKU_PERMISSION_REQUEST_CODE)
        }
    }

    private fun setPrivilegedChecked(checked: Boolean) {
        suppressPrivilegedCallback = true
        privilegedSwitch.isChecked = checked
        suppressPrivilegedCallback = false
    }

    private fun setMasterChecked(checked: Boolean) {
        suppressMasterCallback = true
        masterSwitch.isChecked = checked
        suppressMasterCallback = false
    }

    private fun updateChildrenEnabled(enabled: Boolean) {
        childContainer.alpha = if (enabled) 1.0f else 0.5f
        childSwitches.forEach { child ->
            childContainer.findViewById<View>(child.switchId).isEnabled = enabled && child.available
        }
        privilegedSwitch.isEnabled = enabled
        updatePrivilegedProviderEnabled(enabled && privilegedSwitch.isChecked)
    }

    private fun updatePrivilegedProviderEnabled(enabled: Boolean) {
        for (index in 0 until privilegedProviderGroup.childCount) {
            privilegedProviderGroup.getChildAt(index).isEnabled = enabled
        }
    }

    private data class ChildSwitch(
        val switchId: Int,
        val preference: String,
        val defaultValue: Boolean,
        val available: Boolean,
    )

    private companion object {
        const val SHIZUKU_PERMISSION_REQUEST_CODE = 0xB37A
    }
}
