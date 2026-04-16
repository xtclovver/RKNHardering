package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import com.google.android.material.materialswitch.MaterialSwitch

internal class SettingsPrivacyFragment : Fragment(R.layout.fragment_settings_privacy) {

    private lateinit var prefs: SharedPreferences

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        val switchPrivacyMode = view.findViewById<MaterialSwitch>(R.id.switchPrivacyMode)
        switchPrivacyMode.isChecked = prefs.getBoolean(SettingsPrefs.PREF_PRIVACY_MODE, false)
        switchPrivacyMode.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(SettingsPrefs.PREF_PRIVACY_MODE, isChecked) }
        }
    }
}
