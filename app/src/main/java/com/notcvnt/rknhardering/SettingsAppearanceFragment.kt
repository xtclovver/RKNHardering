package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import com.google.android.material.chip.ChipGroup

internal class SettingsAppearanceFragment : Fragment(R.layout.fragment_settings_appearance) {

    private lateinit var prefs: SharedPreferences
    private lateinit var chipGroupTheme: ChipGroup
    private lateinit var chipGroupLanguage: ChipGroup

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        chipGroupTheme = view.findViewById(R.id.chipGroupTheme)
        chipGroupLanguage = view.findViewById(R.id.chipGroupLanguage)
        loadSettings()
        setupListeners()
    }

    private fun loadSettings() {
        val theme = prefs.getString(SettingsPrefs.PREF_THEME, "system") ?: "system"
        chipGroupTheme.check(
            when (theme) {
                "light" -> R.id.chipThemeLight
                "dark" -> R.id.chipThemeDark
                else -> R.id.chipThemeSystem
            },
        )

        val language = prefs.getString(SettingsPrefs.PREF_LANGUAGE, "").orEmpty()
        chipGroupLanguage.check(
            when (language) {
                "en" -> R.id.chipLangEn
                "ru" -> R.id.chipLangRu
                "fa" -> R.id.chipLangFa
                "zh-CN" -> R.id.chipLangZh
                else -> R.id.chipLangSystem
            },
        )
    }

    private fun setupListeners() {
        chipGroupTheme.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val value = when (checkedIds.first()) {
                R.id.chipThemeLight -> "light"
                R.id.chipThemeDark -> "dark"
                else -> "system"
            }
            prefs.edit { putString(SettingsPrefs.PREF_THEME, value) }
            SettingsActivity.applyTheme(value)
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
            prefs.edit { putString(SettingsPrefs.PREF_LANGUAGE, value) }
            AppUiSettings.applyLanguage(value)
        }
    }
}
