package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import com.google.android.material.chip.ChipGroup
import com.google.android.material.snackbar.Snackbar

internal class SettingsAppearanceFragment : Fragment(R.layout.fragment_settings_appearance) {

    private lateinit var prefs: SharedPreferences
    private lateinit var chipGroupResultDisplayMode: ChipGroup
    private lateinit var textResultDisplayModeDescription: TextView
    private lateinit var chipGroupTheme: ChipGroup
    private lateinit var chipGroupIconStyle: ChipGroup
    private lateinit var chipGroupLanguage: ChipGroup

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        chipGroupResultDisplayMode = view.findViewById(R.id.chipGroupResultDisplayMode)
        textResultDisplayModeDescription = view.findViewById(R.id.textResultDisplayModeDescription)
        chipGroupTheme = view.findViewById(R.id.chipGroupTheme)
        chipGroupIconStyle = view.findViewById(R.id.chipGroupIconStyle)
        chipGroupLanguage = view.findViewById(R.id.chipGroupLanguage)
        loadSettings()
        setupListeners(view)
    }

    private fun loadSettings() {
        val resultDisplayMode = ResultDisplayMode.fromPrefs(prefs)
        chipGroupResultDisplayMode.check(
            when (resultDisplayMode) {
                ResultDisplayMode.SIMPLE -> R.id.chipResultDisplaySimple
                ResultDisplayMode.NORMAL -> R.id.chipResultDisplayNormal
                ResultDisplayMode.ADVANCED -> R.id.chipResultDisplayAdvanced
            },
        )
        updateResultDisplayModeDescription(resultDisplayMode)

        val theme = prefs.getString(SettingsPrefs.PREF_THEME, "system") ?: "system"
        chipGroupTheme.check(
            when (theme) {
                "light" -> R.id.chipThemeLight
                "dark" -> R.id.chipThemeDark
                else -> R.id.chipThemeSystem
            },
        )

        val iconStyle = prefs.getString(SettingsPrefs.PREF_ICON_STYLE, "new") ?: "new"
        chipGroupIconStyle.check(
            if (iconStyle == "classic") R.id.chipIconStyleClassic else R.id.chipIconStyleNew,
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

    private fun setupListeners(view: View) {
        chipGroupResultDisplayMode.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val mode = when (checkedIds.first()) {
                R.id.chipResultDisplaySimple -> ResultDisplayMode.SIMPLE
                R.id.chipResultDisplayAdvanced -> ResultDisplayMode.ADVANCED
                else -> ResultDisplayMode.NORMAL
            }
            prefs.edit { putString(SettingsPrefs.PREF_RESULT_DISPLAY_MODE, mode.prefValue) }
            updateResultDisplayModeDescription(mode)
        }

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

        chipGroupIconStyle.setOnCheckedStateChangeListener { _, checkedIds ->
            if (checkedIds.isEmpty()) return@setOnCheckedStateChangeListener
            val isClassic = checkedIds.first() == R.id.chipIconStyleClassic
            val value = if (isClassic) "classic" else "new"
            prefs.edit { putString(SettingsPrefs.PREF_ICON_STYLE, value) }
            applyIconStyle(view, isClassic)
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

    private fun updateResultDisplayModeDescription(mode: ResultDisplayMode) {
        textResultDisplayModeDescription.setText(
            when (mode) {
                ResultDisplayMode.SIMPLE -> R.string.settings_result_display_mode_simple_desc
                ResultDisplayMode.NORMAL -> R.string.settings_result_display_mode_normal_desc
                ResultDisplayMode.ADVANCED -> R.string.settings_result_display_mode_advanced_desc
            },
        )
    }

    private fun applyIconStyle(view: View, isClassic: Boolean) {
        val rawMode = prefs.getString(SettingsPrefs.PREF_COLOR_VISION_MODE, null)
        val mode = ColorVisionMode.fromPref(rawMode)
        val redGreenSub = redGreenSubVariantFromPrefs()
        val target = LauncherIconVariant.resolve(isClassic, mode, redGreenSub)
        val message = if (LauncherIconManager.apply(requireContext(), target)) {
            R.string.settings_color_vision_icon_changed_warning
        } else {
            R.string.settings_color_vision_icon_change_failed
        }
        Snackbar.make(view, message, Snackbar.LENGTH_LONG).show()
    }

    private fun redGreenSubVariantFromPrefs(): LauncherIconVariant? {
        val unlocked = prefs.getBoolean(SettingsPrefs.PREF_EASTER_EGG_PROTANOPIA_UNLOCKED, false)
        if (!unlocked) return null
        return when (prefs.getString(SettingsPrefs.PREF_RED_GREEN_ICON_VARIANT, LauncherIconVariant.DEUTERANOPIA.prefValue)) {
            LauncherIconVariant.PROTANOPIA.prefValue -> LauncherIconVariant.PROTANOPIA
            else -> LauncherIconVariant.DEUTERANOPIA
        }
    }
}
