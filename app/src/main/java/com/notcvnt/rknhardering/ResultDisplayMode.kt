package com.notcvnt.rknhardering

import android.content.SharedPreferences

enum class ResultDisplayMode(val prefValue: String) {
    SIMPLE("simple"),
    NORMAL("normal"),
    ADVANCED("advanced"),
    ;

    companion object {
        fun fromPref(value: String?): ResultDisplayMode =
            entries.firstOrNull { it.prefValue == value } ?: NORMAL

        fun fromPrefs(prefs: SharedPreferences): ResultDisplayMode =
            fromPref(prefs.getString(SettingsPrefs.PREF_RESULT_DISPLAY_MODE, null))
    }
}
