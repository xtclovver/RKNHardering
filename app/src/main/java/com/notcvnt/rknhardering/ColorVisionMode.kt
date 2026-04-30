package com.notcvnt.rknhardering

import androidx.annotation.StringRes

internal enum class ColorVisionMode(
    val prefValue: String,
    @param:StringRes val titleRes: Int,
) {
    OFF("off", R.string.settings_color_vision_off),
    RED_GREEN("red_green", R.string.settings_color_vision_red_green),
    BLUE_YELLOW("blue_yellow", R.string.settings_color_vision_blue_yellow),
    ACHROMATOPSIA("achromatopsia", R.string.settings_color_vision_achromatopsia);

    companion object {
        fun fromPref(value: String?): ColorVisionMode {
            return when (value) {
                "protanomaly",
                "protanopia",
                "deuteranomaly",
                "deuteranopia" -> RED_GREEN
                "tritanomaly",
                "tritanopia" -> BLUE_YELLOW
                else -> entries.firstOrNull { it.prefValue == value } ?: OFF
            }
        }
    }
}
