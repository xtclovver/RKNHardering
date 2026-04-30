package com.notcvnt.rknhardering

import org.junit.Assert.assertEquals
import org.junit.Test

class ColorVisionModeTest {

    @Test
    fun `parses all stable preference values`() {
        ColorVisionMode.entries.forEach { mode ->
            assertEquals(mode, ColorVisionMode.fromPref(mode.prefValue))
        }
    }

    @Test
    fun `falls back to off for unknown preference value`() {
        assertEquals(ColorVisionMode.OFF, ColorVisionMode.fromPref("unknown"))
        assertEquals(ColorVisionMode.OFF, ColorVisionMode.fromPref(null))
    }

    @Test
    fun `maps legacy detailed red green values to combined mode`() {
        assertEquals(ColorVisionMode.RED_GREEN, ColorVisionMode.fromPref("protanomaly"))
        assertEquals(ColorVisionMode.RED_GREEN, ColorVisionMode.fromPref("protanopia"))
        assertEquals(ColorVisionMode.RED_GREEN, ColorVisionMode.fromPref("deuteranomaly"))
        assertEquals(ColorVisionMode.RED_GREEN, ColorVisionMode.fromPref("deuteranopia"))
    }

    @Test
    fun `maps legacy detailed blue yellow values to combined mode`() {
        assertEquals(ColorVisionMode.BLUE_YELLOW, ColorVisionMode.fromPref("tritanomaly"))
        assertEquals(ColorVisionMode.BLUE_YELLOW, ColorVisionMode.fromPref("tritanopia"))
    }
}
