package com.notcvnt.rknhardering

import org.junit.Assert.assertEquals
import org.junit.Test

class ResultDisplayModeTest {

    @Test
    fun `missing and unknown preference fall back to normal`() {
        assertEquals(ResultDisplayMode.NORMAL, ResultDisplayMode.fromPref(null))
        assertEquals(ResultDisplayMode.NORMAL, ResultDisplayMode.fromPref(""))
        assertEquals(ResultDisplayMode.NORMAL, ResultDisplayMode.fromPref("unexpected"))
    }

    @Test
    fun `all preference values round trip`() {
        ResultDisplayMode.entries.forEach { mode ->
            assertEquals(mode, ResultDisplayMode.fromPref(mode.prefValue))
        }
    }
}
