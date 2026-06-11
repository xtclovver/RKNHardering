package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertEquals
import org.junit.Test

class NativeEmulatorParserTest {

    @Test
    fun parsesKindAndDetail() {
        val rows = arrayOf(
            "qemu_prop|ro.kernel.qemu=1",
            "qemu_pipe|/dev/qemu_pipe",
        )
        val result = NativeInterfaceProbe.parseEmulatorFindings(rows)
        assertEquals(2, result.size)
        assertEquals("qemu_prop", result[0].kind)
        assertEquals("ro.kernel.qemu=1", result[0].detail)
        assertEquals("qemu_pipe", result[1].kind)
        assertEquals("/dev/qemu_pipe", result[1].detail)
    }

    @Test
    fun dropsRowsWithoutSeparator() {
        val rows = arrayOf("garbage", "goldfish|ranchu")
        val result = NativeInterfaceProbe.parseEmulatorFindings(rows)
        assertEquals(1, result.size)
        assertEquals("goldfish", result[0].kind)
    }

    @Test
    fun blankDetailBecomesNull() {
        val rows = arrayOf("cpuinfo|")
        val result = NativeInterfaceProbe.parseEmulatorFindings(rows)
        assertEquals(1, result.size)
        assertEquals(null, result[0].detail)
    }
}
