package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class PortScanPlannerTest {

    @Test
    fun `custom preview keeps only selected range`() {
        val previewRanges = PortScanPlanner.buildPreviewRanges(
            portRange = "custom",
            portRangeStart = 50010,
            portRangeEnd = 50000,
        )

        assertEquals(listOf(50000..50010), previewRanges)
    }

    @Test
    fun `execution plan normalizes reversed custom bounds and filters popular ports`() {
        val plan = PortScanPlanner.buildExecutionPlan(
            portRange = "custom",
            portRangeStart = 1100,
            portRangeEnd = 1024,
            popularPorts = listOf(1080, 7890),
        )

        assertEquals(ScanMode.AUTO, plan.mode)
        assertEquals(1024..1100, plan.scanRange)
        assertEquals(listOf(1080), plan.popularPorts)
    }

    @Test
    fun `execution plan keeps custom range strict when it does not intersect popular ports`() {
        val plan = PortScanPlanner.buildExecutionPlan(
            portRange = "custom",
            portRangeStart = 50000,
            portRangeEnd = 50010,
            popularPorts = listOf(1080, 7890),
        )

        assertEquals(50000..50010, plan.scanRange)
        assertFalse(plan.popularPorts.contains(1080))
        assertFalse(plan.popularPorts.contains(7890))
    }
}
