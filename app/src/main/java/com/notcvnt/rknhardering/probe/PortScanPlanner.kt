package com.notcvnt.rknhardering.probe

data class PortScanPlan(
    val mode: ScanMode,
    val scanRange: IntRange,
    val popularPorts: List<Int>,
)

object PortScanPlanner {
    const val MIN_PORT = 1024
    const val MAX_PORT = 65535

    private val EXTENDED_RANGE = MIN_PORT..15000
    private val FULL_RANGE = MIN_PORT..MAX_PORT

    fun normalizeCustomRange(start: Int, end: Int): IntRange {
        val boundedStart = start.coerceIn(MIN_PORT, MAX_PORT)
        val boundedEnd = end.coerceIn(MIN_PORT, MAX_PORT)
        return minOf(boundedStart, boundedEnd)..maxOf(boundedStart, boundedEnd)
    }

    fun buildExecutionPlan(
        portRange: String,
        portRangeStart: Int,
        portRangeEnd: Int,
        popularPorts: List<Int> = ProxyScanner.DEFAULT_POPULAR_PORTS,
    ): PortScanPlan {
        return when (portRange) {
            "popular" -> PortScanPlan(
                mode = ScanMode.POPULAR_ONLY,
                scanRange = FULL_RANGE,
                popularPorts = popularPorts,
            )
            "extended" -> PortScanPlan(
                mode = ScanMode.AUTO,
                scanRange = EXTENDED_RANGE,
                popularPorts = popularPorts,
            )
            "custom" -> {
                val customRange = normalizeCustomRange(portRangeStart, portRangeEnd)
                PortScanPlan(
                    mode = ScanMode.AUTO,
                    scanRange = customRange,
                    popularPorts = popularPorts.filter { it in customRange },
                )
            }
            else -> PortScanPlan(
                mode = ScanMode.AUTO,
                scanRange = FULL_RANGE,
                popularPorts = popularPorts,
            )
        }
    }

    fun buildPreviewRanges(
        portRange: String,
        portRangeStart: Int,
        portRangeEnd: Int,
        popularPorts: List<Int> = ProxyScanner.DEFAULT_POPULAR_PORTS,
    ): List<IntRange> {
        val ranges = when (portRange) {
            "popular" -> popularPorts.map { it..it }
            "extended" -> popularPorts.map { it..it } + listOf(EXTENDED_RANGE)
            "custom" -> listOf(normalizeCustomRange(portRangeStart, portRangeEnd))
            else -> popularPorts.map { it..it } + listOf(FULL_RANGE)
        }
        return mergeRanges(ranges)
    }

    internal fun mergeRanges(ranges: List<IntRange>): List<IntRange> {
        if (ranges.isEmpty()) return emptyList()

        val sortedRanges = ranges.sortedBy { it.first }
        val mergedRanges = mutableListOf<IntRange>()
        var currentStart = sortedRanges.first().first
        var currentEnd = sortedRanges.first().last

        for (range in sortedRanges.drop(1)) {
            if (range.first <= currentEnd + 1) {
                currentEnd = maxOf(currentEnd, range.last)
            } else {
                mergedRanges += currentStart..currentEnd
                currentStart = range.first
                currentEnd = range.last
            }
        }

        mergedRanges += currentStart..currentEnd
        return mergedRanges
    }
}
