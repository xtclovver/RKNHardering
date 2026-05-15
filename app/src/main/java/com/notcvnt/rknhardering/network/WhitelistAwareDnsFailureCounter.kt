package com.notcvnt.rknhardering.network

import java.util.concurrent.atomic.AtomicInteger

object WhitelistAwareDnsFailureCounter {
    private const val THRESHOLD = 3

    private val count = AtomicInteger(0)

    @Volatile
    var dnsExhausted: Boolean = false
        private set

    fun reset() {
        count.set(0)
        dnsExhausted = false
    }

    fun recordFailure() {
        val current = count.incrementAndGet()
        if (current >= THRESHOLD) {
            dnsExhausted = true
        }
    }
}
