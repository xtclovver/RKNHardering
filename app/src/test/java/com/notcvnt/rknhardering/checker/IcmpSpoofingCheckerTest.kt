package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.SystemPingProber
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException
import kotlin.system.measureTimeMillis

@RunWith(RobolectricTestRunner::class)
class IcmpSpoofingCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        IcmpSpoofingChecker.dependenciesOverride = null
    }

    @Test
    fun `blocked target without reply stays clean`() = runBlocking {
        IcmpSpoofingChecker.dependenciesOverride = dependencies(
            blocked = pingResult(received = 0),
            control = pingResult(received = 3, min = 15.0, avg = 18.0, max = 20.0),
        )

        val result = IcmpSpoofingChecker.check(context, DnsResolverConfig.system())

        assertFalse(result.needsReview)
        assertFalse(result.hasError)
    }

    @Test
    fun `blocked target reply yields needs review`() = runBlocking {
        IcmpSpoofingChecker.dependenciesOverride = dependencies(
            blocked = pingResult(received = 2),
            control = pingResult(received = 3, min = 15.0, avg = 18.0, max = 20.0),
        )

        val result = IcmpSpoofingChecker.check(context, DnsResolverConfig.system())

        assertTrue(result.needsReview)
        assertTrue(result.evidence.any { it.source == EvidenceSource.ICMP_SPOOFING && it.detected })
    }

    @Test
    fun `too fast control target yields needs review`() = runBlocking {
        IcmpSpoofingChecker.dependenciesOverride = dependencies(
            blocked = pingResult(received = 0),
            control = pingResult(received = 3, min = 1.0, avg = 5.0, max = 7.0),
        )

        val result = IcmpSpoofingChecker.check(context, DnsResolverConfig.system())

        assertTrue(result.needsReview)
        assertFalse(result.hasError)
    }

    @Test
    fun `unavailable ping yields error without review`() = runBlocking {
        IcmpSpoofingChecker.dependenciesOverride = IcmpSpoofingChecker.Dependencies(
            resolveIpv4 = { _, _ -> "203.0.113.10" },
            ping = { _, _, _ -> throw IOException("ping unavailable") },
        )

        val result = IcmpSpoofingChecker.check(context, DnsResolverConfig.system())

        assertFalse(result.needsReview)
        assertTrue(result.hasError)
    }

    @Test
    fun `icmp targets are probed in parallel`() {
        IcmpSpoofingChecker.dependenciesOverride = IcmpSpoofingChecker.Dependencies(
            resolveIpv4 = { host, _ ->
                when (host) {
                    "instagram.com" -> "157.240.22.174"
                    "google.com" -> "8.8.8.8"
                    else -> error("Unexpected host $host")
                }
            },
            ping = { address, _, _ ->
                delay(300)
                when (address) {
                    "157.240.22.174" -> pingResult(received = 0)
                    "8.8.8.8" -> pingResult(received = 3, min = 15.0, avg = 18.0, max = 20.0)
                    else -> error("Unexpected address $address")
                }
            },
        )

        val elapsedMs = measureTimeMillis {
            val result = runBlocking {
                IcmpSpoofingChecker.check(context, DnsResolverConfig.system())
            }

            assertFalse(result.hasError)
        }

        assertTrue("Expected ICMP targets to overlap, but took ${elapsedMs}ms", elapsedMs < 500)
    }

    private fun dependencies(
        blocked: SystemPingProber.PingResult,
        control: SystemPingProber.PingResult,
    ): IcmpSpoofingChecker.Dependencies {
        return IcmpSpoofingChecker.Dependencies(
            resolveIpv4 = { host, _ ->
                when (host) {
                    "instagram.com" -> "157.240.22.174"
                    "google.com" -> "8.8.8.8"
                    else -> error("Unexpected host $host")
                }
            },
            ping = { address, _, _ ->
                when (address) {
                    "157.240.22.174" -> blocked
                    "8.8.8.8" -> control
                    else -> error("Unexpected address $address")
                }
            },
        )
    }

    private fun pingResult(
        received: Int,
        min: Double? = null,
        avg: Double? = null,
        max: Double? = null,
    ): SystemPingProber.PingResult {
        return SystemPingProber.PingResult(
            address = "0.0.0.0",
            sent = 3,
            received = received,
            minRttMs = min,
            avgRttMs = avg,
            maxRttMs = max,
            exitCode = if (received > 0) 0 else 1,
            rawOutput = "",
        )
    }
}
