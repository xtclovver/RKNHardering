package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.network.DnsResolverConfig
import java.io.IOException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class IpComparisonCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `all checkers returning same ip produces clean result`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "1.2.3.4"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "1.2.3.4"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals(context.getString(R.string.checker_ip_comp_status_has_response), result.ruGroup.statusLabel)
        assertEquals(context.getString(R.string.checker_ip_comp_status_match), result.nonRuGroup.statusLabel)
    }

    @Test
    fun `ru and non-ru mismatch with full data is detected`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "10.0.0.1"),
                response("ipify", IpCheckerScope.NON_RU, ip = "20.0.0.1"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "20.0.0.1"),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.summary.contains("10.0.0.1"))
        assertTrue(result.summary.contains("20.0.0.1"))
    }

    @Test
    fun `non-ru mismatch inside group requires attention`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "5.6.7.8"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "9.9.9.9"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.nonRuGroup.detected)
        assertEquals(context.getString(R.string.checker_ip_comp_status_mismatch), result.nonRuGroup.statusLabel)
    }

    @Test
    fun `errors in non-ru group do not block mismatch detection`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "5.6.7.8"),
                response("ip.sb", IpCheckerScope.NON_RU, error = "timeout"),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertEquals(context.getString(R.string.checker_ip_comp_status_match), result.nonRuGroup.statusLabel)
    }

    @Test
    fun `mixed ipv4 and ipv6 responses require review instead of detection`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("ipify", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "2a01:4f9:c013:d2ba::1"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertEquals(context.getString(R.string.checker_ip_comp_status_ipv4_ipv6), result.nonRuGroup.statusLabel)
    }

    @Test
    fun `ignored ipv6 error does not make ru group partial`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex IPv4", IpCheckerScope.RU, ip = "37.113.42.220"),
                response(
                    "Yandex IPv6",
                    IpCheckerScope.RU,
                    error = "connect failed",
                    ignoredIpv6Error = true,
                    ipv6Records = listOf("2a02:6b8::"),
                ),
                response("ifconfig.me", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("checkip.amazonaws.com", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals(context.getString(R.string.checker_ip_comp_status_match), result.ruGroup.statusLabel)
        assertEquals(1, result.ruGroup.ignoredIpv6ErrorCount)
    }

    @Test
    fun `ignored ipv6 error does not make non ru group partial`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex IPv4", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("2ip.ru", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("ifconfig.me IPv4", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response(
                    "ifconfig.me IPv6",
                    IpCheckerScope.NON_RU,
                    error = "connect failed",
                    ignoredIpv6Error = true,
                    ipv6Records = listOf("2600:1901:0:b2bd::"),
                ),
                response("ipify", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("ip.sb IPv4", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals(context.getString(R.string.checker_ip_comp_status_match), result.nonRuGroup.statusLabel)
        assertEquals(1, result.nonRuGroup.ignoredIpv6ErrorCount)
    }

    @Test
    fun `same ip with ordinary errors stays clean`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex IPv4", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("2ip.ru", IpCheckerScope.RU, error = "HTTP 403 // Forbidden"),
                response("ifconfig.me IPv4", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("ipify", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("ip.sb IPv4", IpCheckerScope.NON_RU, error = "timeout"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals(context.getString(R.string.checker_ip_comp_status_match), result.ruGroup.statusLabel)
        assertEquals(context.getString(R.string.checker_ip_comp_status_match), result.nonRuGroup.statusLabel)
    }

    @Test
    fun `all ordinary errors without ip become no response`() {
        val result = IpComparisonChecker.evaluate(
            context,
            listOf(
                response("Yandex IPv4", IpCheckerScope.RU, error = "timeout"),
                response("2ip.ru", IpCheckerScope.RU, error = "HTTP 403 // Forbidden"),
                response("ifconfig.me IPv4", IpCheckerScope.NON_RU, error = "timeout"),
                response("ipify", IpCheckerScope.NON_RU, error = "timeout"),
            ),
        )

        assertTrue(result.needsReview)
        assertEquals(context.getString(R.string.checker_ip_comp_status_no_response), result.ruGroup.statusLabel)
        assertEquals(context.getString(R.string.checker_ip_comp_status_no_response), result.nonRuGroup.statusLabel)
    }

    @Test
    fun `fetch retries up to third attempt before succeeding`() = runBlocking {
        var attempts = 0

        val result = IpComparisonChecker.fetchIpWithRetries(
            endpoint = "https://example.com/ip",
            timeoutMs = 1_000,
            resolverConfig = DnsResolverConfig.system(),
            retryDelayMs = 0,
        ) { _, _, _ ->
            attempts += 1
            if (attempts < 3) {
                Result.failure(IOException("timeout"))
            } else {
                Result.success("1.2.3.4")
            }
        }

        assertTrue(result.isSuccess)
        assertEquals(3, attempts)
        assertEquals("1.2.3.4", result.getOrNull())
    }

    private fun response(
        label: String,
        scope: IpCheckerScope,
        ip: String? = null,
        error: String? = null,
        ipv4Records: List<String> = emptyList(),
        ipv6Records: List<String> = emptyList(),
        ignoredIpv6Error: Boolean = false,
    ): IpCheckerResponse = IpCheckerResponse(
        label = label,
        url = "https://example.com/$label",
        scope = scope,
        ip = ip,
        error = error,
        ipv4Records = ipv4Records,
        ipv6Records = ipv6Records,
        ignoredIpv6Error = ignoredIpv6Error,
    )
}
