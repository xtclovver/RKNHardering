package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.customcheck.CdnPullingConfig
import com.notcvnt.rknhardering.customcheck.CustomCdnTarget
import com.notcvnt.rknhardering.customcheck.ResponseMapping
import com.notcvnt.rknhardering.customcheck.ResponseType
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.network.DnsResolverConfig
import java.io.IOException
import java.security.cert.CertPathValidatorException
import javax.net.ssl.SSLHandshakeException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CdnPullingCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `evaluate marks result detected when actionable target exposes data`() {
        val result = CdnPullingChecker.evaluate(
            context = context,
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "meduza.io",
                    url = "https://meduza.io/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    importantFields = linkedMapOf("IP" to "203.0.113.64", "LOC" to "FI"),
                    rawBody = "ip=203.0.113.64\nloc=FI",
                ),
                CdnPullingResponse(
                    targetLabel = "redirector.googlevideo.com",
                    url = "https://redirector.googlevideo.com/report_mapping?di=no",
                    error = "timeout",
                ),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertFalse(result.hasError)
    }

    @Test
    fun `evaluate treats cloudflare trace as diagnostic only`() {
        val result = CdnPullingChecker.evaluate(
            context = context,
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "redirector.googlevideo.com",
                    url = "https://redirector.googlevideo.com/report_mapping?di=no",
                    error = "timeout",
                ),
                CdnPullingResponse(
                    targetLabel = "cloudflare.com",
                    url = "https://www.cloudflare.com/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    importantFields = linkedMapOf("IP" to "203.0.113.64", "LOC" to "RU"),
                ),
                CdnPullingResponse(
                    targetLabel = "one.one.one.one",
                    url = "https://one.one.one.one/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    importantFields = linkedMapOf("IP" to "203.0.113.64", "LOC" to "RU"),
                ),
                CdnPullingResponse(
                    targetLabel = "meduza.io",
                    url = "https://meduza.io/cdn-cgi/trace",
                    error = "timeout",
                ),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertFalse(result.hasError)
        assertEquals(
            context.getString(R.string.checker_cdn_pulling_summary_detected_partial, "203.0.113.64", 2, 4),
            result.summary,
        )
    }

    @Test
    fun `evaluate marks result as error when no usable data is returned`() {
        val result = CdnPullingChecker.evaluate(
            context = context,
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "redirector.googlevideo.com",
                    url = "https://redirector.googlevideo.com/report_mapping?di=no",
                    rawBody = "unknown body",
                    error = "unrecognized",
                ),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.hasError)
        assertFalse(result.needsReview)
    }

    @Test
    fun `evaluate uses no-ip summary when trace data is partial`() {
        val result = CdnPullingChecker.evaluate(
            context = context,
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "meduza.io",
                    url = "https://meduza.io/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    importantFields = linkedMapOf("IP" to "203.0.113.64", "LOC" to "FI"),
                ),
                CdnPullingResponse(
                    targetLabel = "redirector.googlevideo.com",
                    url = "https://redirector.googlevideo.com/report_mapping?di=no",
                    importantFields = linkedMapOf("LOC" to "NL", "COLO" to "AMS"),
                ),
            ),
        )

        assertTrue(result.detected)
        // No IP conflict — partial trace data alone is informational.
        assertFalse(result.needsReview)
        assertEquals(
            context.getString(R.string.checker_cdn_pulling_summary_detected_no_ip, 2, 2),
            result.summary,
        )
        assertTrue(result.findings.any { it.description == "meduza.io: IP: 203.0.113.64, LOC: FI" })
    }

    @Test
    fun `evaluate raises review when actionable IPs disagree`() {
        val result = CdnPullingChecker.evaluate(
            context = context,
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "meduza.io",
                    url = "https://meduza.io/cdn-cgi/trace",
                    ip = "203.0.113.64",
                    ipv4 = "203.0.113.64",
                    importantFields = linkedMapOf("IP" to "203.0.113.64"),
                ),
                CdnPullingResponse(
                    targetLabel = "redirector.googlevideo.com",
                    url = "https://redirector.googlevideo.com/report_mapping?di=no",
                    ip = "198.51.100.42",
                    ipv4 = "198.51.100.42",
                    importantFields = linkedMapOf("IP" to "198.51.100.42"),
                ),
            ),
        )

        assertTrue(result.detected)
        assertTrue(result.needsReview)
    }

    @Test
    fun `fetchBodyWithRetries retries transient failures and returns success`() = runBlocking {
        var attempts = 0

        val result = CdnPullingChecker.fetchBodyWithRetries(
            endpoint = "https://meduza.io/cdn-cgi/trace",
            timeoutMs = 1000,
            resolverConfig = DnsResolverConfig.system(),
            maxAttempts = 3,
            retryDelayMs = 0,
        ) { _, _, _, _ ->
            attempts += 1
            if (attempts < 3) {
                Result.failure(IOException("timeout"))
            } else {
                Result.success("ip=203.0.113.64")
            }
        }

        assertTrue(result.isSuccess)
        assertEquals("ip=203.0.113.64", result.getOrNull())
        assertEquals(3, attempts)
    }

    @Test
    fun `fetchBodyWithRetries does not retry untrusted tls certificate failures`() = runBlocking {
        var attempts = 0
        val error = SSLHandshakeException("Handshake failed").apply {
            initCause(CertPathValidatorException("Trust anchor for certification path not found"))
        }

        val result = CdnPullingChecker.fetchBodyWithRetries(
            endpoint = "https://rutracker.org/cdn-cgi/trace",
            timeoutMs = 1000,
            resolverConfig = DnsResolverConfig.system(),
            maxAttempts = 3,
            retryDelayMs = 0,
        ) { _, _, _, _ ->
            attempts += 1
            Result.failure(error)
        }

        assertTrue(result.isFailure)
        assertEquals(1, attempts)
    }

    @Test
    fun `formatError explains tls trust failures`() {
        val error = SSLHandshakeException("Handshake failed").apply {
            initCause(CertPathValidatorException("Trust anchor for certification path not found"))
        }

        val message = CdnPullingChecker.formatError(context, error)

        assertTrue(message.contains(context.getString(R.string.checker_cdn_pulling_error_tls_certificate)))
        assertTrue(message.contains("Trust anchor for certification path not found"))
    }

    @After
    fun tearDown() {
        CdnPullingChecker.dependenciesOverride = null
    }

    @Test
    fun `when builtinTargetsEnabled=false then only custom targets are fetched`() = runBlocking {
        val fetchedLabels = mutableListOf<String>()
        CdnPullingChecker.dependenciesOverride = CdnPullingChecker.Dependencies(
            fetchEndpoint = { _, endpoint, _, _ ->
                fetchedLabels.add(endpoint.label)
                CdnPullingResponse(
                    targetLabel = endpoint.label,
                    url = endpoint.url,
                    error = "stub",
                )
            },
        )

        val customTarget = CustomCdnTarget(
            label = "custom.example.com",
            url = "https://custom.example.com/trace",
            enabled = true,
            responseMapping = ResponseMapping(responseType = ResponseType.KEY_VALUE),
        )
        CdnPullingChecker.check(
            context = context,
            config = CdnPullingConfig(
                enabled = true,
                builtinTargetsEnabled = false,
                customTargets = listOf(customTarget),
            ),
        )

        // The dependenciesOverride only intercepts builtin endpoint fetches.
        // With builtinTargetsEnabled=false, the override should never be called.
        assertTrue("No builtin endpoints should be fetched when toggle is off", fetchedLabels.isEmpty())
    }

    @Test
    fun `when meduzaEnabled=false the meduza domain is skipped`() = runBlocking {
        val fetchedLabels = mutableListOf<String>()
        CdnPullingChecker.dependenciesOverride = CdnPullingChecker.Dependencies(
            fetchEndpoint = { _, endpoint, _, _ ->
                fetchedLabels.add(endpoint.label)
                CdnPullingResponse(
                    targetLabel = endpoint.label,
                    url = endpoint.url,
                    error = "stub",
                )
            },
        )

        CdnPullingChecker.check(
            context = context,
            config = CdnPullingConfig(
                enabled = true,
                builtinTargetsEnabled = true,
                meduzaEnabled = false,
            ),
        )

        assertFalse("meduza.io must not be fetched when meduzaEnabled=false", fetchedLabels.contains("meduza.io"))
        assertTrue("other builtin targets should still be fetched", fetchedLabels.isNotEmpty())
    }
}
