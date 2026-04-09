package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.EvidenceSource
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class GeoIpCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `foreign residential ip requires review but is not detected`() {
        val result = GeoIpChecker.evaluate(
            context,
            GeoIpChecker.GeoIpSnapshot(
                ip = "11.22.33.44",
                country = "China",
                countryCode = "CN",
                isp = "China Mobile",
                org = "China Mobile",
                asn = "AS4134",
                isProxy = false,
                isHosting = false,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.evidence.isEmpty())
        assertTrue(result.findings.any { it.source == EvidenceSource.GEO_IP && it.needsReview })
    }

    @Test
    fun `evaluate produces exactly 5 informational findings`() {
        val result = GeoIpChecker.evaluate(
            context,
            GeoIpChecker.GeoIpSnapshot(
                ip = "1.2.3.4",
                country = "Russia",
                countryCode = "RU",
                isp = "Test ISP",
                org = "Test Org",
                asn = "AS999",
                isProxy = false,
                isHosting = false,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )

        val infoFindings = result.findings.filter { it.isInformational }
        val infoDescriptions = infoFindings.map { it.description }
        assertEquals(5, infoFindings.size)
        assertTrue(infoDescriptions.contains(context.getString(R.string.checker_geo_info_ip, "1.2.3.4")))
        assertTrue(infoDescriptions.contains(context.getString(R.string.checker_geo_info_country, "Russia", "RU")))
        assertTrue(infoDescriptions.contains(context.getString(R.string.checker_geo_info_isp, "Test ISP")))
        assertTrue(infoDescriptions.contains(context.getString(R.string.checker_geo_info_org, "Test Org")))
        assertTrue(infoDescriptions.contains(context.getString(R.string.checker_geo_info_asn, "AS999")))
    }

    @Test
    fun `evaluate info findings have detected=false and needsReview=false`() {
        val result = GeoIpChecker.evaluate(
            context,
            GeoIpChecker.GeoIpSnapshot(
                ip = "1.2.3.4",
                country = "Russia",
                countryCode = "RU",
                isp = "ISP",
                org = "Org",
                asn = "AS1",
                isProxy = false,
                isHosting = false,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )

        result.findings.filter { it.isInformational }.forEach { finding ->
            assertFalse("Info finding should not be detected: ${finding.description}", finding.detected)
            assertFalse("Info finding should not need review: ${finding.description}", finding.needsReview)
        }
    }

    @Test
    fun `hosting or proxy still count as detected geo risk`() {
        val result = GeoIpChecker.evaluate(
            context,
            GeoIpChecker.GeoIpSnapshot(
                ip = "22.33.44.55",
                country = "Russia",
                countryCode = "RU",
                isp = "Example ISP",
                org = "Example Org",
                asn = "AS12345",
                isProxy = true,
                isHosting = true,
                hostingVotes = 2,
                hostingChecks = 2,
                hostingSources = listOf("ipapi.is", "iplocate.io"),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertEquals(2, result.evidence.count { it.source == EvidenceSource.GEO_IP })
    }

    @Test
    fun `mergeSnapshots falls back to ipapi is when primary provider is unavailable`() {
        val fallback = GeoIpChecker.ProviderSnapshot(
            provider = "ipapi.is",
            snapshot = GeoIpChecker.GeoIpSnapshot(
                ip = "157.180.123.101",
                country = "Finland",
                countryCode = "FI",
                isp = "Hetzner Online GmbH",
                org = "Hetzner Online GmbH",
                asn = "AS24940 Hetzner Online GmbH",
                isProxy = false,
                isHosting = true,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )
        val secondFallback = GeoIpChecker.ProviderSnapshot(
            provider = "iplocate.io",
            snapshot = GeoIpChecker.GeoIpSnapshot(
                ip = "157.180.123.101",
                country = "Finland",
                countryCode = "FI",
                isp = "Hetzner Online GmbH",
                org = "Hetzner Online",
                asn = "AS24940 Hetzner Online GmbH",
                isProxy = false,
                isHosting = true,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )

        val merged = GeoIpChecker.mergeSnapshots(
            baseProvider = fallback,
            providers = listOf(fallback, secondFallback),
        )

        assertEquals("157.180.123.101", merged.ip)
        assertEquals("Finland", merged.country)
        assertEquals("FI", merged.countryCode)
        assertEquals("Hetzner Online GmbH", merged.isp)
        assertEquals("Hetzner Online GmbH", merged.org)
        assertEquals("AS24940 Hetzner Online GmbH", merged.asn)
        assertTrue(merged.isHosting)
        assertEquals(2, merged.hostingVotes)
        assertEquals(2, merged.hostingChecks)
        assertEquals(listOf("ipapi.is", "iplocate.io"), merged.hostingSources)
    }

    @Test
    fun `mergeSnapshots fills missing fields from compatible fallback`() {
        val baseProvider = GeoIpChecker.ProviderSnapshot(
            provider = "ipapi.is",
            snapshot = GeoIpChecker.GeoIpSnapshot(
                ip = "157.180.123.101",
                country = "Finland",
                countryCode = "FI",
                isp = "Hetzner Online GmbH",
                org = "N/A",
                asn = "AS24940",
                isProxy = false,
                isHosting = true,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )
        val fallback = GeoIpChecker.ProviderSnapshot(
            provider = "iplocate.io",
            snapshot = GeoIpChecker.GeoIpSnapshot(
                ip = "157.180.123.101",
                country = "Finland",
                countryCode = "FI",
                isp = "Hetzner Online GmbH",
                org = "Hetzner Online",
                asn = "AS24940 Hetzner Online GmbH",
                isProxy = true,
                isHosting = true,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )

        val merged = GeoIpChecker.mergeSnapshots(
            baseProvider = baseProvider,
            providers = listOf(baseProvider, fallback),
        )

        assertEquals("Hetzner Online", merged.org)
        assertEquals("AS24940", merged.asn)
        assertTrue(merged.isProxy)
    }

    @Test
    fun `mergeSnapshots ignores hosting votes from different ip versions`() {
        val baseProvider = GeoIpChecker.ProviderSnapshot(
            provider = "ipapi.is",
            snapshot = GeoIpChecker.GeoIpSnapshot(
                ip = "157.180.123.101",
                country = "Finland",
                countryCode = "FI",
                isp = "Hetzner Online GmbH",
                org = "Hetzner Online GmbH",
                asn = "AS24940 Hetzner Online GmbH",
                isProxy = false,
                isHosting = false,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )
        val ipv6Fallback = GeoIpChecker.ProviderSnapshot(
            provider = "iplocate.io",
            snapshot = GeoIpChecker.GeoIpSnapshot(
                ip = "2a01:4f9:c013:d2ba::1",
                country = "Finland",
                countryCode = "FI",
                isp = "Hetzner Online GmbH",
                org = "Hetzner Online",
                asn = "AS24940 Hetzner Online GmbH",
                isProxy = false,
                isHosting = true,
                hostingVotes = 0,
                hostingChecks = 0,
                hostingSources = emptyList(),
            ),
        )

        val merged = GeoIpChecker.mergeSnapshots(
            baseProvider = baseProvider,
            providers = listOf(baseProvider, ipv6Fallback),
        )

        assertFalse(merged.isHosting)
        assertEquals(0, merged.hostingVotes)
        assertEquals(1, merged.hostingChecks)
        assertTrue(merged.hostingSources.isEmpty())
    }

    @Test
    fun `evaluate uses available hosting checks in description`() {
        val result = GeoIpChecker.evaluate(
            context,
            GeoIpChecker.GeoIpSnapshot(
                ip = "157.180.123.101",
                country = "Finland",
                countryCode = "FI",
                isp = "Hetzner Online GmbH",
                org = "Hetzner Online GmbH",
                asn = "AS24940 Hetzner Online GmbH",
                isProxy = false,
                isHosting = true,
                hostingVotes = 2,
                hostingChecks = 2,
                hostingSources = listOf("ipapi.is", "iplocate.io"),
            ),
        )

        assertTrue(
            result.findings.any {
                it.description == context.getString(R.string.checker_geo_hosting_prefix, context.getString(R.string.checker_yes)) +
                    " (2/2: ipapi.is, iplocate.io)"
            },
        )
    }

    @Test
    fun `no provider result is review and not error`() {
        val result = GeoIpChecker.noProviderResult(
            context.getString(R.string.checker_geo_error_no_provider),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertFalse(result.hasError)
        assertTrue(result.findings.all { it.needsReview && !it.isError })
    }

    @Test
    fun `geoip fetch retries up to third attempt before succeeding`() = runBlocking {
        var attempts = 0

        val result = GeoIpChecker.fetchWithRetries(retryDelayMs = 0) {
            attempts += 1
            if (attempts < 3) null else "ok"
        }

        assertEquals("ok", result)
        assertEquals(3, attempts)
    }
}
