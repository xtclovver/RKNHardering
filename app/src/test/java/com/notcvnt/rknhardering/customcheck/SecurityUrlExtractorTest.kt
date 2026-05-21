package com.notcvnt.rknhardering.customcheck

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityUrlExtractorTest {

    private fun emptyProfile() = CustomCheckProfile(
        id = "test",
        name = "Test",
        checksConfig = ChecksConfig(
            geoIp = GeoIpConfig(customProviders = emptyList()),
            ipComparison = IpComparisonConfig(customEndpoints = emptyList()),
            cdnPulling = CdnPullingConfig(enabled = false, customTargets = emptyList()),
            icmpSpoofing = IcmpSpoofingConfig(enabled = false, customTargets = emptyList()),
            rttTriangulation = RttTriangulationConfig(enabled = false, customTargets = emptyList()),
            callTransport = CallTransportConfig(enabled = false, customStunServers = emptyList()),
        ),
    )

    @Test
    fun `empty profile returns no URLs`() {
        val urls = CustomCheckSerializer.extractAllUrls(emptyProfile())
        assertTrue(urls.isEmpty())
    }

    @Test
    fun `custom GeoIP provider URL is extracted`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                geoIp = GeoIpConfig(
                    customProviders = listOf(
                        CustomGeoIpProvider(name = "MyGeo", url = "https://mygeo.example.com/api", enabled = true),
                    )
                )
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertEquals(1, urls.size)
        assertEquals("https://mygeo.example.com/api", urls[0].url)
        assertEquals("MyGeo", urls[0].purpose)
        assertEquals("GeoIP", urls[0].checkName)
    }

    @Test
    fun `disabled GeoIP provider with blank URL is skipped`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                geoIp = GeoIpConfig(
                    customProviders = listOf(
                        CustomGeoIpProvider(name = "Blank", url = "", enabled = false),
                    )
                )
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.isEmpty())
    }

    @Test
    fun `custom IP comparison endpoints are extracted`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                ipComparison = IpComparisonConfig(
                    customEndpoints = listOf(
                        CustomIpEndpoint(label = "RU checker", url = "https://checker.ru/ip", scope = EndpointScope.RU),
                        CustomIpEndpoint(label = "Non-RU checker", url = "https://checker.com/ip", scope = EndpointScope.NON_RU),
                    )
                )
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertEquals(2, urls.size)
        assertEquals("https://checker.ru/ip", urls[0].url)
        assertEquals("RU checker", urls[0].purpose)
        assertEquals("IP Comparison", urls[0].checkName)
        assertEquals("https://checker.com/ip", urls[1].url)
    }

    @Test
    fun `custom CDN targets are extracted`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                cdnPulling = CdnPullingConfig(
                    enabled = true,
                    customTargets = listOf(
                        CustomCdnTarget(label = "My CDN", url = "https://cdn.example.com/trace"),
                    )
                )
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertEquals(1, urls.size)
        assertEquals("https://cdn.example.com/trace", urls[0].url)
        assertEquals("CDN Pulling", urls[0].checkName)
    }

    @Test
    fun `ICMP custom targets produce ping entries`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                icmpSpoofing = IcmpSpoofingConfig(
                    enabled = true,
                    customTargets = listOf(
                        IcmpTarget(host = "example.com", label = "Blocked", isControl = false),
                        IcmpTarget(host = "google.com", label = "Control", isControl = true),
                    )
                )
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertEquals(2, urls.size)
        assertEquals("ping example.com", urls[0].url)
        assertEquals("ICMP Spoofing", urls[0].checkName)
        assertEquals("ping google.com", urls[1].url)
    }

    @Test
    fun `RTT custom targets produce ping entries`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                rttTriangulation = RttTriangulationConfig(
                    enabled = true,
                    customTargets = listOf(
                        RttTarget(host = "ya.ru", label = "Local", expectedLocation = "home"),
                    )
                )
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertEquals(1, urls.size)
        assertEquals("ping ya.ru", urls[0].url)
        assertEquals("RTT Triangulation", urls[0].checkName)
    }

    @Test
    fun `custom STUN servers produce stun scheme entries`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                callTransport = CallTransportConfig(
                    enabled = true,
                    customStunServers = listOf(
                        StunServer(host = "stun.example.com", port = 3478, label = "My STUN"),
                    )
                )
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertEquals(1, urls.size)
        assertEquals("stun://stun.example.com:3478", urls[0].url)
        assertEquals("Call Transport", urls[0].checkName)
        assertEquals("My STUN", urls[0].purpose)
    }

    @Test
    fun `multiple categories combined`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                geoIp = GeoIpConfig(
                    customProviders = listOf(
                        CustomGeoIpProvider(name = "Geo1", url = "https://geo.example.com"),
                    )
                ),
                ipComparison = IpComparisonConfig(
                    customEndpoints = listOf(
                        CustomIpEndpoint(label = "Checker1", url = "https://ip.example.com", scope = EndpointScope.RU),
                    )
                ),
                callTransport = CallTransportConfig(
                    enabled = true,
                    customStunServers = listOf(
                        StunServer(host = "stun.example.com", port = 3478, label = "STUN1"),
                    )
                ),
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertEquals(3, urls.size)
        val checks = urls.map { it.checkName }.toSet()
        assertTrue(checks.contains("GeoIP"))
        assertTrue(checks.contains("IP Comparison"))
        assertTrue(checks.contains("Call Transport"))
    }

    @Test
    fun `blank host in ICMP target is skipped`() {
        val profile = emptyProfile().copy(
            checksConfig = ChecksConfig(
                icmpSpoofing = IcmpSpoofingConfig(
                    enabled = true,
                    customTargets = listOf(
                        IcmpTarget(host = "", label = "Empty", isControl = false),
                    )
                )
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.isEmpty())
    }
}
