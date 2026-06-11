package com.notcvnt.rknhardering.customcheck

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CustomCheckSerializerTest {

    private fun defaultProfile(name: String = "Test Profile"): CustomCheckProfile =
        CustomCheckProfile(
            id = "test-id-123",
            name = name,
            description = "desc",
            author = "tester",
            version = "1.0.0",
            createdAt = 1000L,
            updatedAt = 2000L,
        )

    // ── roundtrip ─────────────────────────────────────────────────────────────

    @Test
    fun `roundtrip preserves all scalar fields`() {
        val profile = defaultProfile()
        val json = CustomCheckSerializer.serialize(profile)
        val restored = CustomCheckSerializer.deserialize(json)

        assertEquals(profile.id, restored.id)
        assertEquals(profile.name, restored.name)
        assertEquals(profile.description, restored.description)
        assertEquals(profile.author, restored.author)
        assertEquals(profile.version, restored.version)
        assertEquals(profile.createdAt, restored.createdAt)
        assertEquals(profile.updatedAt, restored.updatedAt)
    }

    @Test
    fun `roundtrip preserves split tunnel config`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                splitTunnel = SplitTunnelConfig(
                    enabled = false,
                    proxyScan = false,
                    xrayApiScan = false,
                    portRange = "custom",
                    portRangeStart = 8000,
                    portRangeEnd = 9000,
                    connectTimeoutMs = 500,
                )
            )
        )
        val restored = CustomCheckSerializer.deserialize(CustomCheckSerializer.serialize(profile))
        val st = restored.checksConfig.splitTunnel

        assertEquals(false, st.enabled)
        assertEquals(false, st.proxyScan)
        assertEquals(false, st.xrayApiScan)
        assertEquals("custom", st.portRange)
        assertEquals(8000, st.portRangeStart)
        assertEquals(9000, st.portRangeEnd)
        assertEquals(500, st.connectTimeoutMs)
    }

    @Test
    fun `roundtrip preserves custom geoip providers`() {
        val mapping = ResponseMapping(
            responseType = ResponseType.JSON,
            ipPath = "$.ip",
            countryCodePath = "$.country",
        )
        val provider = CustomGeoIpProvider(name = "MyAPI", url = "https://example.com/geoip", enabled = true, responseMapping = mapping)
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(geoIp = GeoIpConfig(customProviders = listOf(provider)))
        )
        val restored = CustomCheckSerializer.deserialize(CustomCheckSerializer.serialize(profile))
        val restoredProvider = restored.checksConfig.geoIp.customProviders.first()

        assertEquals("MyAPI", restoredProvider.name)
        assertEquals("https://example.com/geoip", restoredProvider.url)
        assertEquals("$.ip", restoredProvider.responseMapping.ipPath)
        assertEquals("$.country", restoredProvider.responseMapping.countryCodePath)
    }

    @Test
    fun `roundtrip preserves custom geoip provider with ip placeholder`() {
        val provider = CustomGeoIpProvider(
            name = "MyAPI",
            url = "https://example.com/geoip/{ip}?format=json",
            enabled = true,
            responseMapping = ResponseMapping(responseType = ResponseType.JSON, ipPath = "$.ip"),
        )
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(geoIp = GeoIpConfig(customProviders = listOf(provider)))
        )
        val restored = CustomCheckSerializer.deserialize(CustomCheckSerializer.serialize(profile))

        assertEquals(1, restored.checksConfig.geoIp.customProviders.size)
        assertEquals(
            "https://example.com/geoip/{ip}?format=json",
            restored.checksConfig.geoIp.customProviders.first().url,
        )
    }

    @Test
    fun `roundtrip preserves custom ip endpoints`() {
        val endpoint = CustomIpEndpoint(
            label = "My Checker",
            url = "https://checker.example.com",
            scope = EndpointScope.NON_RU,
            enabled = false,
        )
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(ipComparison = IpComparisonConfig(customEndpoints = listOf(endpoint)))
        )
        val restored = CustomCheckSerializer.deserialize(CustomCheckSerializer.serialize(profile))
        val ep = restored.checksConfig.ipComparison.customEndpoints.first()

        assertEquals("My Checker", ep.label)
        assertEquals(EndpointScope.NON_RU, ep.scope)
        assertEquals(false, ep.enabled)
    }

    @Test
    fun `roundtrip preserves stun servers`() {
        val stun = StunServer(host = "stun.myserver.com", port = 3478, label = "My STUN")
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(callTransport = CallTransportConfig(enabled = true, customStunServers = listOf(stun)))
        )
        val restored = CustomCheckSerializer.deserialize(CustomCheckSerializer.serialize(profile))
        val s = restored.checksConfig.callTransport.customStunServers.first()

        assertEquals("stun.myserver.com", s.host)
        assertEquals(3478, s.port)
    }

    @Test
    fun `roundtrip preserves marketplace info`() {
        val info = MarketplaceInfo(sourceUrl = "https://market.example.com", official = true, verified = true, signatureVerified = true, marketplaceId = "abc")
        val profile = defaultProfile().copy(marketplaceInfo = info)
        // Untrusted deserialize: signature_verified is dropped, which downgrades
        // official/verified to false. This is the public contract.
        val restored = CustomCheckSerializer.deserialize(CustomCheckSerializer.serialize(profile))
        assertEquals("https://market.example.com", restored.marketplaceInfo?.sourceUrl)
        assertEquals(false, restored.marketplaceInfo?.official)
        assertEquals(false, restored.marketplaceInfo?.signatureVerified)

        // Trusted deserialize (storage) honors the bit.
        val fromStorage = CustomCheckSerializer.deserializeFromStorage(CustomCheckSerializer.serialize(profile))
        assertEquals(true, fromStorage.marketplaceInfo?.official)
        assertEquals(true, fromStorage.marketplaceInfo?.signatureVerified)
    }

    @Test
    fun `roundtrip preserves null marketplace info`() {
        val profile = defaultProfile().copy(marketplaceInfo = null)
        val restored = CustomCheckSerializer.deserialize(CustomCheckSerializer.serialize(profile))
        assertNull(restored.marketplaceInfo)
    }

    // ── defaults on missing fields ────────────────────────────────────────────

    @Test
    fun `deserialize minimal json uses defaults`() {
        val json = """{"schema_version":1,"id":"x","name":"Minimal"}"""
        val profile = CustomCheckSerializer.deserialize(json)

        assertEquals("x", profile.id)
        assertEquals("Minimal", profile.name)
        assertEquals("", profile.description)
        assertEquals(true, profile.checksConfig.splitTunnel.enabled)
        assertEquals(true, profile.networkConfig.networkRequestsEnabled)
    }

    // ── validate ─────────────────────────────────────────────────────────────

    @Test
    fun `validate ok on valid json`() {
        val json = CustomCheckSerializer.serialize(defaultProfile())
        assertEquals(ValidationResult.Ok, CustomCheckSerializer.validate(json))
    }

    @Test
    fun `validate error on broken json`() {
        val result = CustomCheckSerializer.validate("{not valid json}")
        assertTrue(result is ValidationResult.Error)
    }

    @Test
    fun `validate error on missing schema_version`() {
        val json = """{"id":"x","name":"N"}"""
        val result = CustomCheckSerializer.validate(json)
        assertTrue(result is ValidationResult.Error)
        assertTrue((result as ValidationResult.Error).message.contains("schema_version"))
    }

    @Test
    fun `validate error on missing id`() {
        val json = """{"schema_version":1,"name":"N"}"""
        val result = CustomCheckSerializer.validate(json)
        assertTrue(result is ValidationResult.Error)
        assertTrue((result as ValidationResult.Error).message.contains("id"))
    }

    @Test
    fun `validate error on missing name`() {
        val json = """{"schema_version":1,"id":"x"}"""
        val result = CustomCheckSerializer.validate(json)
        assertTrue(result is ValidationResult.Error)
        assertTrue((result as ValidationResult.Error).message.contains("name"))
    }

    @Test
    fun `validate error on blank name`() {
        val json = """{"schema_version":1,"id":"x","name":"   "}"""
        val result = CustomCheckSerializer.validate(json)
        assertTrue(result is ValidationResult.Error)
    }

    // ── extractAllUrls ────────────────────────────────────────────────────────

    @Test
    fun `extractAllUrls includes custom geoip providers`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                geoIp = GeoIpConfig(customProviders = listOf(
                    CustomGeoIpProvider("MyGeo", "https://geo.example.com", true, ResponseMapping())
                ))
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.any { it.url == "https://geo.example.com" && it.checkName == "GeoIP" })
    }

    @Test
    fun `extractAllUrls includes custom ip endpoints`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                ipComparison = IpComparisonConfig(customEndpoints = listOf(
                    CustomIpEndpoint("MyIP", "https://ip.example.com")
                ))
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.any { it.url == "https://ip.example.com" && it.checkName == "IP Comparison" })
    }

    @Test
    fun `extractAllUrls includes custom cdn targets`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                cdnPulling = CdnPullingConfig(customTargets = listOf(
                    CustomCdnTarget("CDN", "https://cdn.example.com/trace")
                ))
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.any { it.url == "https://cdn.example.com/trace" && it.checkName == "CDN Pulling" })
    }

    @Test
    fun `extractAllUrls includes icmp hosts as ping format`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                icmpSpoofing = IcmpSpoofingConfig(customTargets = listOf(
                    IcmpTarget("blocked.example.com", "Blocked site")
                ))
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.any { it.url == "ping blocked.example.com" && it.checkName == "ICMP Spoofing" })
    }

    @Test
    fun `extractAllUrls includes rtt hosts as ping format`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                rttTriangulation = RttTriangulationConfig(customTargets = listOf(
                    RttTarget("server.ru", "My server", "RU")
                ))
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.any { it.url == "ping server.ru" && it.checkName == "RTT Triangulation" })
    }

    @Test
    fun `extractAllUrls includes stun servers in stun url format`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(
                callTransport = CallTransportConfig(customStunServers = listOf(
                    StunServer("stun.myserver.com", 3478, "My STUN")
                ))
            )
        )
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.any { it.url == "stun://stun.myserver.com:3478" && it.checkName == "Call Transport" })
    }

    @Test
    fun `extractAllUrls returns empty for default profile`() {
        val profile = defaultProfile()
        val urls = CustomCheckSerializer.extractAllUrls(profile)
        assertTrue(urls.isEmpty())
    }

    @Test
    fun `schema_version is 1 in serialized output`() {
        val json = CustomCheckSerializer.serialize(defaultProfile())
        val obj = org.json.JSONObject(json)
        assertEquals(1, obj.getInt("schema_version"))
    }

    @Test
    fun `roundtrip preserves domainReachabilityEnabled false`() {
        val profile = defaultProfile().copy(
            checksConfig = ChecksConfig(domainReachabilityEnabled = false),
        )
        val restored = CustomCheckSerializer.deserialize(CustomCheckSerializer.serialize(profile))
        assertEquals(false, restored.checksConfig.domainReachabilityEnabled)
    }

    @Test
    fun `legacy JSON without domain_reachability_enabled defaults to true`() {
        val legacy = """
            {
              "schema_version": 1,
              "id": "legacy-1",
              "name": "Legacy",
              "checks": { }
            }
        """.trimIndent()
        val restored = CustomCheckSerializer.deserialize(legacy)
        assertEquals(true, restored.checksConfig.domainReachabilityEnabled)
    }
}
