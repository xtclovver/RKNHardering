package com.notcvnt.rknhardering.customcheck

import org.json.JSONArray
import org.json.JSONObject

// ─── Validation result ───────────────────────────────────────────────────────

sealed interface ValidationResult {
    object Ok : ValidationResult
    data class Error(val message: String) : ValidationResult
}

// ─── URL extraction ──────────────────────────────────────────────────────────

data class UrlInfo(
    val url: String,
    val purpose: String,
    val checkName: String,
)

// ─── Serializer ──────────────────────────────────────────────────────────────

object CustomCheckSerializer {

    private const val SCHEMA_VERSION = 1
    // Caps on imported payload size to keep memory predictable and to make
    // attacker-controlled payloads less interesting (no point ferrying 10k URLs).
    private const val MAX_CUSTOM_ENTRIES = 32
    private const val MAX_LABEL_LEN = 128

    // ── serialize ────────────────────────────────────────────────────────────

    fun serialize(profile: CustomCheckProfile): String {
        val root = JSONObject()
        root.put("schema_version", SCHEMA_VERSION)
        root.put("id", profile.id)
        root.put("name", profile.name)
        root.put("description", profile.description)
        root.put("author", profile.author)
        root.put("version", profile.version)
        root.put("created_at", profile.createdAt)
        root.put("updated_at", profile.updatedAt)

        root.put("checks", serializeChecksConfig(profile.checksConfig))
        root.put("custom_domains", serializeCustomDomains(profile.customDomains))
        root.put("network", serializeNetworkConfig(profile.networkConfig))

        profile.marketplaceInfo?.let { root.put("marketplace", serializeMarketplaceInfo(it, includeSignatureVerified = true)) }
        profile.sourceProfileId?.let { root.put("source_profile_id", it) }

        return root.toString(2)
    }

    private fun serializeChecksConfig(c: ChecksConfig): JSONObject {
        val obj = JSONObject()
        obj.put("geo_ip", serializeGeoIp(c.geoIp))
        obj.put("ip_comparison", serializeIpComparison(c.ipComparison))
        obj.put("cdn_pulling", serializeCdnPulling(c.cdnPulling))
        obj.put("direct_signs", serializeDirectSigns(c.directSigns))
        obj.put("indirect_signs", serializeIndirectSigns(c.indirectSigns))
        obj.put("native_signs", JSONObject().also { it.put("enabled", c.nativeSigns.enabled) })
        obj.put("location_signals", serializeLocationSignals(c.locationSignals))
        obj.put("icmp_spoofing", serializeIcmpSpoofing(c.icmpSpoofing))
        obj.put("rtt_triangulation", serializeRttTriangulation(c.rttTriangulation))
        obj.put("call_transport", serializeCallTransport(c.callTransport))
        obj.put("split_tunnel", serializeSplitTunnel(c.splitTunnel))
        obj.put("domain_reachability_enabled", c.domainReachabilityEnabled)
        return obj
    }

    private fun serializeResponseMapping(m: ResponseMapping): JSONObject {
        val obj = JSONObject()
        obj.put("response_type", m.responseType.name)
        m.ipPath?.let { obj.put("ip_path", it) }
        m.countryCodePath?.let { obj.put("country_code_path", it) }
        m.countryNamePath?.let { obj.put("country_name_path", it) }
        m.ispPath?.let { obj.put("isp_path", it) }
        m.orgPath?.let { obj.put("org_path", it) }
        m.asnPath?.let { obj.put("asn_path", it) }
        m.isHostingPath?.let { obj.put("is_hosting_path", it) }
        m.isProxyPath?.let { obj.put("is_proxy_path", it) }
        return obj
    }

    private fun serializeGeoIp(g: GeoIpConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", g.enabled)
        obj.put("timeout_ms", g.timeoutMs)
        val builtinObj = JSONObject()
        g.builtinProviders.forEach { (k, v) -> builtinObj.put(k, v) }
        obj.put("builtin_providers", builtinObj)
        val arr = JSONArray()
        g.customProviders.forEach { p ->
            val e = JSONObject()
            e.put("name", p.name)
            e.put("url", p.url)
            e.put("enabled", p.enabled)
            e.put("response_mapping", serializeResponseMapping(p.responseMapping))
            arr.put(e)
        }
        obj.put("custom_providers", arr)
        return obj
    }

    private fun serializeIpComparison(c: IpComparisonConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", c.enabled)
        obj.put("timeout_ms", c.timeoutMs)
        obj.put("builtin_ru_checkers_enabled", c.builtinRuCheckersEnabled)
        obj.put("builtin_non_ru_checkers_enabled", c.builtinNonRuCheckersEnabled)
        val arr = JSONArray()
        c.customEndpoints.forEach { ep ->
            val e = JSONObject()
            e.put("label", ep.label)
            e.put("url", ep.url)
            e.put("scope", ep.scope.name)
            e.put("enabled", ep.enabled)
            e.put("response_mapping", serializeResponseMapping(ep.responseMapping))
            arr.put(e)
        }
        obj.put("custom_endpoints", arr)
        return obj
    }

    private fun serializeCdnPulling(c: CdnPullingConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", c.enabled)
        obj.put("timeout_ms", c.timeoutMs)
        obj.put("meduza_enabled", c.meduzaEnabled)
        obj.put("rutracker_enabled", c.rutrackerEnabled)
        obj.put("builtin_targets_enabled", c.builtinTargetsEnabled)
        val arr = JSONArray()
        c.customTargets.forEach { t ->
            val e = JSONObject()
            e.put("label", t.label)
            e.put("url", t.url)
            e.put("enabled", t.enabled)
            e.put("response_mapping", serializeResponseMapping(t.responseMapping))
            arr.put(e)
        }
        obj.put("custom_targets", arr)
        return obj
    }

    private fun serializeDirectSigns(d: DirectSignsConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", d.enabled)
        obj.put("check_transport_vpn", d.checkTransportVpn)
        obj.put("check_http_proxy", d.checkHttpProxy)
        obj.put("check_socks_proxy", d.checkSocksProxy)
        obj.put("check_proxy_info", d.checkProxyInfo)
        obj.put("check_vpn_service", d.checkVpnService)
        return obj
    }

    private fun serializeIndirectSigns(i: IndirectSignsConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", i.enabled)
        obj.put("check_not_vpn_cap", i.checkNotVpnCap)
        obj.put("check_vpn_interfaces", i.checkVpnInterfaces)
        obj.put("check_mtu_anomaly", i.checkMtuAnomaly)
        obj.put("check_ipsec", i.checkIpsec)
        obj.put("check_routing", i.checkRouting)
        obj.put("check_dns", i.checkDns)
        obj.put("check_proxy_tools", i.checkProxyTools)
        obj.put("check_local_listeners", i.checkLocalListeners)
        obj.put("check_dumpsys", i.checkDumpsys)
        obj.put("listener_port_threshold", i.listenerPortThreshold)
        return obj
    }

    private fun serializeLocationSignals(l: LocationSignalsConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", l.enabled)
        obj.put("check_beacondb", l.checkBeacondb)
        obj.put("check_cell_towers", l.checkCellTowers)
        obj.put("check_wifi_signals", l.checkWifiSignals)
        return obj
    }

    private fun serializeIcmpSpoofing(c: IcmpSpoofingConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", c.enabled)
        obj.put("timeout_ms", c.timeoutMs)
        obj.put("ping_count", c.pingCount)
        obj.put("builtin_targets_enabled", c.builtinTargetsEnabled)
        val arr = JSONArray()
        c.customTargets.forEach { t ->
            val e = JSONObject()
            e.put("host", t.host)
            e.put("label", t.label)
            e.put("is_control", t.isControl)
            arr.put(e)
        }
        obj.put("custom_targets", arr)
        return obj
    }

    private fun serializeRttTriangulation(c: RttTriangulationConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", c.enabled)
        obj.put("timeout_ms", c.timeoutMs)
        obj.put("ping_count", c.pingCount)
        obj.put("builtin_targets_enabled", c.builtinTargetsEnabled)
        val arr = JSONArray()
        c.customTargets.forEach { t ->
            val e = JSONObject()
            e.put("host", t.host)
            e.put("label", t.label)
            e.put("expected_location", t.expectedLocation)
            arr.put(e)
        }
        obj.put("custom_targets", arr)
        return obj
    }

    private fun serializeCallTransport(c: CallTransportConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", c.enabled)
        obj.put("timeout_ms", c.timeoutMs)
        obj.put("builtin_global_stun_enabled", c.builtinGlobalStunEnabled)
        obj.put("builtin_ru_stun_enabled", c.builtinRuStunEnabled)
        obj.put("check_mtproto", c.checkMtproto)
        val arr = JSONArray()
        c.customStunServers.forEach { s ->
            val e = JSONObject()
            e.put("host", s.host)
            e.put("port", s.port)
            e.put("label", s.label)
            arr.put(e)
        }
        obj.put("custom_stun_servers", arr)
        return obj
    }

    private fun serializeSplitTunnel(s: SplitTunnelConfig): JSONObject {
        val obj = JSONObject()
        obj.put("enabled", s.enabled)
        obj.put("proxy_scan", s.proxyScan)
        obj.put("xray_api_scan", s.xrayApiScan)
        obj.put("port_range", s.portRange)
        obj.put("port_range_start", s.portRangeStart)
        obj.put("port_range_end", s.portRangeEnd)
        obj.put("connect_timeout_ms", s.connectTimeoutMs)
        obj.put("check_underlying_network", s.checkUnderlyingNetwork)
        obj.put("check_vpn_network_binding", s.checkVpnNetworkBinding)
        obj.put("check_mtproto_via_proxy", s.checkMtprotoViaProxy)
        return obj
    }

    private fun serializeCustomDomains(domains: List<CustomDomain>): JSONArray {
        val arr = JSONArray()
        domains.forEach { d ->
            val e = JSONObject()
            e.put("domain", d.domain)
            e.put("check_type", d.checkType)
            e.put("description", d.description)
            e.put("expected_dns_available", d.expectedDnsAvailable)
            e.put("expected_tcp_available", d.expectedTcpAvailable)
            e.put("expected_tls_available", d.expectedTlsAvailable)
            arr.put(e)
        }
        return arr
    }

    private fun serializeNetworkConfig(n: NetworkConfig): JSONObject {
        val obj = JSONObject()
        obj.put("network_requests_enabled", n.networkRequestsEnabled)
        obj.put("dns_mode", n.dnsMode)
        obj.put("dns_preset", n.dnsPreset)
        obj.put("dns_servers", n.dnsServers)
        obj.put("doh_url", n.dohUrl)
        obj.put("doh_bootstrap", n.dohBootstrap)
        return obj
    }

    private fun serializeMarketplaceInfo(m: MarketplaceInfo, includeSignatureVerified: Boolean): JSONObject {
        val obj = JSONObject()
        if (m.sourceUrl != null) obj.put("source_url", m.sourceUrl) else obj.put("source_url", JSONObject.NULL)
        obj.put("official", m.official)
        obj.put("verified", m.verified)
        // signature_verified is a device-local trust signal — only serialized when
        // writing to local storage, never included in the canonical hash and never
        // honored when an imported file claims it.
        if (includeSignatureVerified) obj.put("signature_verified", m.signatureVerified)
        if (m.marketplaceId != null) obj.put("marketplace_id", m.marketplaceId) else obj.put("marketplace_id", JSONObject.NULL)
        if (m.originalHash != null) obj.put("original_hash", m.originalHash) else obj.put("original_hash", JSONObject.NULL)
        return obj
    }

    // ── deserialize ──────────────────────────────────────────────────────────

    // Deserialize a profile from an UNTRUSTED source (file/clipboard/network).
    // marketplace.signature_verified, official, verified are forced to false here —
    // those bits can only be set later by code that actually verified the catalog
    // signature for this profile. URLs and hosts are scrubbed via UrlSanitizer.
    fun deserialize(json: String): CustomCheckProfile = deserializeInternal(json, trustSignatureField = false)

    // Deserialize from device-local storage where we trust the signature_verified
    // bit because the app itself wrote it after a successful catalog check.
    fun deserializeFromStorage(json: String): CustomCheckProfile = deserializeInternal(json, trustSignatureField = true)

    private fun deserializeInternal(json: String, trustSignatureField: Boolean): CustomCheckProfile {
        val root = JSONObject(json)

        val id = root.optString("id", java.util.UUID.randomUUID().toString())
        val name = root.optString("name", "Unnamed Profile")
        val description = root.optString("description", "")
        val author = root.optString("author", "")
        val version = root.optString("version", "1.0.0")
        val createdAt = root.optLong("created_at", System.currentTimeMillis())
        val updatedAt = root.optLong("updated_at", System.currentTimeMillis())

        val checksConfig = if (root.has("checks")) deserializeChecksConfig(root.getJSONObject("checks"))
        else ChecksConfig()

        val customDomains = if (root.has("custom_domains")) deserializeCustomDomains(root.getJSONArray("custom_domains"))
        else emptyList()

        val networkConfig = if (root.has("network")) deserializeNetworkConfig(root.getJSONObject("network"))
        else NetworkConfig()

        val rawMarketplaceInfo = if (root.has("marketplace")) deserializeMarketplaceInfo(root.getJSONObject("marketplace"), trustSignatureField)
        else null
        // Force official/verified to false when the trust signal is missing. The
        // catalog-verification path will re-mint these flags after Ed25519 succeeds.
        val marketplaceInfo = rawMarketplaceInfo?.let {
            if (it.signatureVerified) it else it.copy(official = false, verified = false)
        }

        val sourceProfileId = if (root.has("source_profile_id") && !root.isNull("source_profile_id"))
            root.getString("source_profile_id") else null

        return CustomCheckProfile(
            id = id,
            name = name,
            description = description,
            author = author,
            version = version,
            createdAt = createdAt,
            updatedAt = updatedAt,
            checksConfig = checksConfig,
            customDomains = customDomains,
            networkConfig = networkConfig,
            marketplaceInfo = marketplaceInfo,
            sourceProfileId = sourceProfileId,
        )
    }

    private fun deserializeChecksConfig(obj: JSONObject): ChecksConfig {
        return ChecksConfig(
            geoIp = if (obj.has("geo_ip")) deserializeGeoIp(obj.getJSONObject("geo_ip")) else GeoIpConfig(),
            ipComparison = if (obj.has("ip_comparison")) deserializeIpComparison(obj.getJSONObject("ip_comparison")) else IpComparisonConfig(),
            cdnPulling = if (obj.has("cdn_pulling")) deserializeCdnPulling(obj.getJSONObject("cdn_pulling")) else CdnPullingConfig(enabled = false),
            directSigns = if (obj.has("direct_signs")) deserializeDirectSigns(obj.getJSONObject("direct_signs")) else DirectSignsConfig(),
            indirectSigns = if (obj.has("indirect_signs")) deserializeIndirectSigns(obj.getJSONObject("indirect_signs")) else IndirectSignsConfig(),
            nativeSigns = if (obj.has("native_signs")) CheckToggle(obj.getJSONObject("native_signs").optBoolean("enabled", true)) else CheckToggle(),
            locationSignals = if (obj.has("location_signals")) deserializeLocationSignals(obj.getJSONObject("location_signals")) else LocationSignalsConfig(),
            icmpSpoofing = if (obj.has("icmp_spoofing")) deserializeIcmpSpoofing(obj.getJSONObject("icmp_spoofing")) else IcmpSpoofingConfig(enabled = false),
            rttTriangulation = if (obj.has("rtt_triangulation")) deserializeRttTriangulation(obj.getJSONObject("rtt_triangulation")) else RttTriangulationConfig(enabled = false),
            callTransport = if (obj.has("call_transport")) deserializeCallTransport(obj.getJSONObject("call_transport")) else CallTransportConfig(enabled = false),
            splitTunnel = if (obj.has("split_tunnel")) deserializeSplitTunnel(obj.getJSONObject("split_tunnel")) else SplitTunnelConfig(),
            domainReachabilityEnabled = obj.optBoolean("domain_reachability_enabled", true),
        )
    }

    private fun deserializeResponseMapping(obj: JSONObject): ResponseMapping {
        val type = runCatching { ResponseType.valueOf(obj.optString("response_type", "JSON")) }
            .getOrDefault(ResponseType.JSON)
        return ResponseMapping(
            responseType = type,
            ipPath = obj.optStringOrNull("ip_path"),
            countryCodePath = obj.optStringOrNull("country_code_path"),
            countryNamePath = obj.optStringOrNull("country_name_path"),
            ispPath = obj.optStringOrNull("isp_path"),
            orgPath = obj.optStringOrNull("org_path"),
            asnPath = obj.optStringOrNull("asn_path"),
            isHostingPath = obj.optStringOrNull("is_hosting_path"),
            isProxyPath = obj.optStringOrNull("is_proxy_path"),
        )
    }

    private fun JSONObject.optStringOrNull(key: String): String? =
        if (has(key) && !isNull(key)) optString(key).takeIf { it.isNotEmpty() } else null

    private fun deserializeGeoIp(obj: JSONObject): GeoIpConfig {
        val builtinProviders = mutableMapOf<String, Boolean>()
        if (obj.has("builtin_providers")) {
            val bp = obj.getJSONObject("builtin_providers")
            bp.keys().forEach { k -> builtinProviders[k] = bp.optBoolean(k, true) }
        }
        val customProviders = mutableListOf<CustomGeoIpProvider>()
        if (obj.has("custom_providers")) {
            val arr = obj.getJSONArray("custom_providers")
            for (i in 0 until arr.length().coerceAtMost(MAX_CUSTOM_ENTRIES)) {
                val e = arr.getJSONObject(i)
                val sanitizedUrl = UrlSanitizer.sanitizeHttpsUrl(e.optString("url", ""))
                if (sanitizedUrl.isEmpty()) continue
                customProviders.add(
                    CustomGeoIpProvider(
                        name = e.optString("name", "").take(MAX_LABEL_LEN),
                        url = sanitizedUrl,
                        enabled = e.optBoolean("enabled", true),
                        responseMapping = if (e.has("response_mapping")) deserializeResponseMapping(e.getJSONObject("response_mapping")) else ResponseMapping(),
                    )
                )
            }
        }
        return GeoIpConfig(
            enabled = obj.optBoolean("enabled", true),
            timeoutMs = obj.optInt("timeout_ms", 10_000),
            builtinProviders = builtinProviders,
            customProviders = customProviders,
        )
    }

    private fun deserializeIpComparison(obj: JSONObject): IpComparisonConfig {
        val endpoints = mutableListOf<CustomIpEndpoint>()
        if (obj.has("custom_endpoints")) {
            val arr = obj.getJSONArray("custom_endpoints")
            for (i in 0 until arr.length().coerceAtMost(MAX_CUSTOM_ENTRIES)) {
                val e = arr.getJSONObject(i)
                val sanitizedUrl = UrlSanitizer.sanitizeHttpsUrl(e.optString("url", ""))
                if (sanitizedUrl.isEmpty()) continue
                val scope = runCatching { EndpointScope.valueOf(e.optString("scope", "RU")) }.getOrDefault(EndpointScope.RU)
                endpoints.add(
                    CustomIpEndpoint(
                        label = e.optString("label", "").take(MAX_LABEL_LEN),
                        url = sanitizedUrl,
                        scope = scope,
                        enabled = e.optBoolean("enabled", true),
                        responseMapping = if (e.has("response_mapping")) deserializeResponseMapping(e.getJSONObject("response_mapping"))
                        else ResponseMapping(responseType = ResponseType.PLAIN_TEXT),
                    )
                )
            }
        }
        return IpComparisonConfig(
            enabled = obj.optBoolean("enabled", true),
            timeoutMs = obj.optInt("timeout_ms", 8_000),
            builtinRuCheckersEnabled = obj.optBoolean("builtin_ru_checkers_enabled", true),
            builtinNonRuCheckersEnabled = obj.optBoolean("builtin_non_ru_checkers_enabled", true),
            customEndpoints = endpoints,
        )
    }

    private fun deserializeCdnPulling(obj: JSONObject): CdnPullingConfig {
        val targets = mutableListOf<CustomCdnTarget>()
        if (obj.has("custom_targets")) {
            val arr = obj.getJSONArray("custom_targets")
            for (i in 0 until arr.length().coerceAtMost(MAX_CUSTOM_ENTRIES)) {
                val e = arr.getJSONObject(i)
                val sanitizedUrl = UrlSanitizer.sanitizeHttpsUrl(e.optString("url", ""))
                if (sanitizedUrl.isEmpty()) continue
                targets.add(
                    CustomCdnTarget(
                        label = e.optString("label", "").take(MAX_LABEL_LEN),
                        url = sanitizedUrl,
                        enabled = e.optBoolean("enabled", true),
                        responseMapping = if (e.has("response_mapping")) deserializeResponseMapping(e.getJSONObject("response_mapping"))
                        else ResponseMapping(responseType = ResponseType.KEY_VALUE),
                    )
                )
            }
        }
        return CdnPullingConfig(
            enabled = obj.optBoolean("enabled", false),
            timeoutMs = obj.optInt("timeout_ms", 10_000),
            meduzaEnabled = obj.optBoolean("meduza_enabled", true),
            rutrackerEnabled = obj.optBoolean("rutracker_enabled", true),
            builtinTargetsEnabled = obj.optBoolean("builtin_targets_enabled", true),
            customTargets = targets,
        )
    }

    private fun deserializeDirectSigns(obj: JSONObject): DirectSignsConfig = DirectSignsConfig(
        enabled = obj.optBoolean("enabled", true),
        checkTransportVpn = obj.optBoolean("check_transport_vpn", true),
        checkHttpProxy = obj.optBoolean("check_http_proxy", true),
        checkSocksProxy = obj.optBoolean("check_socks_proxy", true),
        checkProxyInfo = obj.optBoolean("check_proxy_info", true),
        checkVpnService = obj.optBoolean("check_vpn_service", true),
    )

    private fun deserializeIndirectSigns(obj: JSONObject): IndirectSignsConfig = IndirectSignsConfig(
        enabled = obj.optBoolean("enabled", true),
        checkNotVpnCap = obj.optBoolean("check_not_vpn_cap", true),
        checkVpnInterfaces = obj.optBoolean("check_vpn_interfaces", true),
        checkMtuAnomaly = obj.optBoolean("check_mtu_anomaly", true),
        checkIpsec = obj.optBoolean("check_ipsec", true),
        checkRouting = obj.optBoolean("check_routing", true),
        checkDns = obj.optBoolean("check_dns", true),
        checkProxyTools = obj.optBoolean("check_proxy_tools", true),
        checkLocalListeners = obj.optBoolean("check_local_listeners", true),
        checkDumpsys = obj.optBoolean("check_dumpsys", true),
        listenerPortThreshold = obj.optInt("listener_port_threshold", 5),
    )

    private fun deserializeLocationSignals(obj: JSONObject): LocationSignalsConfig = LocationSignalsConfig(
        enabled = obj.optBoolean("enabled", true),
        checkBeacondb = obj.optBoolean("check_beacondb", true),
        checkCellTowers = obj.optBoolean("check_cell_towers", true),
        checkWifiSignals = obj.optBoolean("check_wifi_signals", true),
    )

    private fun deserializeIcmpSpoofing(obj: JSONObject): IcmpSpoofingConfig {
        val targets = mutableListOf<IcmpTarget>()
        if (obj.has("custom_targets")) {
            val arr = obj.getJSONArray("custom_targets")
            for (i in 0 until arr.length().coerceAtMost(MAX_CUSTOM_ENTRIES)) {
                val e = arr.getJSONObject(i)
                val host = UrlSanitizer.sanitizeHost(e.optString("host", ""))
                if (host.isEmpty()) continue
                targets.add(IcmpTarget(
                    host = host,
                    label = e.optString("label", "").take(MAX_LABEL_LEN),
                    isControl = e.optBoolean("is_control", false),
                ))
            }
        }
        return IcmpSpoofingConfig(
            enabled = obj.optBoolean("enabled", false),
            timeoutMs = obj.optInt("timeout_ms", 5_000),
            pingCount = obj.optInt("ping_count", 3),
            builtinTargetsEnabled = obj.optBoolean("builtin_targets_enabled", true),
            customTargets = targets,
        )
    }

    private fun deserializeRttTriangulation(obj: JSONObject): RttTriangulationConfig {
        val targets = mutableListOf<RttTarget>()
        if (obj.has("custom_targets")) {
            val arr = obj.getJSONArray("custom_targets")
            for (i in 0 until arr.length().coerceAtMost(MAX_CUSTOM_ENTRIES)) {
                val e = arr.getJSONObject(i)
                val host = UrlSanitizer.sanitizeHost(e.optString("host", ""))
                if (host.isEmpty()) continue
                targets.add(RttTarget(
                    host = host,
                    label = e.optString("label", "").take(MAX_LABEL_LEN),
                    expectedLocation = e.optString("expected_location", "").take(MAX_LABEL_LEN),
                ))
            }
        }
        return RttTriangulationConfig(
            enabled = obj.optBoolean("enabled", false),
            timeoutMs = obj.optInt("timeout_ms", 5_000),
            pingCount = obj.optInt("ping_count", 5),
            builtinTargetsEnabled = obj.optBoolean("builtin_targets_enabled", true),
            customTargets = targets,
        )
    }

    private fun deserializeCallTransport(obj: JSONObject): CallTransportConfig {
        val servers = mutableListOf<StunServer>()
        if (obj.has("custom_stun_servers")) {
            val arr = obj.getJSONArray("custom_stun_servers")
            for (i in 0 until arr.length().coerceAtMost(MAX_CUSTOM_ENTRIES)) {
                val e = arr.getJSONObject(i)
                val host = UrlSanitizer.sanitizeHost(e.optString("host", ""))
                if (host.isEmpty()) continue
                val port = e.optInt("port", 3478).coerceIn(1, 65535)
                servers.add(StunServer(
                    host = host,
                    port = port,
                    label = e.optString("label", "").take(MAX_LABEL_LEN),
                ))
            }
        }
        return CallTransportConfig(
            enabled = obj.optBoolean("enabled", false),
            timeoutMs = obj.optInt("timeout_ms", 5_000),
            builtinGlobalStunEnabled = obj.optBoolean("builtin_global_stun_enabled", true),
            builtinRuStunEnabled = obj.optBoolean("builtin_ru_stun_enabled", true),
            checkMtproto = obj.optBoolean("check_mtproto", true),
            customStunServers = servers,
        )
    }

    private fun deserializeSplitTunnel(obj: JSONObject): SplitTunnelConfig = SplitTunnelConfig(
        enabled = obj.optBoolean("enabled", true),
        proxyScan = obj.optBoolean("proxy_scan", true),
        xrayApiScan = obj.optBoolean("xray_api_scan", true),
        portRange = obj.optString("port_range", "popular"),
        portRangeStart = obj.optInt("port_range_start", 1024),
        portRangeEnd = obj.optInt("port_range_end", 65535),
        connectTimeoutMs = obj.optInt("connect_timeout_ms", 300),
        checkUnderlyingNetwork = obj.optBoolean("check_underlying_network", true),
        checkVpnNetworkBinding = obj.optBoolean("check_vpn_network_binding", true),
        checkMtprotoViaProxy = obj.optBoolean("check_mtproto_via_proxy", true),
    )

    private fun deserializeCustomDomains(arr: JSONArray): List<CustomDomain> {
        val list = mutableListOf<CustomDomain>()
        for (i in 0 until arr.length().coerceAtMost(MAX_CUSTOM_ENTRIES)) {
            val e = arr.getJSONObject(i)
            val domain = UrlSanitizer.sanitizeHost(e.optString("domain", ""))
            if (domain.isEmpty()) continue
            list.add(CustomDomain(
                domain = domain,
                checkType = e.optString("check_type", "").take(MAX_LABEL_LEN),
                description = e.optString("description", "").take(MAX_LABEL_LEN),
                expectedDnsAvailable = e.optBoolean("expected_dns_available", true),
                expectedTcpAvailable = e.optBoolean("expected_tcp_available", true),
                expectedTlsAvailable = e.optBoolean("expected_tls_available", true),
            ))
        }
        return list
    }

    private fun deserializeNetworkConfig(obj: JSONObject): NetworkConfig = NetworkConfig(
        networkRequestsEnabled = obj.optBoolean("network_requests_enabled", true),
        dnsMode = obj.optString("dns_mode", "system"),
        dnsPreset = obj.optString("dns_preset", "custom"),
        dnsServers = UrlSanitizer.sanitizeAddressList(obj.optString("dns_servers", "")),
        dohUrl = UrlSanitizer.sanitizeHttpsUrl(obj.optString("doh_url", "")),
        dohBootstrap = UrlSanitizer.sanitizeAddressList(obj.optString("doh_bootstrap", "")),
    )

    private fun deserializeMarketplaceInfo(obj: JSONObject, trustSignatureVerifiedField: Boolean): MarketplaceInfo = MarketplaceInfo(
        sourceUrl = if (obj.has("source_url") && !obj.isNull("source_url")) obj.getString("source_url") else null,
        official = obj.optBoolean("official", false),
        verified = obj.optBoolean("verified", false),
        // signature_verified inside a file is only honored when reading from
        // local storage (where the app itself wrote it). For imports we ignore
        // the field entirely so attackers cannot forge it.
        signatureVerified = trustSignatureVerifiedField && obj.optBoolean("signature_verified", false),
        marketplaceId = if (obj.has("marketplace_id") && !obj.isNull("marketplace_id")) obj.getString("marketplace_id") else null,
        originalHash = if (obj.has("original_hash") && !obj.isNull("original_hash")) obj.getString("original_hash") else null,
    )

    // ── validate ─────────────────────────────────────────────────────────────

    fun validate(json: String): ValidationResult {
        val root = try {
            JSONObject(json)
        } catch (e: Exception) {
            return ValidationResult.Error("Invalid JSON: ${e.message}")
        }
        if (!root.has("schema_version")) return ValidationResult.Error("Missing required field: schema_version")
        if (!root.has("id")) return ValidationResult.Error("Missing required field: id")
        if (!root.has("name")) return ValidationResult.Error("Missing required field: name")
        val name = root.optString("name", "")
        if (name.isBlank()) return ValidationResult.Error("Field 'name' must not be blank")
        return ValidationResult.Ok
    }

    // ── canonical hash ────────────────────────────────────────────────────────
    //
    // SHA-256 over a canonical JSON projection of the profile that excludes the
    // marketplace block, the active id, and the timestamps. The intent is that the
    // hash is stable across (a) the JSON downloaded from GitHub and (b) the JSON
    // saved on the device — so the app can verify that a profile marked
    // official/verified has not been edited in place by the user.

    fun canonicalHash(profile: CustomCheckProfile): String {
        val root = JSONObject()
        root.put("name", profile.name)
        root.put("description", profile.description)
        root.put("author", profile.author)
        root.put("version", profile.version)
        root.put("checks", serializeChecksConfig(profile.checksConfig))
        root.put("custom_domains", serializeCustomDomains(profile.customDomains))
        root.put("network", serializeNetworkConfig(profile.networkConfig))
        return sha256Hex(root.toString())
    }

    // Re-validates a profile loaded from local storage.
    //   * If trustedHash is null (never installed from signed catalog), strip any
    //     official/verified the file might claim.
    //   * If trustedHash is provided, recompute canonicalHash and require match.
    //     The trustedHash comes from outside the file (SharedPrefs) so an attacker
    //     who can rewrite the .rkncheck cannot also rewrite this anchor.
    fun verifyIntegrity(profile: CustomCheckProfile, trustedHash: String? = null): CustomCheckProfile {
        val info = profile.marketplaceInfo ?: return profile
        if (trustedHash == null) {
            return if (info.official || info.verified || info.signatureVerified) {
                profile.copy(marketplaceInfo = info.copy(official = false, verified = false, signatureVerified = false))
            } else profile
        }
        val recomputed = canonicalHash(profile)
        if (recomputed.equals(trustedHash, ignoreCase = true)) return profile
        return profile.copy(
            marketplaceInfo = info.copy(official = false, verified = false, signatureVerified = false),
        )
    }

    private fun sha256Hex(input: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_CHARS[v ushr 4])
            sb.append(HEX_CHARS[v and 0x0F])
        }
        return sb.toString()
    }

    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    // ── extractAllUrls ────────────────────────────────────────────────────────

    fun extractAllUrls(profile: CustomCheckProfile): List<UrlInfo> {
        val result = mutableListOf<UrlInfo>()

        val net = profile.networkConfig
        if (net.dohUrl.isNotBlank()) {
            result.add(UrlInfo(url = net.dohUrl, purpose = "DoH endpoint", checkName = "DNS"))
        }
        if (net.dnsServers.isNotBlank()) {
            result.add(UrlInfo(url = net.dnsServers, purpose = "DNS servers", checkName = "DNS"))
        }
        if (net.dohBootstrap.isNotBlank()) {
            result.add(UrlInfo(url = net.dohBootstrap, purpose = "DoH bootstrap", checkName = "DNS"))
        }

        profile.checksConfig.geoIp.customProviders.forEach { p ->
            if (p.url.isNotBlank()) {
                result.add(UrlInfo(url = p.url, purpose = p.name, checkName = "GeoIP"))
            }
        }

        profile.checksConfig.ipComparison.customEndpoints.forEach { ep ->
            if (ep.url.isNotBlank()) {
                result.add(UrlInfo(url = ep.url, purpose = ep.label, checkName = "IP Comparison"))
            }
        }

        profile.checksConfig.cdnPulling.customTargets.forEach { t ->
            if (t.url.isNotBlank()) {
                result.add(UrlInfo(url = t.url, purpose = t.label, checkName = "CDN Pulling"))
            }
        }

        profile.checksConfig.icmpSpoofing.customTargets.forEach { t ->
            if (t.host.isNotBlank()) {
                result.add(UrlInfo(url = "ping ${t.host}", purpose = t.label, checkName = "ICMP Spoofing"))
            }
        }

        profile.checksConfig.rttTriangulation.customTargets.forEach { t ->
            if (t.host.isNotBlank()) {
                result.add(UrlInfo(url = "ping ${t.host}", purpose = t.label, checkName = "RTT Triangulation"))
            }
        }

        profile.checksConfig.callTransport.customStunServers.forEach { s ->
            if (s.host.isNotBlank()) {
                result.add(UrlInfo(url = "stun://${s.host}:${s.port}", purpose = s.label, checkName = "Call Transport"))
            }
        }

        profile.customDomains.forEach { d ->
            if (d.domain.isNotBlank()) {
                result.add(
                    UrlInfo(
                        url = d.domain,
                        purpose = d.description.ifBlank { d.checkType },
                        checkName = "Custom Domain (${d.checkType})",
                    ),
                )
            }
        }

        return result
    }
}
