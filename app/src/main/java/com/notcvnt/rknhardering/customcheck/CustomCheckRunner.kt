package com.notcvnt.rknhardering.customcheck

import android.content.Context
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.DnsResolverMode
import com.notcvnt.rknhardering.network.DnsResolverPreset

object CustomCheckRunner {

    /**
     * Maps a [CustomCheckProfile] onto [baseSettings], overriding only the fields
     * the profile controls. All other baseSettings fields are preserved as-is.
     */
    fun toCheckSettings(profile: CustomCheckProfile, baseSettings: CheckSettings): CheckSettings {
        val st = profile.checksConfig.splitTunnel
        val net = profile.networkConfig
        val cdn = profile.checksConfig.cdnPulling
        val ct = profile.checksConfig.callTransport
        val icmp = profile.checksConfig.icmpSpoofing
        val rtt = profile.checksConfig.rttTriangulation

        val resolverConfig = DnsResolverConfig(
            mode = DnsResolverMode.fromPref(net.dnsMode),
            preset = DnsResolverPreset.fromPref(net.dnsPreset),
            customDirectServers = DnsResolverConfig.parseAddressList(net.dnsServers),
            customDohUrl = net.dohUrl.trim().takeUnless { it.isEmpty() },
            customDohBootstrapHosts = DnsResolverConfig.parseAddressList(net.dohBootstrap),
        ).sanitized()

        // === Route customDomains to per-checker configs ===
        val domainsByType = profile.customDomains.groupBy { it.checkType }

        val icmpDomains = domainsByType["icmp"]?.map { d ->
            IcmpTarget(host = d.domain, label = d.description.ifEmpty { d.domain })
        } ?: emptyList()

        val rttDomains = domainsByType["rtt"]?.map { d ->
            RttTarget(host = d.domain, label = d.description.ifEmpty { d.domain })
        } ?: emptyList()

        val stunDomains = domainsByType["stun"]?.map { d ->
            StunServer(host = d.domain, port = 3478, label = d.description.ifEmpty { d.domain })
        } ?: emptyList()

        val cdnDomains = domainsByType["cdn_pulling"]?.map { d ->
            CustomCdnTarget(
                label = d.description.ifEmpty { d.domain },
                url = "https://${d.domain}/cdn-cgi/trace",
                responseMapping = ResponseMapping(
                    responseType = ResponseType.KEY_VALUE,
                    ipPath = "ip=(.+)",
                ),
            )
        } ?: emptyList()

        val ipCompDomains = domainsByType["ip_comparison"]?.map { d ->
            CustomIpEndpoint(
                label = d.description.ifEmpty { d.domain },
                url = "https://${d.domain}/",
                responseMapping = ResponseMapping(responseType = ResponseType.PLAIN_TEXT),
            )
        } ?: emptyList()

        val geoIpDomains = domainsByType["geo_ip"]?.map { d ->
            CustomGeoIpProvider(
                name = d.description.ifEmpty { d.domain },
                url = "https://${d.domain}/",
                responseMapping = ResponseMapping(responseType = ResponseType.JSON),
            )
        } ?: emptyList()

        val reachabilityToggle = profile.checksConfig.domainReachabilityEnabled
        val reachabilityDomainsRaw = (domainsByType["reachability"] ?: emptyList()) +
            (domainsByType["dpi"] ?: emptyList())
        val reachabilityDomains = if (reachabilityToggle) reachabilityDomainsRaw else emptyList()

        // Merge domain-derived targets into existing configs
        val effectiveIcmp = icmp.copy(
            customTargets = icmp.customTargets + icmpDomains,
            enabled = icmp.enabled || icmpDomains.isNotEmpty(),
        )
        val effectiveRtt = rtt.copy(
            customTargets = rtt.customTargets + rttDomains,
            enabled = rtt.enabled || rttDomains.isNotEmpty(),
        )
        val effectiveCt = ct.copy(
            customStunServers = ct.customStunServers + stunDomains,
            enabled = ct.enabled || stunDomains.isNotEmpty(),
        )
        val effectiveCdn = cdn.copy(
            customTargets = cdn.customTargets + cdnDomains,
            enabled = cdn.enabled || cdnDomains.isNotEmpty(),
        )
        val effectiveIpComp = profile.checksConfig.ipComparison.copy(
            customEndpoints = profile.checksConfig.ipComparison.customEndpoints + ipCompDomains,
        )
        val effectiveGeoIp = profile.checksConfig.geoIp.copy(
            customProviders = profile.checksConfig.geoIp.customProviders + geoIpDomains,
        )

        return baseSettings.copy(
            splitTunnelEnabled = st.enabled,
            proxyScanEnabled = st.proxyScan,
            xrayApiScanEnabled = st.xrayApiScan,
            networkRequestsEnabled = net.networkRequestsEnabled,
            callTransportProbeEnabled = effectiveCt.enabled,
            cdnPullingEnabled = effectiveCdn.enabled,
            cdnPullingMeduzaEnabled = cdn.meduzaEnabled,
            icmpSpoofingEnabled = effectiveIcmp.enabled,
            rttTriangulationEnabled = effectiveRtt.enabled,
            nativeSignsEnabled = profile.checksConfig.nativeSigns.enabled,
            portRange = st.portRange,
            portRangeStart = st.portRangeStart,
            portRangeEnd = st.portRangeEnd,
            splitTunnelConnectTimeoutMs = st.connectTimeoutMs,
            splitTunnelCheckUnderlyingNetwork = st.checkUnderlyingNetwork,
            splitTunnelCheckVpnNetworkBinding = st.checkVpnNetworkBinding,
            splitTunnelCheckMtprotoViaProxy = st.checkMtprotoViaProxy,
            resolverConfig = resolverConfig,

            // Per-checker deep customization
            geoIp = effectiveGeoIp,
            ipComparison = effectiveIpComp,
            cdnPulling = effectiveCdn,
            directSigns = profile.checksConfig.directSigns,
            indirectSigns = profile.checksConfig.indirectSigns,
            locationSignals = profile.checksConfig.locationSignals,
            icmpSpoofing = effectiveIcmp,
            rttTriangulation = effectiveRtt,
            callTransport = effectiveCt,

            // Domain reachability (DPI)
            domainReachabilityEnabled = reachabilityDomains.isNotEmpty(),
            reachabilityDomains = reachabilityDomains,
        )
    }

    fun isProfileActive(context: Context): Boolean =
        CustomCheckRepository.getActiveProfileId(context) != null

    fun getActiveProfile(context: Context): CustomCheckProfile? {
        val id = CustomCheckRepository.getActiveProfileId(context) ?: return null
        return CustomCheckRepository.getById(context, id)
    }
}
