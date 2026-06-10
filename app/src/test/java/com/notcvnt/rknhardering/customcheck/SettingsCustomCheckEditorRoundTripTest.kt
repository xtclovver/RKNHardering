package com.notcvnt.rknhardering.customcheck

import android.app.Application
import android.os.Bundle
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.button.MaterialButton
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.SettingsActivity
import com.notcvnt.rknhardering.SettingsCustomCheckEditorFragment
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

/**
 * Characterization tests pinning the editor's read/write semantics before the
 * fragment is decomposed into per-section binders: what the editor loads into
 * its views and what saveAndExit reconstructs must stay byte-equal.
 */
@RunWith(RobolectricTestRunner::class)
class SettingsCustomCheckEditorRoundTripTest {

    private val context: Application = ApplicationProvider.getApplicationContext()

    private fun launchEditor(profileId: String?): SettingsCustomCheckEditorFragment {
        val activity = Robolectric.buildActivity(SettingsActivity::class.java).setup().get()
        val fragment = SettingsCustomCheckEditorFragment().apply {
            if (profileId != null) {
                arguments = Bundle().apply { putString("profile_id", profileId) }
            }
        }
        activity.supportFragmentManager.beginTransaction()
            .replace(R.id.settingsFragmentContainer, fragment)
            .commitNow()
        return fragment
    }

    private fun clickSave(fragment: SettingsCustomCheckEditorFragment) {
        fragment.requireView().findViewById<MaterialButton>(R.id.btnSave).performClick()
    }

    @Test
    fun `non-default profile survives open-save round trip unchanged`() {
        val original = CustomCheckProfile(
            name = "Round trip",
            description = "desc",
            author = "tester",
            version = "2.3.4",
            checksConfig = ChecksConfig(
                geoIp = GeoIpConfig(
                    enabled = true,
                    timeoutMs = 4321,
                    builtinProviders = mapOf(
                        "ipapi.is" to false,
                        "iplocate.io" to true,
                        "ipquery.io" to false,
                        "iplookup.it" to true,
                        "ipbot.com" to true,
                    ),
                    // Note: a {ip}-placeholder URL would be silently dropped by
                    // UrlSanitizer on reload (pre-existing bug, tracked separately).
                    customProviders = listOf(
                        CustomGeoIpProvider(name = "p1", url = "https://geo.example/?q="),
                    ),
                ),
                ipComparison = IpComparisonConfig(
                    enabled = true,
                    timeoutMs = 2222,
                    builtinRuCheckersEnabled = false,
                    builtinNonRuCheckersEnabled = true,
                    customEndpoints = listOf(
                        CustomIpEndpoint(label = "e1", url = "https://ip.example", scope = EndpointScope.NON_RU),
                    ),
                ),
                cdnPulling = CdnPullingConfig(
                    enabled = true,
                    timeoutMs = 3333,
                    meduzaEnabled = false,
                    rutrackerEnabled = true,
                    builtinTargetsEnabled = false,
                    customTargets = listOf(CustomCdnTarget(label = "c1", url = "https://cdn.example")),
                ),
                directSigns = DirectSignsConfig(
                    checkHttpProxy = false,
                    checkVpnService = false,
                ),
                indirectSigns = IndirectSignsConfig(
                    checkDns = false,
                    checkDumpsys = false,
                    listenerPortThreshold = 9,
                ),
                nativeSigns = CheckToggle(enabled = false),
                locationSignals = LocationSignalsConfig(checkCellTowers = false),
                icmpSpoofing = IcmpSpoofingConfig(
                    enabled = true,
                    timeoutMs = 1111,
                    pingCount = 7,
                    builtinTargetsEnabled = false,
                    customTargets = listOf(IcmpTarget(host = "1.2.3.4", label = "t1", isControl = true)),
                ),
                rttTriangulation = RttTriangulationConfig(
                    enabled = true,
                    timeoutMs = 2345,
                    pingCount = 2,
                    customTargets = listOf(RttTarget(host = "8.8.8.8", label = "g", expectedLocation = "EU")),
                ),
                callTransport = CallTransportConfig(
                    enabled = true,
                    timeoutMs = 4444,
                    builtinGlobalStunEnabled = false,
                    checkMtproto = false,
                    customStunServers = listOf(StunServer(host = "stun.example", port = 3479, label = "s1")),
                ),
                splitTunnel = SplitTunnelConfig(
                    proxyScan = false,
                    portRange = "custom",
                    portRangeStart = 2000,
                    portRangeEnd = 3000,
                    connectTimeoutMs = 150,
                    checkMtprotoViaProxy = false,
                ),
                domainReachabilityEnabled = true,
            ),
            customDomains = listOf(
                CustomDomain(domain = "generic.example", checkType = "dns", description = "d"),
                CustomDomain(
                    domain = "reach.example",
                    checkType = "reachability",
                    description = "r",
                    expectedTcpAvailable = false,
                ),
            ),
            networkConfig = NetworkConfig(
                networkRequestsEnabled = false,
                dnsMode = "doh",
                dnsPreset = "custom",
                dohUrl = "https://doh.example/dns-query",
                dohBootstrap = "9.9.9.9",
            ),
        )
        CustomCheckRepository.save(context, original)

        clickSave(launchEditor(original.id))

        val reloaded = CustomCheckRepository.getById(context, original.id)
        assertNotNull(reloaded)
        assertEquals(original.name, reloaded!!.name)
        assertEquals(original.description, reloaded.description)
        assertEquals(original.author, reloaded.author)
        assertEquals(original.version, reloaded.version)
        assertEquals(original.checksConfig, reloaded.checksConfig)
        assertEquals(original.customDomains, reloaded.customDomains)
        assertEquals(original.networkConfig, reloaded.networkConfig)
        assertNull(reloaded.marketplaceInfo)
        assertEquals(original.sourceProfileId, reloaded.sourceProfileId)
    }

    @Test
    fun `untouched new profile saves the pinned editor defaults`() {
        clickSave(launchEditor(profileId = null))

        val saved = CustomCheckRepository.getAll(context).single()
        assertEquals("New profile", saved.name)
        assertEquals("1.0.0", saved.version)

        val allBuiltinGeo = mapOf(
            "ipapi.is" to true,
            "iplocate.io" to true,
            "ipquery.io" to true,
            "iplookup.it" to true,
            "ipbot.com" to true,
        )
        val cfg = saved.checksConfig
        assertEquals(
            GeoIpConfig(enabled = true, timeoutMs = 10_000, builtinProviders = allBuiltinGeo),
            cfg.geoIp,
        )
        assertEquals(IpComparisonConfig(enabled = true, timeoutMs = 8_000), cfg.ipComparison)
        assertEquals(CdnPullingConfig(enabled = false, timeoutMs = 10_000), cfg.cdnPulling)
        assertEquals(DirectSignsConfig(), cfg.directSigns)
        assertEquals(IndirectSignsConfig(listenerPortThreshold = 5), cfg.indirectSigns)
        assertEquals(CheckToggle(enabled = true), cfg.nativeSigns)
        assertEquals(LocationSignalsConfig(), cfg.locationSignals)
        assertEquals(
            IcmpSpoofingConfig(enabled = false, timeoutMs = 5_000, pingCount = 3),
            cfg.icmpSpoofing,
        )
        assertEquals(
            RttTriangulationConfig(enabled = false, timeoutMs = 5_000, pingCount = 5),
            cfg.rttTriangulation,
        )
        assertEquals(CallTransportConfig(enabled = false, timeoutMs = 5_000), cfg.callTransport)
        assertEquals(
            SplitTunnelConfig(
                enabled = true,
                portRange = "popular",
                portRangeStart = 1024,
                portRangeEnd = 65535,
                connectTimeoutMs = 300,
            ),
            cfg.splitTunnel,
        )
        assertTrue(cfg.domainReachabilityEnabled)
        assertEquals(
            NetworkConfig(networkRequestsEnabled = true, dnsMode = "system", dnsPreset = "custom"),
            saved.networkConfig,
        )
        assertTrue(saved.customDomains.isEmpty())
    }

    @Test
    fun `saving an official profile forks it into an edited copy`() {
        // Run the one-time legacy migration on the empty store first; otherwise
        // it would downgrade the profile saved below on first read, like it does
        // for profiles written by pre-signature builds.
        CustomCheckRepository.getAll(context)

        // The official flag only survives storage when signatureVerified is set
        // AND originalHash matches the canonical hash (the repository mirrors it
        // into prefs as the tamper-evident trust anchor).
        val base = CustomCheckProfile(name = "Official check")
        val official = base.copy(
            marketplaceInfo = MarketplaceInfo(
                official = true,
                verified = true,
                signatureVerified = true,
                marketplaceId = "mp-1",
                originalHash = CustomCheckSerializer.canonicalHash(base),
            ),
        )
        CustomCheckRepository.save(context, official)
        val loaded = CustomCheckRepository.getById(context, official.id)
        assertEquals(
            "storage trust chain must keep the official flag",
            true,
            loaded?.marketplaceInfo?.official,
        )

        clickSave(launchEditor(official.id))

        val all = CustomCheckRepository.getAll(context)
        val fork = all.single { it.id != official.id }
        val suffix = context.getString(R.string.profile_name_edited_suffix)
        assertNotEquals(official.id, fork.id)
        assertEquals(official.name + suffix, fork.name)
        assertNull(fork.marketplaceInfo)
        assertEquals(official.id, fork.sourceProfileId)
    }
}
