package com.notcvnt.rknhardering

import android.content.Context
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceMaturity
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.IpFamily
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.LocationSignalsFacts
import com.notcvnt.rknhardering.model.ObservedIp
import com.notcvnt.rknhardering.model.TargetGroup
import com.notcvnt.rknhardering.model.Verdict
import org.junit.Before
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MainActivityUiRenderingTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun setUp() {
        AppUiSettings.prefs(context).edit().clear().commit()
    }

    @Test
    fun `ip comparison response view hides raw error details`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val response = IpCheckerResponse(
            label = "ip.sb IPv6",
            url = "https://api-ipv6.ip.sb/ip",
            scope = IpCheckerScope.NON_RU,
            error = "OkHttp failed after 3 attempts: Could not connect to server",
        )

        val view = invokePrivate<View>(activity, "createIpCheckerResponseView", response, false)
        val text = collectText(view)

        assertTrueContains(text, "ip.sb IPv6")
        assertTrueContains(text, "https://api-ipv6.ip.sb/ip")
        assertTrueContains(text, activity.getString(R.string.main_card_status_error))
        assertFalse(text.contains("OkHttp failed after 3 attempts"))
        assertFalse(text.contains("Could not connect to server"))
    }

    @Test
    fun `ip comparison response view hides ignored ipv6 diagnostics`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val response = IpCheckerResponse(
            label = "ip.sb IPv6",
            url = "https://api-ipv6.ip.sb/ip",
            scope = IpCheckerScope.NON_RU,
            error = "native curl failed",
            ignoredIpv6Error = true,
        )

        val view = invokePrivate<View>(activity, "createIpCheckerResponseView", response, false)
        val text = collectText(view)

        assertFalse(text.contains(activity.getString(R.string.main_ipv6_error_ignored).trim()))
        assertFalse(text.contains("native curl failed"))
    }

    @Test
    fun `cdn pulling response view hides raw error details`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val response = CdnPullingResponse(
            targetLabel = "meduza.io",
            url = "https://meduza.io",
            error = "SSLHandshakeException: certificate path validation failed",
        )

        val view = invokePrivate<View>(activity, "createCdnPullingResponseView", response, false)
        val text = collectText(view)

        assertTrueContains(text, "meduza.io")
        assertTrueContains(text, "https://meduza.io")
        assertTrueContains(text, activity.getString(R.string.main_card_status_error))
        assertFalse(text.contains("SSLHandshakeException"))
        assertFalse(text.contains("certificate path validation failed"))
    }

    @Test
    fun `display category keeps error status and hides error finding text`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val category = CategoryResult(
            name = "direct",
            detected = false,
            needsReview = true,
            findings = listOf(Finding("Socket timeout to 203.0.113.64", isError = true)),
        )
        val card = activity.findViewById<MaterialCardView>(R.id.cardIndirect)
        val icon = activity.findViewById<ImageView>(R.id.iconIndirect)
        val status = activity.findViewById<TextView>(R.id.statusIndirect)
        val findings = activity.findViewById<LinearLayout>(R.id.findingsIndirect)

        invokePrivate<Unit>(
            activity,
            "displayCategory",
            category,
            card,
            icon,
            status,
            findings,
            false,
        )

        assertEquals(activity.getString(R.string.main_card_status_error), status.text.toString())
        assertFalse(collectText(findings).contains("Socket timeout to 203.0.113.64"))
    }

    @Test
    fun `category tile uses error before review`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val category = CategoryResult(
            name = "direct",
            detected = false,
            needsReview = true,
            findings = listOf(Finding("Corrupt Parcel", isError = true)),
        )

        invokePrivate<Unit>(activity, "updateTileFromCategory", "dir", category)

        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val directTile = tiles.getValue("dir")
        val hint = getPrivateField<TextView>(directTile, "hint")
        val header = getPrivateField<View>(directTile, "header")

        assertEquals(activity.getString(R.string.tile_hint_error), hint.text.toString())
        assertTrueContains(header.contentDescription.toString(), activity.getString(R.string.main_card_status_error))
        assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.bodyDirect).visibility)
    }

    @Test
    fun `ip comparison error status reaches card and tile`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val result = IpComparisonResult(
            detected = false,
            needsReview = true,
            hasError = true,
            summary = "ip comparison failed",
            ruGroup = emptyIpCheckerGroup("RU"),
            nonRuGroup = emptyIpCheckerGroup("NON_RU"),
        )

        invokePrivate<Unit>(activity, "displayIpComparison", result, false)
        invokePrivate<Unit>(activity, "updateTileFromIpComparison", result)

        assertEquals(activity.getString(R.string.main_card_status_error), activity.findViewById<TextView>(R.id.statusIpComparison).text.toString())
        assertEquals(activity.getString(R.string.tile_hint_error), tileHint(activity, "ipc"))
    }

    @Test
    fun `cdn pulling error status reaches card and tile`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val result = CdnPullingResult(
            detected = false,
            needsReview = true,
            hasError = true,
            summary = "cdn failed",
            findings = listOf(Finding("cdn failed", isError = true)),
        )

        invokePrivate<Unit>(activity, "displayCdnPulling", result, false)
        invokePrivate<Unit>(activity, "updateTileFromCdn", result)

        assertEquals(activity.getString(R.string.main_card_status_error), activity.findViewById<TextView>(R.id.statusCdnPulling).text.toString())
        assertEquals(activity.getString(R.string.tile_hint_error), tileHint(activity, "cdn"))
    }

    @Test
    fun `bypass error finding reaches card and tile`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val result = BypassResult(
            proxyEndpoint = null,
            directIp = null,
            proxyIp = null,
            xrayApiScanResult = null,
            findings = listOf(Finding("bypass failed", isError = true)),
            detected = false,
            needsReview = true,
        )

        invokePrivate<Unit>(activity, "displayBypass", result, false)
        invokePrivate<Unit>(activity, "updateTileFromBypass", result)

        assertEquals(activity.getString(R.string.main_card_status_error), activity.findViewById<TextView>(R.id.statusBypass).text.toString())
        assertEquals(activity.getString(R.string.tile_hint_error), tileHint(activity, "byp"))
    }

    @Test
    fun `call transport error status reaches card and tile`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val leak = CallTransportLeakResult(
            service = CallTransportService.TELEGRAM,
            probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
            networkPath = CallTransportNetworkPath.ACTIVE,
            status = CallTransportStatus.ERROR,
            summary = "stun failed",
        )

        invokePrivate<Unit>(activity, "displayCallTransport", listOf(leak), emptyList<Any>(), false)
        invokePrivate<Unit>(activity, "updateTileFromCallTransport", listOf(leak), emptyList<Any>())

        assertEquals(activity.getString(R.string.main_card_status_error), activity.findViewById<TextView>(R.id.statusCallTransport).text.toString())
        assertEquals(activity.getString(R.string.tile_hint_error), tileHint(activity, "stn"))
    }

    @Test
    fun `collapsed tiles keep placeholder hint before start`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val geoHint = getPrivateField<TextView>(tiles.getValue("geo"), "hint")
        val callTransportHint = getPrivateField<TextView>(tiles.getValue("stn"), "hint")

        assertEquals(activity.getString(R.string.tile_hint_placeholder), geoHint.text.toString())
        assertEquals(activity.getString(R.string.tile_hint_placeholder), callTransportHint.text.toString())
    }

    @Test
    fun `expanding direct signs before start shows loading description only in body`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val directHint = getPrivateField<TextView>(tiles.getValue("dir"), "hint")

        invokePrivate<Unit>(activity, "expandCategory", "dir")

        val bodyText = collectText(activity.findViewById(R.id.bodyDirect))

        assertEquals(activity.getString(R.string.tile_hint_placeholder), directHint.text.toString())
        assertTrueContains(bodyText, activity.getString(R.string.main_preview_direct))
    }

    @Test
    fun `expanding call transport before start shows loading description only in body`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val callTransportHint = getPrivateField<TextView>(tiles.getValue("stn"), "hint")

        invokePrivate<Unit>(activity, "expandCategory", "stn")

        val bodyText = collectText(activity.findViewById(R.id.bodyCallTransport))

        assertEquals(activity.getString(R.string.tile_hint_placeholder), callTransportHint.text.toString())
        assertTrueContains(bodyText, activity.getString(R.string.main_preview_call_transport))
    }

    @Test
    fun `expanding call transport during running shows active loading description`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()

        invokePrivate<Unit>(
            activity,
            "prepareCheckSessionUi",
            CheckSettings(callTransportProbeEnabled = true),
            false,
        )
        invokePrivate<Unit>(activity, "expandCategory", "stn")

        val bodyText = collectText(activity.findViewById(R.id.bodyCallTransport))

        assertTrueContains(bodyText, activity.getString(R.string.main_loading_call_transport))
    }

    @Test
    fun `prepare check session shows loading hint for call transport tile when probe enabled`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()

        invokePrivate<Unit>(
            activity,
            "prepareCheckSessionUi",
            CheckSettings(callTransportProbeEnabled = true),
            false,
        )

        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val callTransportTile = tiles.getValue("stn")
        val hint = getPrivateField<TextView>(callTransportTile, "hint")

        assertEquals(activity.getString(R.string.tile_hint_loading), hint.text.toString())
    }

    @Test
    fun `prepare check session shows loading hint for icmp tile when network checks are enabled`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()

        invokePrivate<Unit>(
            activity,
            "prepareCheckSessionUi",
            CheckSettings(networkRequestsEnabled = true),
            false,
        )

        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val icmpTile = tiles.getValue("icmp")
        val hint = getPrivateField<TextView>(icmpTile, "hint")

        assertEquals(activity.getString(R.string.tile_hint_loading), hint.text.toString())
    }

    @Test
    fun `prepare check session resets native signs tile to loading on rerun`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val nativeResult = CategoryResult(
            name = "native",
            detected = true,
            findings = listOf(Finding("getifaddrs(): 2 из 3 выявлено", detected = true)),
        )

        invokePrivate<Unit>(activity, "updateTileFromCategory", "nat", nativeResult)
        invokePrivate<Unit>(
            activity,
            "prepareCheckSessionUi",
            CheckSettings(),
            false,
        )

        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val nativeTile = tiles.getValue("nat")
        val hint = getPrivateField<TextView>(nativeTile, "hint")
        val status = activity.findViewById<TextView>(R.id.statusNativeSigns)

        assertEquals(activity.getString(R.string.tile_hint_loading), hint.text.toString())
        assertEquals(activity.getString(R.string.main_loading_status_checking), status.text.toString())
    }

    @Test
    fun `ip channel row shows family together with channel metadata`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val observedIp = ObservedIp(
            value = "203.0.113.64",
            family = IpFamily.V4,
            channel = Channel.VPN,
            sources = setOf("underlying-prober.non-ru.vpn"),
            countryCode = "FI",
            asn = "AS64502 Example VPN",
            targetGroup = TargetGroup.NON_RU,
        )

        val view = invokePrivate<View>(activity, "createIpChannelRow", observedIp, false)
        val text = collectText(view)

        assertTrueContains(text, activity.getString(R.string.ip_channels_channel_vpn))
        assertTrueContains(text, activity.getString(R.string.ip_channels_target_non_ru))
        assertTrueContains(text, "203.0.113.64")
        assertTrueContains(text, "AS64502 Example VPN")
        assertTrueContains(text, activity.getString(R.string.main_card_call_transport_stun_ipv4))
    }

    @Test
    fun `accordion expands categories inline without collapsing previous body`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val geoBody = activity.findViewById<View>(R.id.bodyGeoIp)
        val bypassBody = activity.findViewById<View>(R.id.bodyBypass)

        invokePrivate<Unit>(activity, "expandCategory", "geo")
        assertEquals(View.VISIBLE, geoBody.visibility)
        assertEquals(View.GONE, bypassBody.visibility)
        assertTrue(getPrivateField<Set<String>>(activity, "expandedCategoryIds").contains("geo"))

        invokePrivate<Unit>(activity, "expandCategory", "byp")
        assertEquals(View.VISIBLE, geoBody.visibility)
        assertEquals(View.VISIBLE, bypassBody.visibility)
        val expanded = getPrivateField<Set<String>>(activity, "expandedCategoryIds")
        assertTrue(expanded.contains("geo"))
        assertTrue(expanded.contains("byp"))
    }

    @Test
    fun `tile auto expands when status becomes review or detected`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val geoBody = activity.findViewById<View>(R.id.bodyGeoIp)
        val bypassBody = activity.findViewById<View>(R.id.bodyBypass)
        val reviewResult = BypassResult(
            proxyEndpoint = null,
            directIp = null,
            proxyIp = null,
            xrayApiScanResult = null,
            findings = listOf(Finding("Needs review")),
            detected = false,
            needsReview = true,
        )
        val detectedResult = reviewResult.copy(
            findings = listOf(Finding("Detected", detected = true)),
            detected = true,
            needsReview = false,
        )
        val geoDetectedCategory = CategoryResult(
            name = "geo",
            detected = true,
            findings = listOf(Finding("Geo detected", detected = true)),
        )

        invokePrivate<Unit>(activity, "updateTileFromBypass", reviewResult)
        assertEquals(View.VISIBLE, bypassBody.visibility)
        assertTrue(getPrivateField<Set<String>>(activity, "expandedCategoryIds").contains("byp"))

        invokePrivate<Unit>(activity, "collapseCategory", "byp")
        assertEquals(View.GONE, bypassBody.visibility)

        invokePrivate<Unit>(activity, "updateTileFromCategory", "geo", geoDetectedCategory)
        assertEquals(View.VISIBLE, geoBody.visibility)
        assertTrue(getPrivateField<Set<String>>(activity, "expandedCategoryIds").contains("geo"))

        invokePrivate<Unit>(activity, "updateTileFromBypass", detectedResult)
        assertEquals(View.VISIBLE, bypassBody.visibility)
        assertTrue(getPrivateField<Set<String>>(activity, "expandedCategoryIds").contains("byp"))
    }

    @Test
    fun `tile status uses semantic shape in color vision mode`() {
        AppUiSettings.prefs(context).edit()
            .putString(SettingsPrefs.PREF_COLOR_VISION_MODE, ColorVisionMode.RED_GREEN.prefValue)
            .commit()
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()

        invokePrivate<Unit>(activity, "setTileStatus", "geo", 3, activity.getString(R.string.tile_hint_review))

        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val geoTile = tiles.getValue("geo")
        val statusDot = getPrivateField<View>(geoTile, "statusDot")
        val header = getPrivateField<View>(geoTile, "header")

        assertTrue(statusDot.background is StatusShapeDrawable)
        assertEquals(
            StatusIndicatorShape.DIAMOND,
            (statusDot.background as StatusShapeDrawable).indicatorShape,
        )
        assertTrueContains(
            header.contentDescription.toString(),
            activity.getString(R.string.main_card_status_detected),
        )
    }

    @Test
    fun `finding row exposes text status and semantic indicator`() {
        AppUiSettings.prefs(context).edit()
            .putString(SettingsPrefs.PREF_COLOR_VISION_MODE, ColorVisionMode.ACHROMATOPSIA.prefValue)
            .commit()
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val finding = Finding("Detected signal", detected = true)

        val row = invokePrivate<View>(activity, "createFindingView", finding, false) as ViewGroup
        val indicator = row.getChildAt(0)

        assertTrue(indicator.background is StatusShapeDrawable)
        assertEquals(
            StatusIndicatorShape.DIAMOND,
            (indicator.background as StatusShapeDrawable).indicatorShape,
        )
        assertTrueContains(
            row.contentDescription.toString(),
            activity.getString(R.string.main_card_status_detected),
        )
    }

    @Test
    fun `beta finding UI and accessibility use exactly one prefix`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        for (description in listOf("signal", "β signal")) {
            val finding = Finding(description, maturity = EvidenceMaturity.BETA)
            val row = invokePrivate<View>(activity, "createFindingView", finding, false) as ViewGroup

            assertEquals(1, "β signal".toRegex().findAll(row.contentDescription.toString()).count())
            assertTrueContains(row.contentDescription.toString(), "β signal")
        }
    }

    @Test
    fun `completed event refreshes reconciled cdn and icmp cards`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val rawCdn = CdnPullingResult(
            detected = true,
            needsReview = true,
            summary = "Raw CDN signal",
            responses = listOf(
                CdnPullingResponse(
                    targetLabel = "meduza.io",
                    url = "https://meduza.io/cdn-cgi/trace",
                    ip = "203.0.113.64",
                ),
            ),
        )
        val rawIcmp = CategoryResult(
            name = "icmp",
            detected = false,
            findings = listOf(Finding("Raw ICMP signal", needsReview = true)),
            needsReview = true,
            evidence = listOf(
                EvidenceItem(
                    source = EvidenceSource.ICMP_SPOOFING,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Blocked target replied",
                ),
            ),
        )

        invokePrivate<Unit>(activity, "displayCdnPulling", rawCdn, false)
        invokePrivate<Unit>(activity, "updateTileFromCdn", rawCdn)
        invokePrivate<Unit>(
            activity,
            "displayCategory",
            rawIcmp,
            activity.findViewById<MaterialCardView>(R.id.cardIcmpSpoofing),
            activity.findViewById<ImageView>(R.id.iconIcmpSpoofing),
            activity.findViewById<TextView>(R.id.statusIcmpSpoofing),
            activity.findViewById<LinearLayout>(R.id.findingsIcmpSpoofing),
            false,
        )
        invokePrivate<Unit>(activity, "updateTileFromCategory", "icmp", rawIcmp)

        val finalCdn = rawCdn.copy(detected = false, needsReview = false, summary = "Reconciled CDN signal")
        val finalIcmp = rawIcmp.copy(
            findings = listOf(Finding("Reconciled ICMP signal", isInformational = true)),
            needsReview = false,
            evidence = emptyList(),
        )
        invokePrivate<Unit>(
            activity,
            "applyScanEvent",
            ScanEvent.Completed(
                checkResult(cdnPulling = finalCdn, icmpSpoofing = finalIcmp),
                privacyMode = false,
            ),
            false,
        )

        assertEquals(activity.getString(R.string.main_card_status_clean), activity.findViewById<TextView>(R.id.statusCdnPulling).text.toString())
        assertEquals(activity.getString(R.string.tile_hint_clean_count, 1), tileHint(activity, "cdn"))
        assertEquals(activity.getString(R.string.main_card_status_clean), activity.findViewById<TextView>(R.id.statusIcmpSpoofing).text.toString())
        assertEquals(activity.getString(R.string.tile_hint_clean), tileHint(activity, "icmp"))
    }

    @Test
    fun `completed event shows home routed roaming note in verdict hero`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).setup().get()
        val location = category("location").copy(
            locationFacts = LocationSignalsFacts(
                networkMcc = "250",
                networkIsRussia = true,
                homeSimMcc = "208",
                homeSimCountryIso = "FR",
                homeSimOperatorName = "Free Mobile",
                homeRoutedRoaming = true,
            ),
        )

        invokePrivate<Unit>(
            activity,
            "applyScanEvent",
            ScanEvent.Completed(
                checkResult(locationSignals = location),
                privacyMode = false,
            ),
            false,
        )

        val note = activity.findViewById<TextView>(R.id.verdictHomeRoutedRoamingNote)
        assertEquals(View.VISIBLE, note.visibility)
        assertTrueContains(note.text.toString(), "Free Mobile")
        assertTrueContains(note.text.toString(), "FR")
    }

    private fun collectText(view: View): String {
        if (view is TextView) return view.text.toString()
        if (view !is ViewGroup) return ""
        return buildString {
            for (index in 0 until view.childCount) {
                val childText = collectText(view.getChildAt(index))
                if (childText.isBlank()) continue
                if (isNotBlank()) append('\n')
                append(childText)
            }
        }
    }

    private fun assertTrueContains(text: String, expected: String) {
        assertFalse("Expected text to contain <$expected>, got <$text>", !text.contains(expected))
    }

    private fun tileHint(activity: MainActivity, id: String): String {
        val tiles = getPrivateField<Map<String, Any>>(activity, "tiles")
        val tile = tiles.getValue(id)
        return getPrivateField<TextView>(tile, "hint").text.toString()
    }

    private fun emptyIpCheckerGroup(title: String): IpCheckerGroupResult {
        return IpCheckerGroupResult(
            title = title,
            detected = false,
            statusLabel = "",
            summary = "",
            responses = emptyList(),
        )
    }

    private fun checkResult(
        cdnPulling: CdnPullingResult = CdnPullingResult.empty(),
        icmpSpoofing: CategoryResult = category("icmp"),
        locationSignals: CategoryResult = category("location"),
        verdict: Verdict = Verdict.NOT_DETECTED,
    ): CheckResult {
        return CheckResult(
            geoIp = category("geo"),
            ipComparison = IpComparisonResult(
                detected = false,
                summary = "",
                ruGroup = emptyIpCheckerGroup("RU"),
                nonRuGroup = emptyIpCheckerGroup("NON_RU"),
            ),
            cdnPulling = cdnPulling,
            directSigns = category("direct"),
            indirectSigns = category("indirect"),
            locationSignals = locationSignals,
            bypassResult = BypassResult(
                proxyEndpoint = null,
                directIp = null,
                proxyIp = null,
                xrayApiScanResult = null,
                findings = emptyList(),
                detected = false,
            ),
            verdict = verdict,
            icmpSpoofing = icmpSpoofing,
            ipConsensus = IpConsensusResult.empty(),
        )
    }

    private fun category(name: String): CategoryResult {
        return CategoryResult(
            name = name,
            detected = false,
            findings = emptyList(),
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getPrivateField(target: Any, name: String): T {
        val field = target::class.java.getDeclaredField(name)
        field.isAccessible = true
        return field.get(target) as T
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> invokePrivate(target: Any, name: String, vararg args: Any?): T {
        val method = target::class.java.declaredMethods.first { candidate ->
            candidate.name == name && candidate.parameterTypes.size == args.size
        }
        method.isAccessible = true
        return method.invoke(target, *args) as T
    }
}
