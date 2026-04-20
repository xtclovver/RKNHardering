package com.notcvnt.rknhardering

import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Channel
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import com.notcvnt.rknhardering.model.IpFamily
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.ObservedIp
import com.notcvnt.rknhardering.model.TargetGroup
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MainActivityUiRenderingTest {

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
