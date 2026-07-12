package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SupportingBetaCheckerTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `direct proxy selection is authoritative negative`() {
        val observation = SupportingBetaChecker.proxySelectorObservation(
            context,
            "epoch",
            1L,
            FixedProxySelector(listOf(Proxy.NO_PROXY)),
        )

        assertEquals(ProbeAvailability.AVAILABLE, observation.availability)
        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, observation.polarity)
    }

    @Test
    fun `configured proxy is medium positive without claiming vpn bypass`() {
        val observation = SupportingBetaChecker.proxySelectorObservation(
            context,
            "epoch",
            1L,
            FixedProxySelector(listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", 8080)))),
        )

        assertEquals(ProbeAvailability.AVAILABLE, observation.availability)
        assertEquals(ObservationPolarity.POSITIVE, observation.polarity)
    }

    @Test
    fun `route used tunnel driver is positive but ordinary interface is neutral`() {
        val tunnel = SupportingBetaChecker.evaluateInterfaceDriver(
            context,
            "net0",
            listOf("DEVTYPE=wireguard", "up"),
            "epoch",
            1L,
        )
        val ordinary = SupportingBetaChecker.evaluateInterfaceDriver(
            context,
            "wlan0",
            listOf("DEVTYPE=wlan", "up"),
            "epoch",
            1L,
        )

        assertEquals(ObservationPolarity.POSITIVE, tunnel.polarity)
        assertEquals(ObservationPolarity.INCONCLUSIVE, ordinary.polarity)
    }

    @Test
    fun `controlled canary counter growth is correlated without exposing interface name`() {
        val observation = SupportingBetaChecker.interfaceTrafficObservation(
            context,
            SupportingBetaChecker.InterfaceTrafficSample("wg0", 10, 20),
            SupportingBetaChecker.InterfaceTrafficSample("wg0", 110, 20),
            canaryTransferred = true,
            epochId = "epoch",
            at = 1L,
        )

        assertEquals(ProbeAvailability.AVAILABLE, observation.availability)
        assertEquals(ObservationPolarity.POSITIVE, observation.polarity)
        assertEquals(false, observation.facts.values.any { it.contains("wg0") })
    }

    private class FixedProxySelector(private val proxies: List<Proxy>) : ProxySelector() {
        override fun select(uri: URI?): List<Proxy> = proxies
        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: IOException?) = Unit
    }
}
