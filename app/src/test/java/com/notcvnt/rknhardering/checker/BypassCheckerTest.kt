package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.probe.LocalSocketListener
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BypassCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `explicit vpn network binding on non vpn default network is detected`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "198.51.100.10",
                underlyingIp = "203.0.113.20",
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(outcome.detected)
        assertFalse(outcome.needsReview)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertTrue(findings.any { it.description.contains("VPN network binding") })
    }

    @Test
    fun `underlying reachability is treated as gateway leak only when default network is vpn`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "198.51.100.10",
                underlyingIp = "203.0.113.20",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(outcome.detected)
        assertFalse(outcome.needsReview)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
    }

    @Test
    fun `tun probe success is reported as informational finding`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = "198.51.100.10",
                underlyingIp = null,
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(
            findings.any {
                it.isInformational &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.description.contains("198.51.100.10")
            },
        )
    }

    @Test
    fun `vpn network binding requires verified underlying internet path`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = "198.51.100.10",
                underlyingIp = null,
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(
            findings.any {
                it.needsReview &&
                    it.source == EvidenceSource.VPN_NETWORK_BINDING &&
                    it.description.contains("manual review")
            },
        )
    }

    @Test
    fun `tun probe failure reason is recorded when vpn path fails`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = null,
                underlyingIp = null,
                vpnError = "timeout",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(
            findings.any {
                it.isInformational &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.description.contains("timeout")
            },
        )
    }

    @Test
    fun `gateway leak requires vpn and underlying ip comparison`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = null,
                underlyingIp = "203.0.113.20",
                vpnError = "timeout",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(
            findings.any {
                it.source == EvidenceSource.VPN_GATEWAY_LEAK &&
                    it.needsReview &&
                    it.description.contains("203.0.113.20")
            },
        )
    }

    @Test
    fun `gateway leak falls back to manual review on mixed ip families`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "2001:db8::10",
                underlyingIp = "203.0.113.20",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(findings.any { it.needsReview && it.description.contains("different IP families") })
    }

    @Test
    fun `gateway leak not detected when vpn ip and underlying ip are the same`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "128.71.10.5",
                underlyingIp = "128.71.10.5",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(findings.any { it.isInformational && it.source == EvidenceSource.VPN_GATEWAY_LEAK })
    }

    @Test
    fun `vpn network binding is not detected when default and vpn ips match`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "203.0.113.10",
                underlyingIp = "203.0.113.10",
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertFalse(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(findings.any { it.isInformational && it.source == EvidenceSource.VPN_NETWORK_BINDING })
    }

    @Test
    fun `vpn network binding falls back to manual review on mixed ip families`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val outcome = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "2001:db8::10",
                underlyingIp = "203.0.113.20",
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(outcome.detected)
        assertTrue(outcome.needsReview)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(findings.any { it.needsReview && it.description.contains("different IP families") })
    }

    @Test
    fun `proxy owner matches exact host and port`() {
        val owner = owner(uid = 10123, packageName = "com.whatsapp", appLabel = "WhatsApp")

        val match = BypassChecker.matchProxyOwner(
            proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            listeners = listOf(
                listener(host = "127.0.0.1", port = 1080, owner = owner),
                listener(host = "0.0.0.0", port = 1080, owner = null),
            ),
        )

        assertEquals(BypassChecker.ProxyOwnerStatus.RESOLVED, match.status)
        assertEquals(owner, match.owner)
    }

    @Test
    fun `proxy owner falls back to any address listener when unique`() {
        val owner = owner(uid = 10124, packageName = "com.whatsapp", appLabel = "WhatsApp")

        val match = BypassChecker.matchProxyOwner(
            proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 8080, type = ProxyType.HTTP),
            listeners = listOf(
                listener(host = "0.0.0.0", port = 8080, owner = owner),
            ),
        )

        assertEquals(BypassChecker.ProxyOwnerStatus.RESOLVED, match.status)
        assertEquals(owner, match.owner)
    }

    @Test
    fun `proxy owner is ambiguous when multiple fallback listeners share a port`() {
        val match = BypassChecker.matchProxyOwner(
            proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 8080, type = ProxyType.HTTP),
            listeners = listOf(
                listener(host = "0.0.0.0", port = 8080, owner = owner(uid = 10125, packageName = "com.first", appLabel = "First")),
                listener(host = "::", port = 8080, protocol = "tcp6", owner = owner(uid = 10126, packageName = "com.second", appLabel = "Second")),
            ),
        )

        assertEquals(BypassChecker.ProxyOwnerStatus.AMBIGUOUS, match.status)
        assertNull(match.owner)
    }

    private fun listener(
        host: String,
        port: Int,
        protocol: String = "tcp",
        owner: LocalProxyOwner?,
    ): LocalSocketListener = LocalSocketListener(
        protocol = protocol,
        host = host,
        port = port,
        state = "0A",
        uid = owner?.uid,
        inode = 0L,
        owner = owner,
    )

    private fun owner(uid: Int, packageName: String, appLabel: String): LocalProxyOwner = LocalProxyOwner(
        uid = uid,
        packageNames = listOf(packageName),
        appLabels = listOf(appLabel),
        confidence = com.notcvnt.rknhardering.model.EvidenceConfidence.HIGH,
    )
}
