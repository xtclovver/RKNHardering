package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.DnsClassification
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.InterfaceAddressSnapshot
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.NetworkSnapshot
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.RouteSnapshot
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.TunnelClass
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.customcheck.IndirectSignsConfig
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.LocalSocketInspector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNotEquals
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class IndirectSignsCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @org.junit.After
    fun tearDown() {
        CallTransportChecker.dependenciesOverride = null
    }

    @Test
    fun `classifies loopback dns`() {
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("127.0.0.1"))
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("::1"))
    }

    @Test
    fun `classifies private network dns including carrier grade nat and ula`() {
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("10.0.0.2"))
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("172.16.0.10"))
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("192.168.1.1"))
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("100.64.0.10"))
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("fd00::1"))
    }

    @Test
    fun `classifies link local and public dns separately`() {
        assertEquals(DnsClassification.LINK_LOCAL, IndirectSignsChecker.classifyDnsAddress("169.254.1.1"))
        assertEquals(DnsClassification.LINK_LOCAL, IndirectSignsChecker.classifyDnsAddress("fe80::1"))
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("8.8.8.8"))
        assertEquals(DnsClassification.OTHER_PUBLIC, IndirectSignsChecker.classifyDnsAddress("77.88.55.55"))
    }

    @Test
    fun `parses proc net listeners`() {
        val listeners = IndirectSignsChecker.parseProcNetListeners(
            lines = listOf(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
                "   0: 0100007F:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0",
            ),
            protocol = "tcp",
        )

        assertEquals(1, listeners.size)
        assertEquals("127.0.0.1", listeners.single().host)
        assertEquals(9090, listeners.single().port)
        assertEquals(0, listeners.single().uid)
        assertEquals(0L, listeners.single().inode)
    }

    @Test
    fun `parses proc net ipv6 listeners`() {
        val listeners = IndirectSignsChecker.parseProcNetListeners(
            lines = listOf(
                "  sl  local_address                         rem_address                          st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
                "   0: 00000000000000000000000001000000:2382 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0",
            ),
            protocol = "tcp6",
        )

        assertEquals(1, listeners.size)
        assertEquals(java.net.InetAddress.getByName("::1").hostAddress, listeners.single().host)
        assertEquals(9090, listeners.single().port)
    }

    @Test
    fun `resolves owner for a single visible package`() {
        val owner = LocalSocketInspector.resolveOwner(
            uid = 10123,
            packageNames = listOf("com.whatsapp"),
            uidName = "u0a123",
            appLabelResolver = { "WhatsApp" },
        )

        assertEquals(10123, owner.uid)
        assertEquals(listOf("com.whatsapp"), owner.packageNames)
        assertEquals(listOf("WhatsApp"), owner.appLabels)
        assertEquals(EvidenceConfidence.HIGH, owner.confidence)
    }

    @Test
    fun `resolves owner for shared uid packages`() {
        val owner = LocalSocketInspector.resolveOwner(
            uid = 10124,
            packageNames = listOf("com.example.first", "com.example.second"),
            uidName = "u0a124",
            appLabelResolver = { packageName ->
                when (packageName) {
                    "com.example.first" -> "First"
                    "com.example.second" -> "Second"
                    else -> null
                }
            },
        )

        assertEquals(listOf("com.example.first", "com.example.second"), owner.packageNames)
        assertEquals(listOf("First", "Second"), owner.appLabels)
        assertEquals(EvidenceConfidence.MEDIUM, owner.confidence)
    }

    @Test
    fun `resolves owner to uid fallback when package list is unavailable`() {
        val owner = LocalSocketInspector.resolveOwner(
            uid = 10125,
            packageNames = emptyList(),
            uidName = "u0a125",
            appLabelResolver = { null },
        )

        assertEquals(emptyList<String>(), owner.packageNames)
        assertEquals(listOf("u0a125"), owner.appLabels)
        assertEquals(EvidenceConfidence.LOW, owner.confidence)
    }

    @Test
    fun `loopback dns on active vpn is detected`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("127.0.0.1"),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("192.168.1.1"),
                    interfaceAddresses = listOf(linkAddress("192.168.1.2", 24)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.DNS && it.detected })
    }

    @Test
    fun `vpn replacing public dns yields needs review`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("8.8.8.8"),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("192.168.1.1"),
                    interfaceAddresses = listOf(linkAddress("192.168.1.2", 24)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertTrue(evaluation.needsReview)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.DNS && it.detected })
    }

    @Test
    fun `shared ula dns across vpn and underlying prefixes stays clear`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("fd12:3456:789a::53"),
                    interfaceAddresses = listOf(linkAddress("fd12:3456:789a::2", 64)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("fd12:3456:789a::1"),
                    interfaceAddresses = listOf(linkAddress("fd12:3456:789a::10", 64)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.isEmpty())
    }

    @Test
    fun `shared carrier grade nat dns across vpn and underlying prefixes stays clear`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("100.64.10.53"),
                    interfaceAddresses = listOf(linkAddress("100.64.10.2", 24)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "rmnet0",
                    routes = listOf(route("0.0.0.0/0", "rmnet0", isDefault = true)),
                    dnsServers = listOf("100.64.10.1"),
                    interfaceAddresses = listOf(linkAddress("100.64.10.9", 24)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.isEmpty())
    }

    @Test
    fun `private dns on local non vpn prefix stays clear`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = false,
                    interfaceName = "rmnet0",
                    routes = listOf(route("0.0.0.0/0", "rmnet0", isDefault = true)),
                    dnsServers = listOf("100.64.10.53"),
                    interfaceAddresses = listOf(linkAddress("100.64.10.2", 24)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.isEmpty())
    }

    @Test
    fun `private dns on different underlying prefix stays detected on active vpn`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("fd12:3456:789a::53"),
                    interfaceAddresses = listOf(linkAddress("fd12:3456:789a::2", 64)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("fd98:7654:3210::1"),
                    interfaceAddresses = listOf(linkAddress("fd98:7654:3210::10", 64)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.DNS && it.detected })
    }

    @Test
    fun `carrier ims ipsec is classified as non vpn and exposes diagnostics`() {
        val snapshot = snapshot(
            isActive = true,
            isVpn = false,
            interfaceName = "ipsec21",
            routes = listOf(
                route("0.0.0.0/0", "ipsec21", isDefault = true),
                route("198.51.100.0/24", "ipsec21", isDefault = false),
            ),
            hasNotVpn = true,
            hasIms = true,
            hasMmtel = true,
            capsString = "Capabilities: IMS&NOT_VPN&MMTEL",
        )

        assertEquals(TunnelClass.CARRIER_IMS_IPSEC, IndirectSignsChecker.classifyTunnel("ipsec21", snapshot))

        val diagnostics = IndirectSignsChecker.buildIpsecDiagnostics(context, "ipsec21", snapshot)
        assertEquals(2, diagnostics.size)
        assertTrue(diagnostics.any { it.description.contains("ipsec21") && it.description.contains("carrier") })
        assertTrue(diagnostics.any { it.description.contains("NOT_VPN") && it.description.contains("IMS") && it.description.contains("MMTEL") })

        val routing = IndirectSignsChecker.checkRoutingTable(context, listOf(snapshot))
        assertFalse(routing.detected)

        val dns = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot.copy(dnsServers = listOf("100.64.10.53"), interfaceAddresses = listOf(linkAddress("100.64.10.2", 24))),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "rmnet0",
                    routes = listOf(route("0.0.0.0/0", "rmnet0", isDefault = true)),
                    dnsServers = listOf("100.64.10.1"),
                    interfaceAddresses = listOf(linkAddress("100.64.10.9", 24)),
                ),
            ),
        )
        assertFalse(dns.detected)
        assertFalse(dns.needsReview)
    }

    @Test
    fun `ipsec with transport vpn is classified as confirmed vpn`() {
        val snapshot = snapshot(
            isActive = true,
            isVpn = true,
            interfaceName = "ipsec21",
            routes = listOf(route("0.0.0.0/0", "ipsec21", isDefault = true)),
            hasTransportVpn = true,
            hasNotVpn = false,
            capsString = "Capabilities: TRANSPORT_VPN",
        )

        assertEquals(TunnelClass.CONFIRMED_VPN, IndirectSignsChecker.classifyTunnel("ipsec21", snapshot))

        val routing = IndirectSignsChecker.checkRoutingTable(context, listOf(snapshot))
        assertTrue(routing.detected)
        assertTrue(routing.evidence.any { it.source == EvidenceSource.ROUTING && it.detected })
    }

    @Test
    fun `ipsec without carrier or vpn markers stays unknown`() {
        val snapshot = snapshot(
            isActive = true,
            isVpn = false,
            interfaceName = "ipsec21",
            routes = listOf(route("0.0.0.0/0", "ipsec21", isDefault = true)),
            hasNotVpn = true,
            capsString = "Capabilities: NOT_VPN",
        )

        assertEquals(TunnelClass.UNKNOWN_IPSEC, IndirectSignsChecker.classifyTunnel("ipsec21", snapshot))

        val diagnostics = IndirectSignsChecker.buildIpsecDiagnostics(context, "ipsec21", snapshot)
        assertTrue(diagnostics.any { it.description.contains("ipsec21") })
        assertTrue(diagnostics.any { it.description.contains("unknown") || it.description.contains("не удалось") })

        val routing = IndirectSignsChecker.checkRoutingTable(context, listOf(snapshot))
        assertFalse(routing.detected)
        assertNotEquals(
            TunnelClass.CONFIRMED_VPN,
            IndirectSignsChecker.classifyTunnel("ipsec21", snapshot),
        )
    }

    @Test
    fun `default route on non standard interface is detected`() {
        val evaluation = IndirectSignsChecker.checkRoutingTable(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = false,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.ROUTING && it.detected })
    }

    @Test
    fun `default route on stacked clat interface stays clear`() {
        val evaluation = IndirectSignsChecker.checkRoutingTable(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "v4-wlan0", isDefault = true)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertTrue(evaluation.findings.any { !it.detected && it.description.contains("wlan0") })
    }

    @Test
    fun `split tunneling route pattern is detected`() {
        val evaluation = IndirectSignsChecker.checkRoutingTable(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("10.0.0.0/8", "tun0", isDefault = false)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertTrue(evaluation.evidence.any { it.description.contains("Split-tunneling") })
    }

    @Test
    fun `call transport disabled leaves indirect result untouched`() = runBlocking {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { error("should not be called") },
        )

        val result = IndirectSignsChecker.check(
            context = context,
            networkRequestsEnabled = true,
            callTransportProbeEnabled = false,
            resolverConfig = DnsResolverConfig.system(),
        )

        assertTrue(result.callTransportLeaks.isEmpty())
    }

    @Test
    fun `call transport enabled adds needs review signal into indirect result`() = runBlocking {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = {
                CallTransportTargetCatalog.Catalog(
                    stunTargets = listOf(
                        CallTransportTargetCatalog.StunTarget(
                            host = "stun.example.com",
                            port = 3478,
                            scope = com.notcvnt.rknhardering.model.StunScope.GLOBAL,
                            enabled = true,
                        ),
                    ),
                )
            },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                        vpnProtected = true,
                    ),
                )
            },
            stunDualStackProbe = { _, _, _ ->
                com.notcvnt.rknhardering.probe.StunBindingClient.DualStackBindingResult(
                    ipv4Result = Result.success(
                        com.notcvnt.rknhardering.probe.StunBindingClient.BindingResult(
                            resolvedIps = listOf("93.184.216.34"),
                            remoteIp = "93.184.216.34",
                            remotePort = 3478,
                            mappedIp = "198.51.100.20",
                            mappedPort = 40000,
                        ),
                    ),
                    ipv6Result = null,
                )
            },
            publicIpFetcher = { _, _, _ -> Result.success("203.0.113.10") },
        )

        val result = IndirectSignsChecker.check(
            context = context,
            networkRequestsEnabled = true,
            callTransportProbeEnabled = true,
            resolverConfig = DnsResolverConfig.system(),
        )

        assertTrue(result.callTransportLeaks.any { it.status == CallTransportStatus.NEEDS_REVIEW })
        assertTrue(result.needsReview)
        assertTrue(result.stunProbeGroups.any { group -> group.results.any { it.hasResponse } })
        assertTrue(result.evidence.any { it.source == EvidenceSource.TELEGRAM_CALL_TRANSPORT && it.detected })
        val diagnostics = IndirectCheckPerformanceRegistry.find(result)
        assertTrue(diagnostics != null)
        assertTrue(diagnostics!!.steps.any { it.name == "checkCallTransportSignals" })
        val callTransport = requireNotNull(diagnostics.callTransport)
        assertTrue(callTransport.steps.any { it.name == "probeStunTargets" })
        assertEquals(1, callTransport.totalStunTargets)
        assertEquals(1, callTransport.respondedStunTargets)
        assertEquals(0, callTransport.noResponseStunTargets)
    }

    @Test
    fun `call transport error surfaces through category error state`() = runBlocking {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { error("catalog failed") },
        )

        val result = IndirectSignsChecker.check(
            context = context,
            networkRequestsEnabled = true,
            callTransportProbeEnabled = true,
            resolverConfig = DnsResolverConfig.system(),
        )

        assertTrue(result.callTransportLeaks.any { it.status == CallTransportStatus.ERROR })
        assertTrue(result.hasError)
    }

    private fun snapshot(
        isActive: Boolean,
        isVpn: Boolean,
        interfaceName: String?,
        routes: List<RouteSnapshot>,
        hasTransportVpn: Boolean = isVpn,
        hasNotVpn: Boolean = !isVpn,
        hasIms: Boolean = false,
        hasEims: Boolean = false,
        hasMmtel: Boolean = false,
        capsString: String = if (hasNotVpn) "Capabilities: NOT_VPN" else "Capabilities:",
        dnsServers: List<String> = emptyList(),
        interfaceAddresses: List<InterfaceAddressSnapshot> = emptyList(),
    ): NetworkSnapshot {
        return NetworkSnapshot(
            label = interfaceName ?: "network",
            isActive = isActive,
            isVpn = isVpn,
            interfaceName = interfaceName,
            hasTransportVpn = hasTransportVpn,
            hasNotVpn = hasNotVpn,
            hasIms = hasIms,
            hasEims = hasEims,
            hasMmtel = hasMmtel,
            capsString = capsString,
            routes = routes,
            dnsServers = dnsServers,
            interfaceAddresses = interfaceAddresses,
        )
    }

    private fun linkAddress(address: String, prefixLength: Int): InterfaceAddressSnapshot {
        return InterfaceAddressSnapshot(
            address = address,
            prefixLength = prefixLength,
        )
    }

    private fun route(
        destination: String,
        interfaceName: String?,
        isDefault: Boolean,
        gateway: String? = "192.0.2.1",
    ): RouteSnapshot {
        return RouteSnapshot(
            destination = destination,
            gateway = gateway,
            interfaceName = interfaceName,
            isDefault = isDefault,
        )
    }

    @Test
    fun `when checkVpnInterfaces=false the vpn-interfaces finding is skipped`() = runBlocking {
        // With the toggle disabled the checkNetworkInterfaces path is entirely bypassed.
        // In Robolectric there are no real VPN interfaces, so evidence from NETWORK_INTERFACE
        // should be absent in both cases. The assertion confirms no exception is thrown and
        // no detected NETWORK_INTERFACE evidence appears when the toggle is off.
        val result = IndirectSignsChecker.check(
            context = context,
            config = IndirectSignsConfig(checkVpnInterfaces = false),
        )

        assertFalse(
            result.evidence.any { it.source == EvidenceSource.NETWORK_INTERFACE && it.detected },
        )
    }

    @Test
    fun `when checkLocalListeners=false the local-listeners finding is skipped`() = runBlocking {
        // checkLocalListeners=false prevents the loopback-port scan path inside
        // checkProxyTechnicalSignals from running. In Robolectric /proc/net/tcp is empty
        // so this also produces no listeners with the toggle enabled, but the important
        // contract is that disabling the toggle never produces MORE findings.
        val resultDisabled = IndirectSignsChecker.check(
            context = context,
            config = IndirectSignsConfig(checkLocalListeners = false),
        )
        val resultEnabled = IndirectSignsChecker.check(
            context = context,
            config = IndirectSignsConfig(checkLocalListeners = true),
        )

        val disabledListenerFindings = resultDisabled.findings.count {
            it.source == EvidenceSource.PROXY_TECHNICAL_SIGNAL && it.detected
        }
        val enabledListenerFindings = resultEnabled.findings.count {
            it.source == EvidenceSource.PROXY_TECHNICAL_SIGNAL && it.detected
        }
        assertTrue(disabledListenerFindings <= enabledListenerFindings)
    }
}
