package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.Network
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.customcheck.CallTransportConfig
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.StunScope
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.LocalSocketListener
import com.notcvnt.rknhardering.probe.NativeCurlBridge
import com.notcvnt.rknhardering.probe.ProxyEndpoint
import com.notcvnt.rknhardering.probe.ProxyType
import com.notcvnt.rknhardering.probe.PublicIpClient
import com.notcvnt.rknhardering.probe.Socks5UdpAssociateClient
import com.notcvnt.rknhardering.probe.StunBindingClient
import kotlinx.coroutines.delay
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.system.measureTimeMillis
@RunWith(RobolectricTestRunner::class)
class CallTransportCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun tearDown() {
        CallTransportChecker.dependenciesOverride = null
        PublicIpClient.resetForTests()
        NativeCurlBridge.resetForTests()
    }

    @Test
    fun `proxy assisted telegram stores remote dc as target not local proxy`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            proxyProbe = {
                CallTransportChecker.ProxyProbeOutcome(
                    reachable = true,
                    targetHost = "149.154.167.51",
                    targetPort = 443,
                    observedPublicIp = "203.0.113.10",
                )
            },
            proxyUdpStunProbe = { _, _, _, _ ->
                Result.failure(IllegalStateException("UDP STUN is not part of this scenario"))
            },
        )

        val result = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeProxyAssistedTelegram(
                context = context,
                proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            )
        }

        val tcpResult = result.first { it.probeKind == CallTransportProbeKind.PROXY_ASSISTED_TELEGRAM }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, tcpResult.status)
        assertEquals("149.154.167.51", tcpResult.targetHost)
        assertEquals(443, tcpResult.targetPort)
        assertNull(tcpResult.mappedIp)
        assertEquals("203.0.113.10", tcpResult.observedPublicIp)
    }

    @Test
    fun `proxy assisted telegram adds udp stun signal when udp associate succeeds`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, _ -> Result.success("203.0.113.10") }
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            proxyProbe = {
                CallTransportChecker.ProxyProbeOutcome(reachable = false)
            },
            proxyUdpStunProbe = { _, _, _, _ -> successBindingResult() },
        )

        val results = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeProxyAssistedTelegram(
                context = context,
                proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            )
        }

        val udpResult = results.first { it.probeKind == CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN }
        assertEquals(CallTransportNetworkPath.LOCAL_PROXY, udpResult.networkPath)
        assertEquals(CallTransportStatus.NEEDS_REVIEW, udpResult.status)
        assertEquals("stun.example.com", udpResult.targetHost)
        assertEquals("198.51.100.20", udpResult.mappedIp)
        assertEquals("203.0.113.10", udpResult.observedPublicIp)
    }

    @Test
    fun `proxy assisted telegram auth failures stay as no signal`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            proxyProbe = {
                CallTransportChecker.ProxyProbeOutcome(reachable = false)
            },
            proxyUdpStunProbe = { _, _, _, _ ->
                Result.failure(Socks5UdpAssociateClient.AuthenticationRequiredException())
            },
        )

        val results = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeProxyAssistedTelegram(
                context = context,
                proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            )
        }

        assertTrue(results.all { it.status == CallTransportStatus.NO_SIGNAL })
        assertFalse(results.any { it.status == CallTransportStatus.NEEDS_REVIEW })
    }

    @Test
    fun `check can discover proxy assisted path without bypass ownership`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, _ -> Result.success("203.0.113.10") }
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            loadPaths = { emptyList() },
            findLocalProxyEndpoint = {
                ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5)
            },
            proxyProbe = {
                CallTransportChecker.ProxyProbeOutcome(reachable = false)
            },
            proxyUdpStunProbe = { _, _, _, _ -> successBindingResult() },
        )

        val evaluation = kotlinx.coroutines.runBlocking {
            CallTransportChecker.check(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
                callTransportEnabled = true,
            )
        }

        assertTrue(evaluation.results.any { it.probeKind == CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN })
        assertTrue(evaluation.needsReview)
    }

    @Test
    fun `check runs direct and proxy assisted probes in parallel`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                        vpnProtected = true,
                    ),
                )
            },
            findLocalProxyEndpoint = {
                ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5)
            },
            stunDualStackProbe = { _, _, _ ->
                Thread.sleep(500)
                successDualStackResult()
            },
            publicIpFetcher = { _, _, _ -> Result.success("203.0.113.10") },
            proxyProbe = {
                delay(500)
                CallTransportChecker.ProxyProbeOutcome(
                    reachable = false,
                    observedPublicIp = "203.0.113.10",
                )
            },
            proxyUdpStunProbe = { _, _, _, _ ->
                delay(500)
                successBindingResult()
            },
        )

        val elapsedMs = measureTimeMillis {
            val evaluation = kotlinx.coroutines.runBlocking {
                CallTransportChecker.check(
                    context = context,
                    resolverConfig = DnsResolverConfig.system(),
                    callTransportEnabled = true,
                )
            }

            assertTrue(evaluation.results.any { it.probeKind == CallTransportProbeKind.DIRECT_UDP_STUN })
            assertTrue(evaluation.results.any { it.probeKind == CallTransportProbeKind.PROXY_ASSISTED_UDP_STUN })
        }

        assertTrue("Expected direct and proxy probes to overlap, but took ${elapsedMs}ms", elapsedMs < 1300)
    }

    @Test
    fun `probeDirect keeps needs review signal for vpn protected active path`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.ACTIVE,
                        vpnProtected = true,
                    ),
                )
            },
            stunDualStackProbe = { _, _, _ -> successDualStackResult() },
            publicIpFetcher = { _, _, _ -> Result.success("203.0.113.10") },
        )

        val results = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeDirect(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        val directResult = results.single { it.probeKind == CallTransportProbeKind.DIRECT_UDP_STUN }
        assertEquals(CallTransportStatus.NEEDS_REVIEW, directResult.status)
        assertEquals(CallTransportNetworkPath.ACTIVE, directResult.networkPath)
        assertEquals("198.51.100.20", directResult.mappedIp)
        assertEquals("203.0.113.10", directResult.observedPublicIp)
    }

    @Test
    fun `probeDirect reuses active stun sweep results`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = {
                CallTransportTargetCatalog.Catalog(
                    stunTargets = listOf(
                        CallTransportTargetCatalog.StunTarget(
                            host = "stun.l.google.com",
                            port = 19302,
                            scope = StunScope.GLOBAL,
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
                error("active path STUN probe should be reused from sweep")
            },
            publicIpFetcher = { _, _, _ -> Result.success("203.0.113.10") },
        )

        val results = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeDirect(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
                activeStunGroupsProvider = {
                    listOf(
                        com.notcvnt.rknhardering.model.StunProbeGroupResult(
                            scope = StunScope.GLOBAL,
                            results = listOf(
                                com.notcvnt.rknhardering.model.StunProbeResult(
                                    host = "stun.l.google.com",
                                    port = 19302,
                                    scope = StunScope.GLOBAL,
                                    mappedIpv4 = "198.51.100.20",
                                ),
                            ),
                        ),
                    )
                },
            )
        }

        val directResult = results.single { it.probeKind == CallTransportProbeKind.DIRECT_UDP_STUN }
        assertEquals("stun.l.google.com", directResult.targetHost)
        assertEquals("198.51.100.20", directResult.mappedIp)
        assertEquals(CallTransportStatus.NEEDS_REVIEW, directResult.status)
    }

    @Test
    fun `probeDirect prefers priority stun targets before fallback`() {
        val attemptedHosts = mutableListOf<String>()
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = {
                CallTransportTargetCatalog.Catalog(
                    stunTargets = listOf(
                        CallTransportTargetCatalog.StunTarget(
                            host = "stun.ekiga.net",
                            port = 3478,
                            scope = StunScope.GLOBAL,
                            enabled = true,
                        ),
                        CallTransportTargetCatalog.StunTarget(
                            host = "stun.l.google.com",
                            port = 19302,
                            scope = StunScope.GLOBAL,
                            enabled = true,
                        ),
                    ),
                )
            },
            loadPaths = {
                listOf(
                    CallTransportChecker.PathDescriptor(
                        path = CallTransportNetworkPath.UNDERLYING,
                        vpnProtected = false,
                    ),
                )
            },
            stunDualStackProbe = { target, _, _ ->
                attemptedHosts += target.host
                when (target.host) {
                    "stun.l.google.com" -> successDualStackResult()
                    else -> error("low priority target should not be probed before successful priority target")
                }
            },
            publicIpFetcher = { _, _, _ -> Result.success("203.0.113.10") },
        )

        val results = runBlockingProbeDirect()

        val directResult = results.single()
        assertEquals("stun.l.google.com", directResult.targetHost)
        assertEquals(listOf("stun.l.google.com"), attemptedHosts)
    }

    @Test
    fun `reusable udp relay candidates are derived from the same proxy owner`() {
        val owner = LocalProxyOwner(
            uid = 10123,
            packageNames = listOf("com.example.proxy"),
            appLabels = listOf("Proxy"),
            confidence = EvidenceConfidence.HIGH,
        )

        val candidates = CallTransportChecker.findReusableProxyUdpRelays(
            proxyEndpoint = ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5),
            listeners = listOf(
                listener(protocol = "tcp", host = "127.0.0.1", port = 1080, owner = owner),
                listener(protocol = "udp", host = "0.0.0.0", port = 53000, owner = owner),
                listener(protocol = "udp6", host = "::", port = 53001, owner = owner),
                listener(
                    protocol = "udp",
                    host = "127.0.0.1",
                    port = 53002,
                    owner = owner.copy(uid = 10124),
                ),
            ),
        )

        assertEquals(
            setOf(
                Socks5UdpAssociateClient.SessionInfo(relayHost = "127.0.0.1", relayPort = 53000),
                Socks5UdpAssociateClient.SessionInfo(relayHost = "127.0.0.1", relayPort = 53001),
            ),
            candidates.toSet(),
        )
    }

    @Test
    fun `probeStunTargets returns groups per scope`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            loadPaths = {
                listOf(CallTransportChecker.PathDescriptor(path = CallTransportNetworkPath.ACTIVE))
            },
            stunDualStackProbe = { _, _, _ -> successDualStackResult() },
        )

        val groups = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeStunTargets(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertTrue(groups.isNotEmpty())
        val globalGroup = groups.find { it.scope == StunScope.GLOBAL }
        assertTrue(globalGroup != null)
        assertTrue(globalGroup!!.results.isNotEmpty())
        assertTrue(globalGroup.results.first().hasResponse)
    }

    @Test
    fun `probeStunTargets returns empty when no active path`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            loadPaths = { emptyList() },
            stunDualStackProbe = { _, _, _ -> successDualStackResult() },
        )

        val groups = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeStunTargets(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertTrue(groups.isEmpty())
    }

    @Test
    fun `probeStunTargets no response results have error`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            loadPaths = {
                listOf(CallTransportChecker.PathDescriptor(path = CallTransportNetworkPath.ACTIVE))
            },
            stunDualStackProbe = { _, _, _ ->
                StunBindingClient.DualStackBindingResult(
                    ipv4Result = Result.failure(IllegalStateException("timeout")),
                    ipv6Result = null,
                )
            },
        )

        val groups = kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeStunTargets(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        val globalGroup = groups.find { it.scope == StunScope.GLOBAL }
        assertTrue(globalGroup != null)
        val first = globalGroup!!.results.first()
        assertFalse(first.hasResponse)
        assertTrue(first.error != null)
    }

    private fun runBlockingProbeDirect(): List<CallTransportLeakResult> =
        kotlinx.coroutines.runBlocking {
            CallTransportChecker.probeDirect(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
            )
        }

    private fun successBindingResult(): Result<StunBindingClient.BindingResult> {
        return Result.success(
            StunBindingClient.BindingResult(
                resolvedIps = listOf("93.184.216.34"),
                remoteIp = "93.184.216.34",
                remotePort = 3478,
                mappedIp = "198.51.100.20",
                mappedPort = 40000,
            ),
        )
    }

    private fun successDualStackResult(): StunBindingClient.DualStackBindingResult {
        return StunBindingClient.DualStackBindingResult(
            ipv4Result = Result.success(
                StunBindingClient.BindingResult(
                    resolvedIps = listOf("93.184.216.34"),
                    remoteIp = "93.184.216.34",
                    remotePort = 3478,
                    mappedIp = "198.51.100.20",
                    mappedPort = 40000,
                ),
            ),
            ipv6Result = null,
        )
    }

    private fun catalogWithStunTarget(): CallTransportTargetCatalog.Catalog {
        return CallTransportTargetCatalog.Catalog(
            stunTargets = listOf(
                CallTransportTargetCatalog.StunTarget(
                    host = "stun.example.com",
                    port = 3478,
                    scope = StunScope.GLOBAL,
                    enabled = true,
                ),
            ),
        )
    }

    private fun newNetwork(netId: Int): Network {
        val constructor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(netId)
    }

    private fun listener(
        protocol: String,
        host: String,
        port: Int,
        owner: LocalProxyOwner,
    ): LocalSocketListener = LocalSocketListener(
        protocol = protocol,
        host = host,
        port = port,
        state = if (protocol.startsWith("tcp")) "0A" else "07",
        uid = owner.uid,
        inode = 0L,
        owner = owner,
    )

    @Test
    fun `when builtinGlobalStunEnabled=false then sweep produces no global stun results`() {
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = {
                CallTransportTargetCatalog.Catalog(
                    stunTargets = listOf(
                        CallTransportTargetCatalog.StunTarget(
                            host = "stun.example.com",
                            port = 3478,
                            scope = StunScope.GLOBAL,
                            enabled = true,
                        ),
                    ),
                )
            },
            loadPaths = {
                listOf(CallTransportChecker.PathDescriptor(path = CallTransportNetworkPath.ACTIVE))
            },
            stunDualStackProbe = { _, _, _ -> successDualStackResult() },
            publicIpFetcher = { _, _, _ -> Result.success("203.0.113.10") },
            findLocalProxyEndpoint = { null },
        )

        val evaluation = kotlinx.coroutines.runBlocking {
            CallTransportChecker.check(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
                callTransportEnabled = true,
                config = CallTransportConfig(enabled = true, builtinGlobalStunEnabled = false),
            )
        }

        // The sweep filters out GLOBAL-scope builtin targets; the group must be present but empty.
        val globalGroup = evaluation.stunGroups.find { it.scope == StunScope.GLOBAL }
        assertTrue(
            "GLOBAL sweep group should be present but contain no results when builtinGlobalStunEnabled=false",
            globalGroup != null && globalGroup.results.isEmpty(),
        )
    }

    @Test
    fun `when checkMtproto=false then mtproto check is skipped`() {
        val proxyProbeCalled = mutableListOf<ProxyEndpoint>()
        CallTransportChecker.dependenciesOverride = CallTransportChecker.Dependencies(
            loadCatalog = { catalogWithStunTarget() },
            loadPaths = { emptyList() },
            findLocalProxyEndpoint = {
                ProxyEndpoint(host = "127.0.0.1", port = 1080, type = ProxyType.SOCKS5)
            },
            proxyProbe = { endpoint ->
                proxyProbeCalled += endpoint
                CallTransportChecker.ProxyProbeOutcome(reachable = false)
            },
            proxyUdpStunProbe = { _, _, _, _ ->
                Result.failure(IllegalStateException("not reached"))
            },
        )

        kotlinx.coroutines.runBlocking {
            CallTransportChecker.check(
                context = context,
                resolverConfig = DnsResolverConfig.system(),
                callTransportEnabled = true,
                config = CallTransportConfig(enabled = true, checkMtproto = false),
            )
        }

        assertTrue("proxyProbe must not be called when checkMtproto=false", proxyProbeCalled.isEmpty())
    }
}
