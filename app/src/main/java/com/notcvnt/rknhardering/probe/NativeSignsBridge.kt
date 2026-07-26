package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.ScanExecutionContext

object NativeSignsBridge {
    private const val LIBRARY_NAME = "native_signs_probe"

    @Volatile
    internal var isLibraryLoadedOverride: (() -> Boolean)? = null

    @Volatile
    internal var getIfAddrsOverride: (() -> Array<String>)? = null

    @Volatile
    internal var ifNameToIndexOverride: ((String) -> Int)? = null

    @Volatile
    internal var readProcFileOverride: ((String, Int) -> String?)? = null

    @Volatile
    internal var readSelfMapsSummaryOverride: (() -> Array<String>)? = null

    @Volatile
    internal var probeFeatureFlagsOverride: (() -> Array<String>)? = null

    @Volatile
    internal var libraryIntegrityOverride: (() -> Array<String>)? = null

    @Volatile
    internal var interfaceDumpOverride: (() -> Array<String>)? = null

    @Volatile
    internal var netlinkRouteDumpOverride: ((Int) -> Array<String>)? = null

    @Volatile
    internal var netlinkSockDiagOverride: ((Int, Int) -> Array<String>)? = null

    @Volatile
    internal var betaSocketIdentityOverride: ((Int) -> Array<String>)? = null

    @Volatile
    internal var betaInetDiagByCookieOverride: ((Int) -> Array<String>)? = null

    @Volatile
    internal var betaNetdIdentityOverride: ((Int) -> Array<String>)? = null

    @Volatile
    internal var betaRoutingSnapshotOverride: ((Int, Int) -> Array<String>)? = null

    @Volatile
    internal var betaWireGuardProbeOverride: (() -> Array<String>)? = null

    @Volatile
    internal var betaOvpnProbeOverride: (() -> Array<String>)? = null

    @Volatile
    internal var betaXfrmProbeOverride: ((Boolean) -> Array<String>)? = null

    @Volatile
    internal var betaTunFdProbeOverride: (() -> Array<String>)? = null

    @Volatile
    internal var betaBpfNetfilterProbeOverride: ((Boolean) -> Array<String>)? = null

    @Volatile
    internal var betaUnixDiagProbeOverride: (() -> Array<String>)? = null

    @Volatile
    internal var betaUnixPeerIdentityProbeOverride: ((Int) -> Array<String>)? = null

    @Volatile
    internal var betaOriginalDestinationProbeOverride: ((Int) -> Array<String>)? = null

    @Volatile
    internal var betaPktInfoProbeOverride: ((Int) -> Array<String>)? = null

    @Volatile
    internal var betaTransitionMonitorOverride: ((Int) -> Array<String>)? = null

    @Volatile
    internal var betaExtendedRouteProbeOverride: ((Int, Int) -> Array<String>)? = null

    @Volatile
    internal var betaSandboxSnapshotOverride: ((Array<String>, Boolean) -> Array<String>)? = null

    @Volatile
    internal var betaHookTimingProbeOverride: ((ScanCancellationSignal?) -> Array<String>)? = null

    @Volatile
    internal var detectRootOverride: (() -> Array<String>)? = null

    @Volatile
    internal var detectEmulatorOverride: (() -> Array<String>)? = null

    @Volatile
    internal var detectVpnPropertiesOverride: (() -> Array<String>)? = null

    @Volatile
    internal var detectVpnLeaksOverride: (() -> Array<String>)? = null

    @Volatile
    internal var detectVpnAdvancedOverride: (() -> Array<String>)? = null

    @Volatile
    internal var detectVpnSyscallsOverride: (() -> Array<String>)? = null

    @Volatile
    internal var detectVpnDetectorOverride: ((ScanCancellationSignal?) -> Array<String>)? = null

    @Volatile
    private var initialized = false

    @Volatile
    private var libraryLoaded = false

    @Volatile
    private var lastLoadError: Throwable? = null

    fun initIfNeeded() {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            try {
                System.loadLibrary(LIBRARY_NAME)
                libraryLoaded = true
                lastLoadError = null
            } catch (error: Throwable) {
                libraryLoaded = false
                lastLoadError = error
            } finally {
                initialized = true
            }
        }
    }

    fun isLibraryLoaded(): Boolean {
        isLibraryLoadedOverride?.let { return it.invoke() }
        return libraryLoaded
    }

    internal fun lastLoadErrorMessage(): String? {
        val error = lastLoadError ?: return null
        return error.message?.takeIf { it.isNotBlank() } ?: error.javaClass.simpleName
    }

    fun getIfAddrs(): Array<String> {
        return traceArray("getifaddrs") {
            getIfAddrsOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeGetIfAddrs() }.getOrDefault(emptyArray())
        }
    }

    fun ifNameToIndex(name: String): Int {
        return traceValue("if_nametoindex", name, {
            ifNameToIndexOverride?.invoke(name)
                ?: if (!isLibraryLoaded() || name.isBlank()) 0 else runCatching { nativeIfNameToIndex(name) }.getOrDefault(0)
        }) { it.toString() }
    }

    fun readProcFile(path: String, maxBytes: Int = 262_144): String? {
        return traceValue("readProcFile", path, {
            val override = readProcFileOverride
            if (override != null) {
                override.invoke(path, maxBytes)
            } else if (!isLibraryLoaded()) {
                null
            } else {
                runCatching { nativeReadProcFile(path, maxBytes) }.getOrNull()
            }
        }) { it.orEmpty() }
    }

    fun readSelfMapsSummary(): Array<String> {
        return traceArray("readSelfMapsSummary") {
            readSelfMapsSummaryOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeReadSelfMapsSummary() }.getOrDefault(emptyArray())
        }
    }

    fun probeFeatureFlags(): Array<String> {
        return traceArray("probeFeatureFlags") {
            probeFeatureFlagsOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeProbeFeatureFlags() }.getOrDefault(emptyArray())
        }
    }

    fun libraryIntegrity(): Array<String> {
        return traceArray("libraryIntegrity") {
            libraryIntegrityOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeLibraryIntegrity() }.getOrDefault(emptyArray())
        }
    }

    fun interfaceDump(): Array<String> {
        return traceArray("interfaceDump") {
            interfaceDumpOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeInterfaceDump() }.getOrDefault(emptyArray())
        }
    }

    fun netlinkRouteDump(family: Int = 0): Array<String> {
        return traceArray("netlinkRouteDump", "family=$family") {
            netlinkRouteDumpOverride?.invoke(family)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeNetlinkRouteDump(family) }.getOrDefault(emptyArray())
        }
    }

    fun netlinkSockDiag(family: Int, protocol: Int): Array<String> {
        return traceArray("netlinkSockDiag", "family=$family,protocol=$protocol") {
            netlinkSockDiagOverride?.invoke(family, protocol)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeNetlinkSockDiag(family, protocol) }.getOrDefault(emptyArray())
        }
    }

    fun betaSocketIdentity(fd: Int): Array<String> = traceArray("betaSocketIdentity", "fd=$fd") {
        betaSocketIdentityOverride?.invoke(fd)
            ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeBetaSocketIdentity(fd) }.getOrDefault(emptyArray())
    }

    fun betaInetDiagByCookie(fd: Int, cancellationSignal: ScanCancellationSignal? = null): Array<String> =
        traceArray("betaInetDiagByCookie", "fd=$fd") {
        betaInetDiagByCookieOverride?.invoke(fd)
            ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                nativeBetaInetDiagByCookie(fd, cancellationSignal)
            }.getOrDefault(emptyArray())
        }

    fun betaNetdIdentity(fd: Int): Array<String> =
        traceArray("betaNetdIdentity", "fd=$fd") {
            betaNetdIdentityOverride?.invoke(fd)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaNetdIdentity(fd)
                }.getOrDefault(emptyArray())
        }

    fun betaRoutingSnapshot(
        fd: Int,
        uid: Int,
        cancellationSignal: ScanCancellationSignal? = null,
    ): Array<String> =
        traceArray("betaRoutingSnapshot", "fd=$fd,uid=$uid") {
            betaRoutingSnapshotOverride?.invoke(fd, uid)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaRoutingSnapshot(fd, uid, cancellationSignal)
                }.getOrDefault(emptyArray())
        }

    fun betaWireGuardProbe(cancellationSignal: ScanCancellationSignal? = null): Array<String> =
        traceArray("betaWireGuardProbe") {
            betaWireGuardProbeOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaWireGuardProbe(cancellationSignal)
                }.getOrDefault(emptyArray())
        }

    fun betaOvpnProbe(cancellationSignal: ScanCancellationSignal? = null): Array<String> =
        traceArray("betaOvpnProbe") {
            betaOvpnProbeOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaOvpnProbe(cancellationSignal)
                }.getOrDefault(emptyArray())
        }

    fun betaXfrmProbe(
        imsContext: Boolean,
        cancellationSignal: ScanCancellationSignal? = null,
    ): Array<String> = traceArray("betaXfrmProbe", "imsContext=$imsContext") {
        betaXfrmProbeOverride?.invoke(imsContext)
            ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                nativeBetaXfrmProbe(imsContext, cancellationSignal)
            }.getOrDefault(emptyArray())
    }

    fun betaTunFdProbe(cancellationSignal: ScanCancellationSignal? = null): Array<String> =
        traceArray("betaTunFdProbe") {
            betaTunFdProbeOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaTunFdProbe(cancellationSignal)
                }.getOrDefault(emptyArray())
        }

    fun betaBpfNetfilterProbe(
        aggressive: Boolean,
        cancellationSignal: ScanCancellationSignal? = null,
    ): Array<String> = traceArray("betaBpfNetfilterProbe", "aggressive=$aggressive") {
        betaBpfNetfilterProbeOverride?.invoke(aggressive)
            ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                nativeBetaBpfNetfilterProbe(aggressive, cancellationSignal)
            }.getOrDefault(emptyArray())
    }

    fun betaUnixDiagProbe(cancellationSignal: ScanCancellationSignal? = null): Array<String> =
        traceArray("betaUnixDiagProbe") {
            betaUnixDiagProbeOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaUnixDiagProbe(cancellationSignal)
                }.getOrDefault(emptyArray())
        }

    fun betaUnixPeerIdentityProbe(fd: Int): Array<String> =
        traceArray("betaUnixPeerIdentityProbe", "fd=$fd") {
            betaUnixPeerIdentityProbeOverride?.invoke(fd)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaUnixPeerIdentityProbe(fd)
                }.getOrDefault(emptyArray())
        }

    fun betaOriginalDestinationProbe(fd: Int): Array<String> =
        traceArray("betaOriginalDestinationProbe", "fd=$fd") {
            betaOriginalDestinationProbeOverride?.invoke(fd)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaOriginalDestinationProbe(fd)
                }.getOrDefault(emptyArray())
        }

    fun betaPktInfoProbe(fd: Int): Array<String> =
        traceArray("betaPktInfoProbe", "fd=$fd") {
            betaPktInfoProbeOverride?.invoke(fd)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaPktInfoProbe(fd)
                }.getOrDefault(emptyArray())
        }

    fun betaTransitionMonitor(
        durationMs: Int,
        cancellationSignal: ScanCancellationSignal? = null,
    ): Array<String> = traceArray("betaTransitionMonitor", "durationMs=$durationMs") {
        betaTransitionMonitorOverride?.invoke(durationMs)
            ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                nativeBetaTransitionMonitor(durationMs, cancellationSignal)
            }.getOrDefault(emptyArray())
    }

    fun betaExtendedRouteProbe(
        fd: Int,
        uid: Int,
        cancellationSignal: ScanCancellationSignal? = null,
    ): Array<String> = traceArray("betaExtendedRouteProbe", "fd=$fd,uid=$uid") {
        betaExtendedRouteProbeOverride?.invoke(fd, uid)
            ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                nativeBetaExtendedRouteProbe(fd, uid, cancellationSignal)
            }.getOrDefault(emptyArray())
    }

    fun betaSandboxSnapshot(paths: Array<String>, aggressive: Boolean): Array<String> =
        traceArray("betaSandboxSnapshot", "paths=${paths.size},aggressive=$aggressive") {
            betaSandboxSnapshotOverride?.invoke(paths, aggressive)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaSandboxSnapshot(paths, aggressive)
                }.getOrDefault(emptyArray())
        }

    fun betaHookTimingProbe(cancellationSignal: ScanCancellationSignal? = null): Array<String> =
        traceArray("betaHookTimingProbe") {
            betaHookTimingProbeOverride?.invoke(cancellationSignal)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching {
                    nativeBetaHookTimingProbe(cancellationSignal)
                }.getOrDefault(emptyArray())
        }

    fun detectRoot(): Array<String> {
        return traceArray("detectRoot") {
            detectRootOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeDetectRoot() }.getOrDefault(emptyArray())
        }
    }

    fun detectEmulator(): Array<String> {
        return traceArray("detectEmulator") {
            detectEmulatorOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeDetectEmulator() }.getOrDefault(emptyArray())
        }
    }

    fun detectVpnProperties(): Array<String> {
        return traceArray("detectVpnProperties") {
            detectVpnPropertiesOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeDetectVpnProperties() }.getOrDefault(emptyArray())
        }
    }

    fun detectVpnLeaks(): Array<String> {
        return traceArray("detectVpnLeaks") {
            detectVpnLeaksOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeDetectVpnLeaks() }.getOrDefault(emptyArray())
        }
    }

    fun detectVpnAdvanced(): Array<String> {
        return traceArray("detectVpnAdvanced") {
            detectVpnAdvancedOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeDetectVpnAdvanced() }.getOrDefault(emptyArray())
        }
    }

    fun detectVpnSyscalls(): Array<String> {
        return traceArray("detectVpnSyscalls") {
            detectVpnSyscallsOverride?.invoke()
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeDetectVpnSyscalls() }.getOrDefault(emptyArray())
        }
    }

    fun detectVpnDetector(cancellationSignal: ScanCancellationSignal? = null): Array<String> {
        return traceArray("detectVpnDetector") {
            detectVpnDetectorOverride?.invoke(cancellationSignal)
                ?: if (!isLibraryLoaded()) emptyArray() else runCatching { nativeDetectVpnDetector(cancellationSignal) }.getOrDefault(emptyArray())
        }
    }

    private fun traceArray(
        source: String,
        target: String? = null,
        block: () -> Array<String>,
    ): Array<String> = traceValue(source, target, block) { it.joinToString("\n") }

    private fun <T> traceValue(
        source: String,
        target: String? = null,
        block: () -> T,
        render: (T) -> String,
    ): T {
        val executionContext = ScanExecutionContext.currentOrDefault()
        val startedAt = System.nanoTime()
        return try {
            block().also { result ->
                executionContext.diagnosticCollector?.record(
                    category = "nat",
                    source = source,
                    target = target,
                    status = "completed",
                    durationMs = (System.nanoTime() - startedAt) / 1_000_000,
                    body = render(result),
                )
            }
        } catch (error: Throwable) {
            executionContext.diagnosticCollector?.record(
                category = "nat",
                source = source,
                target = target,
                status = "error",
                durationMs = (System.nanoTime() - startedAt) / 1_000_000,
                body = error.message.orEmpty(),
            )
            throw error
        }
    }

    internal fun resetForTests() {
        isLibraryLoadedOverride = null
        getIfAddrsOverride = null
        ifNameToIndexOverride = null
        readProcFileOverride = null
        readSelfMapsSummaryOverride = null
        probeFeatureFlagsOverride = null
        libraryIntegrityOverride = null
        interfaceDumpOverride = null
        netlinkRouteDumpOverride = null
        netlinkSockDiagOverride = null
        betaSocketIdentityOverride = null
        betaInetDiagByCookieOverride = null
        betaNetdIdentityOverride = null
        betaRoutingSnapshotOverride = null
        betaWireGuardProbeOverride = null
        betaOvpnProbeOverride = null
        betaXfrmProbeOverride = null
        betaTunFdProbeOverride = null
        betaBpfNetfilterProbeOverride = null
        betaUnixDiagProbeOverride = null
        betaUnixPeerIdentityProbeOverride = null
        betaOriginalDestinationProbeOverride = null
        betaPktInfoProbeOverride = null
        betaTransitionMonitorOverride = null
        betaExtendedRouteProbeOverride = null
        betaSandboxSnapshotOverride = null
        betaHookTimingProbeOverride = null
        detectRootOverride = null
        detectEmulatorOverride = null
        detectVpnPropertiesOverride = null
        detectVpnLeaksOverride = null
        detectVpnAdvancedOverride = null
        detectVpnSyscallsOverride = null
        detectVpnDetectorOverride = null
        initialized = false
        libraryLoaded = false
        lastLoadError = null
    }

    private external fun nativeGetIfAddrs(): Array<String>
    private external fun nativeIfNameToIndex(name: String): Int
    private external fun nativeReadProcFile(path: String, maxBytes: Int): String?
    private external fun nativeReadSelfMapsSummary(): Array<String>
    private external fun nativeProbeFeatureFlags(): Array<String>
    private external fun nativeLibraryIntegrity(): Array<String>
    private external fun nativeInterfaceDump(): Array<String>
    private external fun nativeNetlinkRouteDump(family: Int): Array<String>
    private external fun nativeNetlinkSockDiag(family: Int, protocol: Int): Array<String>
    private external fun nativeBetaSocketIdentity(fd: Int): Array<String>
    private external fun nativeBetaInetDiagByCookie(fd: Int, cancellationSignal: ScanCancellationSignal?): Array<String>
    private external fun nativeBetaNetdIdentity(fd: Int): Array<String>
    private external fun nativeBetaRoutingSnapshot(
        fd: Int,
        uid: Int,
        cancellationSignal: ScanCancellationSignal?,
    ): Array<String>
    private external fun nativeBetaWireGuardProbe(cancellationSignal: ScanCancellationSignal?): Array<String>
    private external fun nativeBetaOvpnProbe(cancellationSignal: ScanCancellationSignal?): Array<String>
    private external fun nativeBetaXfrmProbe(
        imsContext: Boolean,
        cancellationSignal: ScanCancellationSignal?,
    ): Array<String>
    private external fun nativeBetaTunFdProbe(cancellationSignal: ScanCancellationSignal?): Array<String>
    private external fun nativeBetaBpfNetfilterProbe(
        aggressive: Boolean,
        cancellationSignal: ScanCancellationSignal?,
    ): Array<String>
    private external fun nativeBetaUnixDiagProbe(cancellationSignal: ScanCancellationSignal?): Array<String>
    private external fun nativeBetaUnixPeerIdentityProbe(fd: Int): Array<String>
    private external fun nativeBetaOriginalDestinationProbe(fd: Int): Array<String>
    private external fun nativeBetaPktInfoProbe(fd: Int): Array<String>
    private external fun nativeBetaTransitionMonitor(
        durationMs: Int,
        cancellationSignal: ScanCancellationSignal?,
    ): Array<String>
    private external fun nativeBetaExtendedRouteProbe(
        fd: Int,
        uid: Int,
        cancellationSignal: ScanCancellationSignal?,
    ): Array<String>
    private external fun nativeBetaSandboxSnapshot(paths: Array<String>, aggressive: Boolean): Array<String>
    private external fun nativeBetaHookTimingProbe(cancellationSignal: ScanCancellationSignal?): Array<String>
    private external fun nativeDetectRoot(): Array<String>
    private external fun nativeDetectEmulator(): Array<String>
    private external fun nativeDetectVpnProperties(): Array<String>
    private external fun nativeDetectVpnLeaks(): Array<String>
    private external fun nativeDetectVpnAdvanced(): Array<String>
    private external fun nativeDetectVpnSyscalls(): Array<String>
    private external fun nativeDetectVpnDetector(cancellationSignal: ScanCancellationSignal?): Array<String>
}
