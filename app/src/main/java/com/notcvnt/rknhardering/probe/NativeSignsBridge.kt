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
    private external fun nativeDetectRoot(): Array<String>
    private external fun nativeDetectEmulator(): Array<String>
    private external fun nativeDetectVpnProperties(): Array<String>
    private external fun nativeDetectVpnLeaks(): Array<String>
    private external fun nativeDetectVpnAdvanced(): Array<String>
    private external fun nativeDetectVpnSyscalls(): Array<String>
    private external fun nativeDetectVpnDetector(cancellationSignal: ScanCancellationSignal?): Array<String>
}
