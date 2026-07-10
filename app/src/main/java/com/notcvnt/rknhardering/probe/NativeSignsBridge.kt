package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanCancellationSignal

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
        getIfAddrsOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeGetIfAddrs() }.getOrDefault(emptyArray())
    }

    fun ifNameToIndex(name: String): Int {
        ifNameToIndexOverride?.let { return it.invoke(name) }
        if (!isLibraryLoaded() || name.isBlank()) return 0
        return runCatching { nativeIfNameToIndex(name) }.getOrDefault(0)
    }

    fun readProcFile(path: String, maxBytes: Int = 262_144): String? {
        readProcFileOverride?.let { return it.invoke(path, maxBytes) }
        if (!isLibraryLoaded()) return null
        return runCatching { nativeReadProcFile(path, maxBytes) }.getOrNull()
    }

    fun readSelfMapsSummary(): Array<String> {
        readSelfMapsSummaryOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeReadSelfMapsSummary() }.getOrDefault(emptyArray())
    }

    fun probeFeatureFlags(): Array<String> {
        probeFeatureFlagsOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeProbeFeatureFlags() }.getOrDefault(emptyArray())
    }

    fun libraryIntegrity(): Array<String> {
        libraryIntegrityOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeLibraryIntegrity() }.getOrDefault(emptyArray())
    }

    fun interfaceDump(): Array<String> {
        interfaceDumpOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeInterfaceDump() }.getOrDefault(emptyArray())
    }

    fun netlinkRouteDump(family: Int = 0): Array<String> {
        netlinkRouteDumpOverride?.let { return it.invoke(family) }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeNetlinkRouteDump(family) }.getOrDefault(emptyArray())
    }

    fun netlinkSockDiag(family: Int, protocol: Int): Array<String> {
        netlinkSockDiagOverride?.let { return it.invoke(family, protocol) }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeNetlinkSockDiag(family, protocol) }.getOrDefault(emptyArray())
    }

    fun detectRoot(): Array<String> {
        detectRootOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeDetectRoot() }.getOrDefault(emptyArray())
    }

    fun detectEmulator(): Array<String> {
        detectEmulatorOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeDetectEmulator() }.getOrDefault(emptyArray())
    }

    fun detectVpnProperties(): Array<String> {
        detectVpnPropertiesOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeDetectVpnProperties() }.getOrDefault(emptyArray())
    }

    fun detectVpnLeaks(): Array<String> {
        detectVpnLeaksOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeDetectVpnLeaks() }.getOrDefault(emptyArray())
    }

    fun detectVpnAdvanced(): Array<String> {
        detectVpnAdvancedOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeDetectVpnAdvanced() }.getOrDefault(emptyArray())
    }

    fun detectVpnSyscalls(): Array<String> {
        detectVpnSyscallsOverride?.let { return it.invoke() }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeDetectVpnSyscalls() }.getOrDefault(emptyArray())
    }

    fun detectVpnDetector(cancellationSignal: ScanCancellationSignal? = null): Array<String> {
        detectVpnDetectorOverride?.let { return it.invoke(cancellationSignal) }
        if (!isLibraryLoaded()) return emptyArray()
        return runCatching { nativeDetectVpnDetector(cancellationSignal) }.getOrDefault(emptyArray())
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
