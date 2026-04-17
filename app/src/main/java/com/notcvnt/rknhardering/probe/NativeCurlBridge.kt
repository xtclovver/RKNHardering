package com.notcvnt.rknhardering.probe

import android.content.Context
import org.json.JSONObject

object NativeCurlBridge {
    private const val LIBRARY_NAME = "native_curl_probe"

    @Volatile
    internal var initOverride: ((Context) -> NativeCaBundle.Info)? = null

    @Volatile
    internal var executeOverride: ((NativeCurlRequest) -> NativeCurlResponse)? = null

    @Volatile
    internal var cancelOverride: ((String) -> Boolean)? = null

    @Volatile
    internal var isLibraryLoadedOverride: (() -> Boolean)? = null

    @Volatile
    private var initialized = false

    @Volatile
    private var libraryLoaded = false

    @Volatile
    private var lastLoadError: Throwable? = null

    @Volatile
    private var caBundleInfo: NativeCaBundle.Info? = null

    fun initIfNeeded(context: Context) {
        if (initialized) return

        synchronized(this) {
            if (initialized) return
            val appContext = context.applicationContext
            try {
                val override = initOverride
                if (override != null) {
                    caBundleInfo = override(appContext)
                    libraryLoaded = isLibraryLoadedOverride?.invoke() ?: true
                    lastLoadError = null
                } else {
                    caBundleInfo = NativeCaBundle.ensureInstalled(appContext)
                    System.loadLibrary(LIBRARY_NAME)
                    libraryLoaded = true
                    lastLoadError = null
                }
            } catch (error: Throwable) {
                libraryLoaded = false
                lastLoadError = error
            } finally {
                initialized = true
            }
        }
    }

    fun isLibraryLoaded(): Boolean {
        return isLibraryLoadedOverride?.invoke() ?: libraryLoaded
    }

    fun canExecute(): Boolean {
        return executeOverride != null || (isLibraryLoaded() && caBundleInfo?.absolutePath?.isNotBlank() == true)
    }

    fun execute(requestJson: String): String {
        val request = NativeCurlRequest.fromJson(requestJson)
        return execute(request).toJson()
    }

    internal fun execute(
        request: NativeCurlRequest,
        requestId: String = "",
    ): NativeCurlResponse {
        executeOverride?.let { return it(request) }
        if (!isLibraryLoaded()) {
            return NativeCurlResponse(localError = lastLoadErrorMessage() ?: "Native curl bridge is not loaded")
        }
        val activeCaBundle = request.caBundlePath?.takeIf { it.isNotBlank() } ?: caBundleInfo?.absolutePath
        if (activeCaBundle.isNullOrBlank()) {
            return NativeCurlResponse(localError = "Native CA bundle is unavailable")
        }
        val raw = nativeExecuteRaw(
            url = request.url,
            interfaceName = request.interfaceName,
            method = request.method,
            headers = request.headers.toTypedArray(),
            body = request.body.orEmpty(),
            followRedirects = request.followRedirects,
            proxyUrl = request.proxyUrl.orEmpty(),
            proxyType = request.proxyType.nativeValue,
            resolveRules = request.resolveRules.map(NativeCurlResolveRule::toCurlRule).toTypedArray(),
            ipResolveMode = request.ipResolveMode.nativeValue,
            timeoutMs = request.timeoutMs,
            connectTimeoutMs = request.connectTimeoutMs,
            caBundlePath = activeCaBundle,
            debugVerbose = request.debugVerbose,
            requestId = requestId,
        )
        return NativeCurlResponse.fromRaw(raw)
    }

    internal fun cancelRequest(requestId: String): Boolean {
        if (requestId.isBlank()) return false
        cancelOverride?.let { return it(requestId) }
        if (!isLibraryLoaded()) return false
        return nativeCancelRequest(requestId)
    }

    internal fun lastLoadErrorMessage(): String? {
        val error = lastLoadError ?: return null
        return error.message?.takeIf { it.isNotBlank() } ?: error.javaClass.simpleName
    }

    internal fun caBundleInfo(): NativeCaBundle.Info? = caBundleInfo

    internal fun debugSnapshot(): JSONObject {
        return JSONObject().apply {
            put("libraryLoaded", isLibraryLoaded())
            put("loadError", lastLoadErrorMessage())
            put("caBundleVersion", caBundleInfo?.versionHash)
            put("caBundlePath", caBundleInfo?.absolutePath)
        }
    }

    internal fun resetForTests() {
        initOverride = null
        executeOverride = null
        cancelOverride = null
        isLibraryLoadedOverride = null
        initialized = false
        libraryLoaded = false
        lastLoadError = null
        caBundleInfo = null
    }

    private external fun nativeExecuteRaw(
        url: String,
        interfaceName: String,
        method: String,
        headers: Array<String>,
        body: String,
        followRedirects: Boolean,
        proxyUrl: String,
        proxyType: Int,
        resolveRules: Array<String>,
        ipResolveMode: Int,
        timeoutMs: Int,
        connectTimeoutMs: Int,
        caBundlePath: String,
        debugVerbose: Boolean,
        requestId: String,
    ): Array<String?>

    private external fun nativeCancelRequest(requestId: String): Boolean
}
