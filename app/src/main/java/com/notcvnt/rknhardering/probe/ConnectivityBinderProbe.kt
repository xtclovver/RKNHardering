package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process

internal enum class ConnectivityBinderApiFamily {
    O_TO_R,
    S_TO_U,
    V_AND_NEWER,
}

internal data class ConnectivityBinderSnapshot(
    val effectiveNetwork: Network?,
    val effectiveNetworkHandle: Long?,
    val publicActiveNetworkHandle: Long?,
    val differsFromPublicActiveNetwork: Boolean,
    val capabilities: NetworkCapabilities?,
    val linkProperties: LinkProperties?,
)

internal object ConnectivityBinderProbe {
    private val connectivityService = BinderServiceSpec(
        serviceName = "connectivity",
        descriptor = "android.net.IConnectivityManager",
        interfaceClassName = "android.net.IConnectivityManager",
    )

    internal val readOnlyMethodNames = setOf("getActiveNetworkForUid")

    internal fun familyForSdk(sdk: Int): ConnectivityBinderApiFamily = when {
        sdk >= Build.VERSION_CODES.VANILLA_ICE_CREAM -> ConnectivityBinderApiFamily.V_AND_NEWER
        sdk >= Build.VERSION_CODES.S -> ConnectivityBinderApiFamily.S_TO_U
        else -> ConnectivityBinderApiFamily.O_TO_R
    }

    fun effectiveNetworkForUid(
        context: Context,
        uid: Int = Process.myUid(),
    ): HiddenCallResult<ConnectivityBinderSnapshot> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return HiddenCallResult.Unsupported("Connectivity Binder probe requires API 26+")
        }
        familyForSdk(Build.VERSION.SDK_INT)
        val manager = context.getSystemService(ConnectivityManager::class.java)
            ?: return HiddenCallResult.Unavailable("ConnectivityManager unavailable")

        val reflected = HiddenAndroidApiBridge.invokeOnClass(
            target = manager,
            ownerClass = ConnectivityManager::class.java,
            spec = activeNetworkMethod,
            arguments = arrayOf(uid, false),
        )
        val networkResult = when (reflected) {
            is HiddenCallResult.Success -> reflected.asNullableNetwork("ConnectivityManager.getActiveNetworkForUid")
            is HiddenCallResult.PermissionDenied -> return reflected
            else -> HiddenAndroidApiBridge.withBinderService(connectivityService) { session ->
                HiddenAndroidApiBridge.invokeExact(session, activeNetworkMethod, arrayOf(uid, false))
                    .asNullableNetwork("IConnectivityManager.getActiveNetworkForUid")
            }
        }
        val network = when (networkResult) {
            is HiddenCallResult.Success -> networkResult.value
            is HiddenCallResult.Unavailable -> return networkResult
            is HiddenCallResult.PermissionDenied -> return networkResult
            is HiddenCallResult.Unsupported -> return networkResult
            is HiddenCallResult.Skipped -> return networkResult
            is HiddenCallResult.Failure -> return networkResult
        }

        return try {
            val publicNetwork = manager.activeNetwork
            HiddenCallResult.Success(
                ConnectivityBinderSnapshot(
                    effectiveNetwork = network,
                    effectiveNetworkHandle = network?.networkHandle,
                    publicActiveNetworkHandle = publicNetwork?.networkHandle,
                    differsFromPublicActiveNetwork = network != publicNetwork,
                    capabilities = network?.let(manager::getNetworkCapabilities),
                    linkProperties = network?.let(manager::getLinkProperties),
                ),
            )
        } catch (error: Throwable) {
            HiddenAndroidApiBridge.classifyThrowable(error, "ConnectivityManager network details")
        }
    }

    private val activeNetworkMethod = HiddenMethodSpec(
        name = "getActiveNetworkForUid",
        parameterTypes = listOf(Int::class.javaPrimitiveType!!, Boolean::class.javaPrimitiveType!!),
        returnType = Network::class.java,
    )

    private fun HiddenCallResult<Any?>.asNullableNetwork(operation: String): HiddenCallResult<Network?> = when (this) {
        is HiddenCallResult.Success -> if (value == null || value is Network) {
            HiddenCallResult.Success(value as Network?)
        } else {
            HiddenCallResult.Failure("MALFORMED_RESPONSE: $operation returned ${value.javaClass.name}")
        }
        is HiddenCallResult.Unavailable -> this
        is HiddenCallResult.PermissionDenied -> this
        is HiddenCallResult.Unsupported -> this
        is HiddenCallResult.Skipped -> this
        is HiddenCallResult.Failure -> this
    }
}
