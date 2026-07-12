package com.notcvnt.rknhardering.probe

import android.os.Build

internal data class VpnConfigFacts(
    val present: Boolean,
    val interfaceName: String?,
    val ownerPackage: String?,
    val legacy: Boolean?,
)

internal data class LegacyVpnFacts(
    val present: Boolean,
    val state: Int?,
)

internal data class VpnManagerBinderSnapshot(
    val config: HiddenCallResult<VpnConfigFacts>,
    val legacyInfo: HiddenCallResult<LegacyVpnFacts>,
    val alwaysOnPackage: HiddenCallResult<String?>,
    val lockdownEnabled: HiddenCallResult<Boolean>,
    val lockdownAllowlistSize: HiddenCallResult<Int?>,
)

internal object VpnManagerBinderProbe {
    internal val readOnlyMethodNames = setOf(
        "getVpnConfig",
        "getLegacyVpnInfo",
        "getAlwaysOnVpnPackage",
        "isVpnLockdownEnabled",
        "getVpnLockdownAllowlist",
        "getVpnLockdownWhitelist",
    )

    internal fun serviceSpecForSdk(sdk: Int): BinderServiceSpec = if (sdk >= Build.VERSION_CODES.S) {
        BinderServiceSpec(
            serviceName = "vpn_management",
            descriptor = "android.net.IVpnManager",
            interfaceClassName = "android.net.IVpnManager",
        )
    } else {
        BinderServiceSpec(
            serviceName = "connectivity",
            descriptor = "android.net.IConnectivityManager",
            interfaceClassName = "android.net.IConnectivityManager",
        )
    }

    fun inspect(userId: Int): HiddenCallResult<VpnManagerBinderSnapshot> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return HiddenCallResult.Unsupported("VPN Binder probe requires API 26+")
        }
        return HiddenAndroidApiBridge.withBinderService(serviceSpecForSdk(Build.VERSION.SDK_INT)) { session ->
            HiddenCallResult.Success(
                VpnManagerBinderSnapshot(
                    config = vpnConfig(session, userId),
                    legacyInfo = legacyVpnInfo(session, userId),
                    alwaysOnPackage = nullableStringCall(session, "getAlwaysOnVpnPackage", userId),
                    lockdownEnabled = booleanCall(session, "isVpnLockdownEnabled", userId),
                    lockdownAllowlistSize = lockdownAllowlistSize(session, userId),
                ),
            )
        }
    }

    private fun vpnConfig(session: HiddenBinderSession, userId: Int): HiddenCallResult<VpnConfigFacts> {
        val configClass = hiddenClass("com.android.internal.net.VpnConfig") ?: return HiddenCallResult.Unavailable(
            "com.android.internal.net.VpnConfig unavailable",
        )
        val reply = HiddenAndroidApiBridge.invokeExact(
            session,
            HiddenMethodSpec(
                name = "getVpnConfig",
                parameterTypes = listOf(Int::class.javaPrimitiveType!!),
                returnType = configClass,
            ),
            arrayOf(userId),
        )
        val value = reply.valueOrReturn { return it }
            ?: return HiddenCallResult.Success(VpnConfigFacts(false, null, null, null))
        if (!configClass.isInstance(value)) return malformed("getVpnConfig returned ${value.javaClass.name}")
        return HiddenCallResult.Success(
            VpnConfigFacts(
                present = true,
                interfaceName = readOptionalField(configClass, value, "interfaze", String::class.java),
                ownerPackage = readOptionalField(configClass, value, "user", String::class.java),
                legacy = readOptionalField(configClass, value, "legacy", Boolean::class.javaPrimitiveType!!),
            ),
        )
    }

    private fun legacyVpnInfo(session: HiddenBinderSession, userId: Int): HiddenCallResult<LegacyVpnFacts> {
        val legacyClass = hiddenClass("com.android.internal.net.LegacyVpnInfo") ?: return HiddenCallResult.Unavailable(
            "com.android.internal.net.LegacyVpnInfo unavailable",
        )
        val reply = HiddenAndroidApiBridge.invokeExact(
            session,
            HiddenMethodSpec(
                name = "getLegacyVpnInfo",
                parameterTypes = listOf(Int::class.javaPrimitiveType!!),
                returnType = legacyClass,
            ),
            arrayOf(userId),
        )
        val value = reply.valueOrReturn { return it }
            ?: return HiddenCallResult.Success(LegacyVpnFacts(false, null))
        if (!legacyClass.isInstance(value)) return malformed("getLegacyVpnInfo returned ${value.javaClass.name}")
        return HiddenCallResult.Success(
            LegacyVpnFacts(
                present = true,
                state = readOptionalField(legacyClass, value, "state", Int::class.javaPrimitiveType!!),
            ),
        )
    }

    private fun nullableStringCall(
        session: HiddenBinderSession,
        methodName: String,
        userId: Int,
    ): HiddenCallResult<String?> {
        return when (val reply = invokeUserCall(session, methodName, String::class.java, userId)) {
            is HiddenCallResult.Success -> if (reply.value == null || reply.value is String) {
                HiddenCallResult.Success(reply.value as String?)
            } else {
                malformed("$methodName returned ${reply.value.javaClass.name}")
            }
            is HiddenCallResult.Unavailable -> reply
            is HiddenCallResult.PermissionDenied -> reply
            is HiddenCallResult.Unsupported -> reply
            is HiddenCallResult.Skipped -> reply
            is HiddenCallResult.Failure -> reply
        }
    }

    private fun booleanCall(
        session: HiddenBinderSession,
        methodName: String,
        userId: Int,
    ): HiddenCallResult<Boolean> {
        return when (val reply = invokeUserCall(session, methodName, Boolean::class.javaPrimitiveType!!, userId)) {
            is HiddenCallResult.Success -> (reply.value as? Boolean)?.let { HiddenCallResult.Success(it) }
                ?: malformed("$methodName returned ${reply.value?.javaClass?.name ?: "null"}")
            is HiddenCallResult.Unavailable -> reply
            is HiddenCallResult.PermissionDenied -> reply
            is HiddenCallResult.Unsupported -> reply
            is HiddenCallResult.Skipped -> reply
            is HiddenCallResult.Failure -> reply
        }
    }

    private fun lockdownAllowlistSize(
        session: HiddenBinderSession,
        userId: Int,
    ): HiddenCallResult<Int?> {
        val methodName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            "getVpnLockdownAllowlist"
        } else {
            "getVpnLockdownWhitelist"
        }
        return when (val reply = invokeUserCall(session, methodName, List::class.java, userId)) {
            is HiddenCallResult.Success -> {
                val list = reply.value ?: return HiddenCallResult.Success(null)
                if (list !is List<*> || list.any { it !is String }) {
                    malformed("$methodName returned malformed list")
                } else {
                    HiddenCallResult.Success(list.size)
                }
            }
            is HiddenCallResult.Unavailable -> reply
            is HiddenCallResult.PermissionDenied -> reply
            is HiddenCallResult.Unsupported -> reply
            is HiddenCallResult.Skipped -> reply
            is HiddenCallResult.Failure -> reply
        }
    }

    private fun invokeUserCall(
        session: HiddenBinderSession,
        methodName: String,
        returnType: Class<*>,
        userId: Int,
    ): HiddenCallResult<Any?> = HiddenAndroidApiBridge.invokeExact(
        session,
        HiddenMethodSpec(
            name = methodName,
            parameterTypes = listOf(Int::class.javaPrimitiveType!!),
            returnType = returnType,
        ),
        arrayOf(userId),
    )

    private fun hiddenClass(name: String): Class<*>? = try {
        Class.forName(name)
    } catch (_: Throwable) {
        null
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> readOptionalField(owner: Class<*>, target: Any, name: String, type: Class<*>): T? {
        return try {
            val field = owner.getDeclaredField(name)
            if (field.type != type) null else field.get(target) as? T
        } catch (_: Throwable) {
            null
        }
    }

    private inline fun HiddenCallResult<Any?>.valueOrReturn(
        failure: (HiddenCallResult<Nothing>) -> Nothing,
    ): Any? = when (this) {
        is HiddenCallResult.Success -> value
        is HiddenCallResult.Unavailable -> failure(this)
        is HiddenCallResult.PermissionDenied -> failure(this)
        is HiddenCallResult.Unsupported -> failure(this)
        is HiddenCallResult.Skipped -> failure(this)
        is HiddenCallResult.Failure -> failure(this)
    }

    private fun <T> malformed(reason: String): HiddenCallResult<T> =
        HiddenCallResult.Failure("MALFORMED_RESPONSE: $reason")
}
