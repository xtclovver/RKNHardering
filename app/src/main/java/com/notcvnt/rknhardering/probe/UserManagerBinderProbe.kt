package com.notcvnt.rknhardering.probe

import android.app.ActivityManager
import android.os.Build

internal data class UserManagerBinderSnapshot(
    val profileType: HiddenCallResult<String?>,
    val profileParentUserId: HiddenCallResult<Int?>,
    val foregroundUserId: HiddenCallResult<Int>,
)

internal object UserManagerBinderProbe {
    private val userService = BinderServiceSpec(
        serviceName = "user",
        descriptor = "android.os.IUserManager",
        interfaceClassName = "android.os.IUserManager",
    )
    private val activityService = BinderServiceSpec(
        serviceName = "activity",
        descriptor = "android.app.IActivityManager",
        interfaceClassName = "android.app.IActivityManager",
    )

    internal val readOnlyMethodNames = setOf(
        "getProfileType",
        "getProfileParent",
        "isUserOfType",
        "isSameProfileGroup",
        "getCurrentUserId",
    )

    fun inspect(userId: Int): HiddenCallResult<UserManagerBinderSnapshot> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return HiddenCallResult.Unsupported("IUserManager probe requires API 26+")
        }
        return HiddenAndroidApiBridge.withBinderService(userService) { session ->
            HiddenCallResult.Success(
                UserManagerBinderSnapshot(
                    profileType = profileType(session, userId),
                    profileParentUserId = profileParentUserId(session, userId),
                    foregroundUserId = foregroundUserId(),
                ),
            )
        }
    }

    fun profileType(userId: Int): HiddenCallResult<String?> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return HiddenCallResult.Unsupported("User types require API 29+")
        }
        return HiddenAndroidApiBridge.withBinderService(userService) { session ->
            profileType(session, userId)
        }
    }

    fun isUserOfType(userId: Int, userType: String): HiddenCallResult<Boolean> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return HiddenCallResult.Unsupported("isUserOfType requires API 29+")
        }
        return HiddenAndroidApiBridge.withBinderService(userService) { session ->
            HiddenAndroidApiBridge.invokeExact(
                session,
                HiddenMethodSpec(
                    name = "isUserOfType",
                    parameterTypes = listOf(Int::class.javaPrimitiveType!!, String::class.java),
                    returnType = Boolean::class.javaPrimitiveType!!,
                ),
                arrayOf(userId, userType),
            ).asBoolean("IUserManager.isUserOfType")
        }
    }

    fun isSameProfileGroup(firstUserId: Int, secondUserId: Int): HiddenCallResult<Boolean> {
        return HiddenAndroidApiBridge.withBinderService(userService) { session ->
            HiddenAndroidApiBridge.invokeExact(
                session,
                HiddenMethodSpec(
                    name = "isSameProfileGroup",
                    parameterTypes = listOf(Int::class.javaPrimitiveType!!, Int::class.javaPrimitiveType!!),
                    returnType = Boolean::class.javaPrimitiveType!!,
                ),
                arrayOf(firstUserId, secondUserId),
            ).asBoolean("IUserManager.isSameProfileGroup")
        }
    }

    fun foregroundUserId(): HiddenCallResult<Int> {
        val reflected = HiddenAndroidApiBridge.invokeOnClass(
            target = ActivityManager::class.java,
            ownerClass = ActivityManager::class.java,
            spec = HiddenMethodSpec(
                name = "getCurrentUser",
                parameterTypes = emptyList(),
                returnType = Int::class.javaPrimitiveType!!,
            ),
            arguments = emptyArray(),
        )
        if (reflected is HiddenCallResult.Success) return reflected.asInt("ActivityManager.getCurrentUser")
        if (reflected is HiddenCallResult.PermissionDenied) return reflected

        return HiddenAndroidApiBridge.withBinderService(activityService) { session ->
            HiddenAndroidApiBridge.invokeExact(
                session,
                HiddenMethodSpec(
                    name = "getCurrentUserId",
                    parameterTypes = emptyList(),
                    returnType = Int::class.javaPrimitiveType!!,
                ),
                emptyArray(),
            ).asInt("IActivityManager.getCurrentUserId")
        }
    }

    private fun profileType(session: HiddenBinderSession, userId: Int): HiddenCallResult<String?> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return HiddenCallResult.Unsupported("User types require API 29+")
        }
        return HiddenAndroidApiBridge.invokeExact(
            session,
            HiddenMethodSpec(
                name = "getProfileType",
                parameterTypes = listOf(Int::class.javaPrimitiveType!!),
                returnType = String::class.java,
            ),
            arrayOf(userId),
        ).asNullableString("IUserManager.getProfileType")
    }

    private fun profileParentUserId(
        session: HiddenBinderSession,
        userId: Int,
    ): HiddenCallResult<Int?> {
        val userInfoClass = try {
            Class.forName("android.content.pm.UserInfo")
        } catch (error: Throwable) {
            return HiddenAndroidApiBridge.classifyThrowable(error, "UserInfo class")
        }
        val reply = HiddenAndroidApiBridge.invokeExact(
            session,
            HiddenMethodSpec(
                name = "getProfileParent",
                parameterTypes = listOf(Int::class.javaPrimitiveType!!),
                returnType = userInfoClass,
            ),
            arrayOf(userId),
        )
        val value = when (reply) {
            is HiddenCallResult.Success -> reply.value ?: return HiddenCallResult.Success(null)
            is HiddenCallResult.Unavailable -> return reply
            is HiddenCallResult.PermissionDenied -> return reply
            is HiddenCallResult.Unsupported -> return reply
            is HiddenCallResult.Skipped -> return reply
            is HiddenCallResult.Failure -> return reply
        }
        if (!userInfoClass.isInstance(value)) {
            return malformed("IUserManager.getProfileParent returned ${value.javaClass.name}")
        }
        return try {
            val idField = userInfoClass.getDeclaredField("id")
            if (idField.type != Int::class.javaPrimitiveType) {
                malformed("UserInfo.id signature mismatch")
            } else {
                HiddenCallResult.Success(idField.getInt(value))
            }
        } catch (error: Throwable) {
            HiddenAndroidApiBridge.classifyThrowable(error, "UserInfo.id")
        }
    }

    private fun HiddenCallResult<Any?>.asBoolean(operation: String): HiddenCallResult<Boolean> = when (this) {
        is HiddenCallResult.Success -> (value as? Boolean)?.let { HiddenCallResult.Success(it) }
            ?: malformed("$operation returned ${value?.javaClass?.name ?: "null"}")
        is HiddenCallResult.Unavailable -> this
        is HiddenCallResult.PermissionDenied -> this
        is HiddenCallResult.Unsupported -> this
        is HiddenCallResult.Skipped -> this
        is HiddenCallResult.Failure -> this
    }

    private fun HiddenCallResult<Any?>.asInt(operation: String): HiddenCallResult<Int> = when (this) {
        is HiddenCallResult.Success -> (value as? Int)?.let { HiddenCallResult.Success(it) }
            ?: malformed("$operation returned ${value?.javaClass?.name ?: "null"}")
        is HiddenCallResult.Unavailable -> this
        is HiddenCallResult.PermissionDenied -> this
        is HiddenCallResult.Unsupported -> this
        is HiddenCallResult.Skipped -> this
        is HiddenCallResult.Failure -> this
    }

    private fun HiddenCallResult<Any?>.asNullableString(operation: String): HiddenCallResult<String?> = when (this) {
        is HiddenCallResult.Success -> if (value == null || value is String) {
            HiddenCallResult.Success(value as String?)
        } else {
            malformed("$operation returned ${value.javaClass.name}")
        }
        is HiddenCallResult.Unavailable -> this
        is HiddenCallResult.PermissionDenied -> this
        is HiddenCallResult.Unsupported -> this
        is HiddenCallResult.Skipped -> this
        is HiddenCallResult.Failure -> this
    }

    private fun <T> malformed(reason: String): HiddenCallResult<T> =
        HiddenCallResult.Failure("MALFORMED_RESPONSE: $reason")
}
