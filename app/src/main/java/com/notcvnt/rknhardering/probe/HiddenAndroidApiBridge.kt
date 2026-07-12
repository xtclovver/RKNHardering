package com.notcvnt.rknhardering.probe

import android.os.DeadObjectException
import android.os.IBinder
import android.os.Process
import android.os.RemoteException
import android.os.UserManager
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Modifier

sealed interface HiddenCallResult<out T> {
    data class Success<T>(val value: T) : HiddenCallResult<T>
    data class Unavailable(val reason: String) : HiddenCallResult<Nothing>
    data class PermissionDenied(val reason: String) : HiddenCallResult<Nothing>
    data class Unsupported(val reason: String) : HiddenCallResult<Nothing>
    data class Skipped(val reason: String) : HiddenCallResult<Nothing>
    data class Failure(val reason: String) : HiddenCallResult<Nothing>
}

internal data class BinderServiceSpec(
    val serviceName: String,
    val descriptor: String,
    val interfaceClassName: String,
    val stubClassName: String = "$interfaceClassName\$Stub",
)

internal data class HiddenMethodSpec(
    val name: String,
    val parameterTypes: List<Class<*>>,
    val returnType: Class<*>,
)

internal data class HiddenBinderSession(
    val binder: IBinder,
    val interfaceClass: Class<*>,
    val service: Any,
)

internal object HiddenAndroidApiBridge {
    private const val PER_USER_RANGE = 100_000

    fun currentProfileType(userManager: UserManager): HiddenCallResult<String?> {
        val reflected = invokeOnClass(
            target = userManager,
            ownerClass = UserManager::class.java,
            spec = HiddenMethodSpec("getProfileType", emptyList(), String::class.java),
            arguments = emptyArray(),
        )
        if (reflected is HiddenCallResult.Success) {
            @Suppress("UNCHECKED_CAST")
            return reflected as HiddenCallResult<String?>
        }
        if (reflected is HiddenCallResult.PermissionDenied) return reflected

        return UserManagerBinderProbe.profileType(Process.myUid() / PER_USER_RANGE)
    }

    internal fun <T> withBinderService(
        spec: BinderServiceSpec,
        block: (HiddenBinderSession) -> HiddenCallResult<T>,
    ): HiddenCallResult<T> {
        repeat(2) { attempt ->
            try {
                val session = when (val opened = openBinderService(spec)) {
                    is HiddenCallResult.Success -> opened.value
                    is HiddenCallResult.Unavailable -> return opened
                    is HiddenCallResult.PermissionDenied -> return opened
                    is HiddenCallResult.Unsupported -> return opened
                    is HiddenCallResult.Skipped -> return opened
                    is HiddenCallResult.Failure -> return opened
                }
                return block(session)
            } catch (_: DeadBinderCallException) {
                if (attempt == 1) return HiddenCallResult.Unavailable("DeadObjectException after service retry")
            }
        }
        return HiddenCallResult.Unavailable("Binder service unavailable after retry")
    }

    internal fun invokeExact(
        session: HiddenBinderSession,
        spec: HiddenMethodSpec,
        arguments: Array<out Any?>,
    ): HiddenCallResult<Any?> = invokeOnClass(
        target = session.service,
        ownerClass = session.interfaceClass,
        spec = spec,
        arguments = arguments,
    )

    internal fun invokeOnClass(
        target: Any?,
        ownerClass: Class<*>,
        spec: HiddenMethodSpec,
        arguments: Array<out Any?>,
    ): HiddenCallResult<Any?> {
        if (target == null) return HiddenCallResult.Unavailable("${ownerClass.name}.${spec.name}: null target")
        if (arguments.size != spec.parameterTypes.size) {
            return HiddenCallResult.Failure("${spec.name}: argument count mismatch")
        }
        val method = try {
            ownerClass.getDeclaredMethod(spec.name, *spec.parameterTypes.toTypedArray())
        } catch (error: Throwable) {
            return classifyThrowable(error, "${ownerClass.name}.${spec.name}")
        }
        if (method.returnType != spec.returnType) {
            return HiddenCallResult.Unavailable(
                "${ownerClass.name}.${spec.name}: return ${method.returnType.name}, expected ${spec.returnType.name}",
            )
        }
        return invokeMethod(method, target, arguments, "${ownerClass.name}.${spec.name}")
    }

    internal fun validateBinderDescriptor(binder: IBinder, expected: String): HiddenCallResult<Unit> {
        return try {
            val actual = binder.interfaceDescriptor
            if (actual == expected) {
                HiddenCallResult.Success(Unit)
            } else {
                HiddenCallResult.Unavailable("Binder descriptor $actual, expected $expected")
            }
        } catch (error: Throwable) {
            when (val classified = classifyThrowable(error, "IBinder.getInterfaceDescriptor")) {
                is HiddenCallResult.PermissionDenied -> classified
                is HiddenCallResult.Unsupported -> classified
                is HiddenCallResult.Unavailable -> classified
                is HiddenCallResult.Failure -> classified
                is HiddenCallResult.Success -> HiddenCallResult.Failure("Unexpected descriptor result")
                is HiddenCallResult.Skipped -> classified
            }
        }
    }

    internal fun classifyThrowable(error: Throwable, operation: String? = null): HiddenCallResult<Nothing> {
        val cause = unwrap(error)
        if (cause is DeadObjectException) throw DeadBinderCallException(cause)
        val reason = buildString {
            operation?.let { append(it).append(": ") }
            append(cause.javaClass.simpleName)
            cause.message?.takeIf { it.isNotBlank() }?.let { append(": ").append(it.take(240)) }
        }
        return when (cause) {
            is SecurityException -> HiddenCallResult.PermissionDenied(reason)
            is UnsupportedOperationException -> HiddenCallResult.Unsupported(reason)
            is ClassNotFoundException,
            is NoSuchMethodException,
            is NoSuchFieldException,
            is IllegalAccessException,
            is LinkageError -> HiddenCallResult.Unavailable(reason)
            is RemoteException -> HiddenCallResult.Failure(reason)
            else -> HiddenCallResult.Failure(reason)
        }
    }

    private fun openBinderService(spec: BinderServiceSpec): HiddenCallResult<HiddenBinderSession> {
        val binderResult = serviceBinder(spec.serviceName)
        val binder = when (binderResult) {
            is HiddenCallResult.Success -> binderResult.value
            is HiddenCallResult.Unavailable -> return binderResult
            is HiddenCallResult.PermissionDenied -> return binderResult
            is HiddenCallResult.Unsupported -> return binderResult
            is HiddenCallResult.Skipped -> return binderResult
            is HiddenCallResult.Failure -> return binderResult
        }
        when (val descriptor = validateBinderDescriptor(binder, spec.descriptor)) {
            is HiddenCallResult.Success -> Unit
            is HiddenCallResult.Unavailable -> return descriptor
            is HiddenCallResult.PermissionDenied -> return descriptor
            is HiddenCallResult.Unsupported -> return descriptor
            is HiddenCallResult.Skipped -> return descriptor
            is HiddenCallResult.Failure -> return descriptor
        }
        return try {
            val interfaceClass = Class.forName(spec.interfaceClassName)
            val stubClass = Class.forName(spec.stubClassName)
            val asInterface = stubClass.getDeclaredMethod("asInterface", IBinder::class.java)
            if (!Modifier.isStatic(asInterface.modifiers) || asInterface.returnType != interfaceClass) {
                return HiddenCallResult.Unavailable("${spec.stubClassName}.asInterface signature mismatch")
            }
            val service = asInterface.invoke(null, binder)
                ?: return HiddenCallResult.Unavailable("${spec.stubClassName}.asInterface returned null")
            if (!interfaceClass.isInstance(service)) {
                return HiddenCallResult.Unavailable("${spec.stubClassName}.asInterface returned wrong type")
            }
            HiddenCallResult.Success(HiddenBinderSession(binder, interfaceClass, service))
        } catch (error: Throwable) {
            classifyThrowable(error, "${spec.stubClassName}.asInterface")
        }
    }

    private fun serviceBinder(name: String): HiddenCallResult<IBinder> {
        return try {
            val serviceManager = Class.forName("android.os.ServiceManager")
            val checkService = serviceManager.getDeclaredMethod("checkService", String::class.java)
            if (!Modifier.isStatic(checkService.modifiers) || checkService.returnType != IBinder::class.java) {
                return HiddenCallResult.Unavailable("ServiceManager.checkService signature mismatch")
            }
            val binder = checkService.invoke(null, name) as? IBinder
                ?: return HiddenCallResult.Unavailable("Service $name not published")
            HiddenCallResult.Success(binder)
        } catch (error: Throwable) {
            classifyThrowable(error, "ServiceManager.checkService($name)")
        }
    }

    private fun invokeMethod(
        method: Method,
        target: Any,
        arguments: Array<out Any?>,
        operation: String,
    ): HiddenCallResult<Any?> {
        return try {
            HiddenCallResult.Success(method.invoke(target, *arguments))
        } catch (error: Throwable) {
            classifyThrowable(error, operation)
        }
    }

    private fun unwrap(error: Throwable): Throwable {
        var current = error
        while (current is InvocationTargetException && current.targetException != null) {
            current = current.targetException
        }
        return current
    }

    private class DeadBinderCallException(cause: Throwable) : RuntimeException(cause)
}
