package com.notcvnt.rknhardering

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.asContextElement
import java.net.DatagramSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.CoroutineContext

private val scanExecutionContextThreadLocal = ThreadLocal<ScanExecutionContext?>()

data class ScanExecutionContext(
    val scanId: Long = 0L,
    val cancellationSignal: ScanCancellationSignal = ScanCancellationSignal(),
) {
    fun asCoroutineContext(): CoroutineContext = scanExecutionContextThreadLocal.asContextElement(this)

    fun throwIfCancelled(cause: Throwable? = null) {
        cancellationSignal.throwIfCancelled(cause)
    }

    companion object {
        fun currentOrDefault(): ScanExecutionContext {
            return scanExecutionContextThreadLocal.get() ?: ScanExecutionContext()
        }
    }
}

class ScanCancellationSignal {
    private val cancelled = AtomicBoolean(false)
    private val nextRegistrationId = AtomicLong(1L)
    private val callbacks = ConcurrentHashMap<Long, () -> Unit>()

    fun isCancelled(): Boolean = cancelled.get()

    fun throwIfCancelled(cause: Throwable? = null) {
        if (!isCancelled()) return
        throw CancellationException("Scan cancelled").also { cancellation ->
            cause?.let(cancellation::initCause)
        }
    }

    fun register(callback: () -> Unit): Registration {
        if (isCancelled()) {
            callback()
            return Registration.NO_OP
        }

        val id = nextRegistrationId.getAndIncrement()
        callbacks[id] = callback
        if (isCancelled()) {
            callbacks.remove(id)?.invoke()
            return Registration.NO_OP
        }

        return Registration(this, id)
    }

    fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        // Snapshot via the map's weakly-consistent iterator. Collection.toList()
        // takes a size==1 fast path through first(), which races with concurrent
        // unregister() and can throw NoSuchElementException.
        val pending = ArrayList<() -> Unit>(callbacks.size)
        for (callback in callbacks.values) {
            pending.add(callback)
        }
        callbacks.clear()
        pending.forEach { callback ->
            runCatching(callback)
        }
    }

    private fun unregister(id: Long) {
        callbacks.remove(id)
    }

    class Registration internal constructor(
        private val signal: ScanCancellationSignal?,
        private val id: Long?,
    ) {
        fun dispose() {
            val activeSignal = signal ?: return
            val activeId = id ?: return
            activeSignal.unregister(activeId)
        }

        companion object {
            internal val NO_OP = Registration(signal = null, id = null)
        }
    }
}

fun rethrowIfCancellation(
    error: Throwable,
    executionContext: ScanExecutionContext = ScanExecutionContext.currentOrDefault(),
) {
    if (error is CancellationException) throw error
    executionContext.throwIfCancelled(error)
}

fun ScanCancellationSignal.registerSocket(socket: Socket): ScanCancellationSignal.Registration {
    return register { runCatching { socket.close() } }
}

fun ScanCancellationSignal.registerDatagramSocket(socket: DatagramSocket): ScanCancellationSignal.Registration {
    return register { runCatching { socket.close() } }
}
