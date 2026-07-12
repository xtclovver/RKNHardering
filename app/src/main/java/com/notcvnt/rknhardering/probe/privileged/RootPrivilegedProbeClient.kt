package com.notcvnt.rknhardering.probe.privileged

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import com.topjohnwu.superuser.ipc.RootService
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

internal class RootPrivilegedProbeClient(
    private val context: Context,
) : PrivilegedProbeClient {
    override suspend fun connect(): PrivilegedConnectionResult = suspendCancellableCoroutine { continuation ->
        val completed = AtomicBoolean(false)
        val intent = Intent(context, RootPrivilegedProbeService::class.java)
        val serviceConnection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                if (!completed.compareAndSet(false, true)) return
                val service = binder?.let(IPrivilegedProbeService.Stub::asInterface)
                val boundConnection = this
                continuation.resume(
                    if (service == null) {
                        PrivilegedConnectionResult.Unavailable
                    } else {
                        PrivilegedConnectionResult.Connected(
                            PrivilegedProbeConnection(service, ROOT_UID, LIBSU_BACKEND_VERSION) {
                                RootService.unbind(boundConnection)
                            },
                        )
                    },
                )
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                if (completed.compareAndSet(false, true)) {
                    continuation.resume(PrivilegedConnectionResult.Unavailable)
                }
            }

            override fun onNullBinding(name: ComponentName?) = onServiceDisconnected(name)
            override fun onBindingDied(name: ComponentName?) = onServiceDisconnected(name)
        }
        continuation.invokeOnCancellation {
            completed.set(true)
            runCatching { RootService.unbind(serviceConnection) }
        }
        runCatching { RootService.bind(intent, serviceConnection) }
            .onFailure {
                if (completed.compareAndSet(false, true)) {
                    continuation.resume(PrivilegedConnectionResult.Unavailable)
                }
            }
    }

    private companion object {
        const val ROOT_UID = 0
        const val LIBSU_BACKEND_VERSION = 60_000
    }
}
