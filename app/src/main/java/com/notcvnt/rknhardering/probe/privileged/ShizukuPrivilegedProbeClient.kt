package com.notcvnt.rknhardering.probe.privileged

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import rikka.shizuku.Shizuku

internal class ShizukuPrivilegedProbeClient(
    private val context: Context,
) : PrivilegedProbeClient {
    override suspend fun connect(): PrivilegedConnectionResult {
        val backend = runCatching {
            if (!Shizuku.pingBinder() || Shizuku.isPreV11()) return PrivilegedConnectionResult.Unavailable
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                return PrivilegedConnectionResult.PermissionDenied
            }
            Shizuku.getUid() to Shizuku.getVersion()
        }.getOrElse { return PrivilegedConnectionResult.Unavailable }
        val (backendUid, backendVersion) = backend
        if (backendUid != SHELL_UID && backendUid != ROOT_UID) return PrivilegedConnectionResult.Unavailable

        val args = Shizuku.UserServiceArgs(
            ComponentName(context, ShizukuPrivilegedProbeUserService::class.java),
        )
            .daemon(false)
            .processNameSuffix("beta_privileged")
            .tag("beta_privileged_v1")
            .version(PRIVILEGED_PROBE_PROTOCOL_VERSION)

        return suspendCancellableCoroutine { continuation ->
            val completed = AtomicBoolean(false)
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
                                PrivilegedProbeConnection(service, backendUid, backendVersion) {
                                    Shizuku.unbindUserService(args, boundConnection, false)
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
                runCatching { Shizuku.unbindUserService(args, serviceConnection, false) }
            }
            runCatching { Shizuku.bindUserService(args, serviceConnection) }
                .onFailure {
                    if (completed.compareAndSet(false, true)) {
                        continuation.resume(PrivilegedConnectionResult.Unavailable)
                    }
                }
        }
    }

    private companion object {
        const val ROOT_UID = 0
        const val SHELL_UID = 2_000
    }
}
