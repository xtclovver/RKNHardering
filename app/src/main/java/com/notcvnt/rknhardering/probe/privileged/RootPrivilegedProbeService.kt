package com.notcvnt.rknhardering.probe.privileged

import android.content.Intent
import android.os.IBinder
import com.topjohnwu.superuser.ipc.RootService

class RootPrivilegedProbeService : RootService() {
    private val binder by lazy { PrivilegedProbeBinder(exitOnDestroy = false) }

    override fun onBind(intent: Intent): IBinder = binder
}
