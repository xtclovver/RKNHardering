package com.notcvnt.rknhardering.probe.privileged

import android.os.Binder
import com.notcvnt.rknhardering.ScanCancellationSignal
import java.security.MessageDigest
import kotlin.system.exitProcess

open class PrivilegedProbeBinder internal constructor(
    private val engine: PrivilegedProbeEngine = NativePrivilegedProbeEngine,
    private val exitOnDestroy: Boolean,
) : IPrivilegedProbeService.Stub() {
    private val lock = Any()
    private var clientUid: Int? = null
    private var sessionNonce: ByteArray? = null
    private var cancellationSignal: ScanCancellationSignal? = null

    override fun openSession(nonce: ByteArray?): Boolean {
        if (nonce == null || nonce.size != PRIVILEGED_NONCE_SIZE) return false
        val callerUid = Binder.getCallingUid()
        synchronized(lock) {
            val existingUid = clientUid
            if (existingUid != null && existingUid != callerUid) return false
            clientUid = callerUid
            sessionNonce = nonce.copyOf()
            cancellationSignal = ScanCancellationSignal()
            return true
        }
    }

    override fun getProtocolVersion(nonce: ByteArray?): Int = withSession(nonce) {
        PRIVILEGED_PROBE_PROTOCOL_VERSION
    } ?: -1

    override fun getProviderUid(nonce: ByteArray?): Int = withSession(nonce) {
        currentPrivilegedProviderUid()
    } ?: -1

    override fun probeWireGuard(nonce: ByteArray?): Array<String> =
        withSession(nonce) { signal -> engine.wireGuard(signal) } ?: denied("wireguard_genl")

    override fun probeOvpn(nonce: ByteArray?): Array<String> =
        withSession(nonce) { signal -> engine.ovpn(signal) } ?: denied("ovpn_genl")

    override fun probeXfrm(nonce: ByteArray?, imsContext: Boolean): Array<String> =
        withSession(nonce) { signal -> engine.xfrm(imsContext, signal) } ?: denied("xfrm")

    override fun probeBpfNetfilter(nonce: ByteArray?): Array<String> =
        withSession(nonce) { signal -> engine.bpfNetfilter(signal) } ?: arrayOf(
            deniedRow("cgroup_bpf"),
            deniedRow("bpf_netd"),
            deniedRow("netfilter_path"),
        )

    override fun closeSession(nonce: ByteArray?) {
        synchronized(lock) {
            if (sessionMatches(nonce)) {
                cancellationSignal?.cancel()
                cancellationSignal = null
                sessionNonce?.fill(0)
                sessionNonce = null
                clientUid = null
            }
        }
    }

    override fun cancelSession(nonce: ByteArray?) {
        val signal = synchronized(lock) {
            if (sessionMatches(nonce)) cancellationSignal else null
        }
        signal?.cancel()
    }

    override fun destroy() {
        synchronized(lock) {
            cancellationSignal?.cancel()
            cancellationSignal = null
            sessionNonce?.fill(0)
            sessionNonce = null
            clientUid = null
        }
        if (exitOnDestroy) exitProcess(0)
    }

    private inline fun <T> withSession(nonce: ByteArray?, block: (ScanCancellationSignal) -> T): T? {
        val signal = synchronized(lock) {
            if (!sessionMatches(nonce)) return null
            cancellationSignal ?: return null
        }
        return block(signal)
    }

    private fun sessionMatches(nonce: ByteArray?): Boolean {
        val expected = sessionNonce ?: return false
        return clientUid == Binder.getCallingUid() && nonce != null &&
            MessageDigest.isEqual(expected, nonce)
    }

    private fun denied(checkId: String) = arrayOf(deniedRow(checkId))
    private fun deniedRow(checkId: String) = "beta_v1|check=$checkId|status=permission_denied"
}
