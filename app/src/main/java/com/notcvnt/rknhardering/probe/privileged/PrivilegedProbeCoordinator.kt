package com.notcvnt.rknhardering.probe.privileged

import android.content.Context
import android.os.DeadObjectException
import com.notcvnt.rknhardering.model.PrivilegedProbeProvider
import java.security.SecureRandom
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

enum class PrivilegedProbeKind(val expectedCheckIds: Set<String>) {
    WIREGUARD(setOf("wireguard_genl")),
    OVPN(setOf("ovpn_genl")),
    XFRM(setOf("xfrm")),
    BPF_NETFILTER(setOf("cgroup_bpf", "bpf_netd", "netfilter_path")),
}

data class PrivilegedProbeSettings(
    val betaMasterEnabled: Boolean,
    val privilegedMasterEnabled: Boolean,
    val provider: PrivilegedProbeProvider,
)

data class PrivilegedProviderIdentity(
    val provider: PrivilegedProbeProvider,
    val uid: Int,
    val protocolVersion: Int,
    val backendVersion: Int,
)

sealed interface PrivilegedProbeResult {
    data object Disabled : PrivilegedProbeResult
    data class Available(
        val identity: PrivilegedProviderIdentity,
        val rows: Array<String>,
    ) : PrivilegedProbeResult
    data class PermissionDenied(val provider: PrivilegedProbeProvider) : PrivilegedProbeResult
    data class Unavailable(val provider: PrivilegedProbeProvider) : PrivilegedProbeResult
    data class MalformedResponse(val provider: PrivilegedProbeProvider) : PrivilegedProbeResult
}

internal data class PrivilegedProbeConnection(
    val service: IPrivilegedProbeService,
    val expectedUid: Int,
    val backendVersion: Int,
    val close: () -> Unit,
)

internal sealed interface PrivilegedConnectionResult {
    data class Connected(val connection: PrivilegedProbeConnection) : PrivilegedConnectionResult
    data object PermissionDenied : PrivilegedConnectionResult
    data object Unavailable : PrivilegedConnectionResult
}

internal fun interface PrivilegedProbeClient {
    suspend fun connect(): PrivilegedConnectionResult
}

internal class PrivilegedProbeCoordinator(
    context: Context,
    private val clientFactory: (PrivilegedProbeProvider, Context) -> PrivilegedProbeClient? = { provider, appContext ->
        when (provider) {
            PrivilegedProbeProvider.SHIZUKU -> ShizukuPrivilegedProbeClient(appContext)
            PrivilegedProbeProvider.ROOT -> RootPrivilegedProbeClient(appContext)
            PrivilegedProbeProvider.NONE -> null
        }
    },
) {
    private val appContext = context.applicationContext

    suspend fun run(
        settings: PrivilegedProbeSettings,
        kind: PrivilegedProbeKind,
        imsContext: Boolean = false,
    ): PrivilegedProbeResult = runBatch(settings, linkedSetOf(kind), imsContext).getValue(kind)

    @OptIn(InternalCoroutinesApi::class)
    suspend fun runBatch(
        settings: PrivilegedProbeSettings,
        kinds: Set<PrivilegedProbeKind>,
        imsContext: Boolean = false,
    ): Map<PrivilegedProbeKind, PrivilegedProbeResult> {
        if (kinds.isEmpty()) return emptyMap()
        if (!settings.betaMasterEnabled || !settings.privilegedMasterEnabled ||
            settings.provider == PrivilegedProbeProvider.NONE
        ) {
            return kinds.associateWith { PrivilegedProbeResult.Disabled }
        }
        val provider = settings.provider
        val client = clientFactory(provider, appContext)
            ?: return kinds.associateWith { PrivilegedProbeResult.Disabled }
        val connected = try {
            withTimeout(CONNECT_TIMEOUT_MS) { client.connect() }
        } catch (_: TimeoutCancellationException) {
            return kinds.associateWith { PrivilegedProbeResult.Unavailable(provider) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            return kinds.associateWith { PrivilegedProbeResult.Unavailable(provider) }
        }
        val connection = when (connected) {
            is PrivilegedConnectionResult.Connected -> connected.connection
            PrivilegedConnectionResult.PermissionDenied ->
                return kinds.associateWith { PrivilegedProbeResult.PermissionDenied(provider) }
            PrivilegedConnectionResult.Unavailable ->
                return kinds.associateWith { PrivilegedProbeResult.Unavailable(provider) }
        }
        val nonce = ByteArray(PRIVILEGED_NONCE_SIZE).also(SecureRandom()::nextBytes)
        return try {
            withTimeout(PROBE_TIMEOUT_MS) {
                withContext(Dispatchers.IO) {
                    val service = connection.service
                    if (!service.openSession(nonce)) {
                        return@withContext kinds.associateWith { PrivilegedProbeResult.PermissionDenied(provider) }
                    }
                    val protocol = service.getProtocolVersion(nonce)
                    val uid = service.getProviderUid(nonce)
                    if (protocol != PRIVILEGED_PROBE_PROTOCOL_VERSION || uid != connection.expectedUid) {
                        return@withContext kinds.associateWith { PrivilegedProbeResult.MalformedResponse(provider) }
                    }
                    val cancellationRegistration = currentCoroutineContext()[Job]?.invokeOnCompletion(
                        onCancelling = true,
                        invokeImmediately = true,
                    ) { cause ->
                        if (cause is CancellationException) runCatching { service.cancelSession(nonce) }
                    }
                    try {
                        val identity = PrivilegedProviderIdentity(provider, uid, protocol, connection.backendVersion)
                        kinds.associateWith { kind ->
                            val rows = when (kind) {
                                PrivilegedProbeKind.WIREGUARD -> service.probeWireGuard(nonce)
                                PrivilegedProbeKind.OVPN -> service.probeOvpn(nonce)
                                PrivilegedProbeKind.XFRM -> service.probeXfrm(nonce, imsContext)
                                PrivilegedProbeKind.BPF_NETFILTER -> service.probeBpfNetfilter(nonce)
                            }
                            if (rows == null || !PrivilegedProbeRows.validate(rows, kind.expectedCheckIds)) {
                                PrivilegedProbeResult.MalformedResponse(provider)
                            } else {
                                PrivilegedProbeResult.Available(identity, rows)
                            }
                        }
                    } finally {
                        cancellationRegistration?.dispose()
                    }
                }
            }
        } catch (_: SecurityException) {
            kinds.associateWith { PrivilegedProbeResult.PermissionDenied(provider) }
        } catch (_: DeadObjectException) {
            kinds.associateWith { PrivilegedProbeResult.Unavailable(provider) }
        } catch (_: TimeoutCancellationException) {
            kinds.associateWith { PrivilegedProbeResult.Unavailable(provider) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            kinds.associateWith { PrivilegedProbeResult.Unavailable(provider) }
        } finally {
            runCatching { connection.service.closeSession(nonce) }
            nonce.fill(0)
            runCatching(connection.close)
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 30_000L
        const val PROBE_TIMEOUT_MS = 8_000L
    }
}
