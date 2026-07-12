package com.notcvnt.rknhardering.network

import android.net.Network
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.io.FileDescriptor
import java.net.DatagramSocket
import java.net.Socket
import java.util.WeakHashMap

sealed interface ResolverBinding {
    data class AndroidNetworkBinding(
        val network: Network,
    ) : ResolverBinding

    data class OsDeviceBinding(
        val interfaceName: String,
        val dnsMode: DnsMode = DnsMode.CONFIGURED,
    ) : ResolverBinding {
        init {
            require(interfaceName.isNotBlank()) { "interfaceName must not be blank" }
        }
    }

    enum class DnsMode {
        CONFIGURED,
        SYSTEM,
    }
}

internal object ResolverSocketBinder {
    private val legacySharedDescriptors = WeakHashMap<Any, ParcelFileDescriptor>()
    private val setsockoptIfreqMethod by lazy(LazyThreadSafetyMode.NONE) {
        Os::class.java.getMethod(
            "setsockoptIfreq",
            FileDescriptor::class.java,
            Int::class.javaPrimitiveType,
            Int::class.javaPrimitiveType,
            String::class.java,
        )
    }

    @Volatile
    internal var bindSocketToDeviceOverride: ((Socket, String) -> Unit)? = null

    @Volatile
    internal var bindDatagramToDeviceOverride: ((DatagramSocket, String) -> Unit)? = null

    @Volatile
    internal var bindFileDescriptorToDeviceOverride: ((FileDescriptor, String) -> Unit)? = null

    internal fun resetForTests() {
        bindSocketToDeviceOverride = null
        bindDatagramToDeviceOverride = null
        bindFileDescriptorToDeviceOverride = null
    }

    fun bind(socket: Socket, binding: ResolverBinding?) {
        when (binding) {
            null -> Unit
            is ResolverBinding.AndroidNetworkBinding -> binding.network.bindSocket(socket)
            is ResolverBinding.OsDeviceBinding -> bindSocketToDevice(socket, binding.interfaceName)
        }
    }

    fun bind(socket: DatagramSocket, binding: ResolverBinding?) {
        when (binding) {
            null -> Unit
            is ResolverBinding.AndroidNetworkBinding -> binding.network.bindSocket(socket)
            is ResolverBinding.OsDeviceBinding -> bindDatagramToDevice(socket, binding.interfaceName)
        }
    }

    private fun bindSocketToDevice(socket: Socket, interfaceName: String) {
        // Android creates the native file descriptor lazily. Force its creation before fromSocket() duplicates it.
        socket.reuseAddress
        bindSocketToDeviceOverride?.invoke(socket, interfaceName) ?: bindSocketDescriptor(
            owner = socket,
            interfaceName = interfaceName,
            create = { ParcelFileDescriptor.fromSocket(socket) },
        )
    }

    private fun bindDatagramToDevice(socket: DatagramSocket, interfaceName: String) {
        bindDatagramToDeviceOverride?.invoke(socket, interfaceName) ?: bindSocketDescriptor(
            owner = socket,
            interfaceName = interfaceName,
            create = { ParcelFileDescriptor.fromDatagramSocket(socket) },
        )
    }

    private fun bindSocketDescriptor(
        owner: Any,
        interfaceName: String,
        create: () -> ParcelFileDescriptor,
    ) {
        if (usesSharedSocketDescriptor(Build.VERSION.SDK_INT)) {
            val shared = synchronized(legacySharedDescriptors) {
                legacySharedDescriptors[owner] ?: create().also { legacySharedDescriptors[owner] = it }
            }
            bindFileDescriptorToDevice(shared.fileDescriptor, interfaceName)
        } else {
            create().use { pfd ->
                bindFileDescriptorToDevice(pfd.fileDescriptor, interfaceName)
            }
        }
    }

    internal fun usesSharedSocketDescriptor(sdkInt: Int): Boolean = sdkInt < Build.VERSION_CODES.Q

    private fun bindFileDescriptorToDevice(fd: FileDescriptor, interfaceName: String) {
        bindFileDescriptorToDeviceOverride?.invoke(fd, interfaceName) ?: setsockoptIfreqMethod.invoke(
            null,
            fd,
            OsConstants.SOL_SOCKET,
            OsConstants.SO_BINDTODEVICE,
            interfaceName,
        )
    }
}
