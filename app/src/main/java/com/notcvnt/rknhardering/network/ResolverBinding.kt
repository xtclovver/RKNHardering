package com.notcvnt.rknhardering.network

import android.net.Network
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.io.FileDescriptor
import java.net.DatagramSocket
import java.net.Socket

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

    internal fun resetForTests() {
        bindSocketToDeviceOverride = null
        bindDatagramToDeviceOverride = null
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
        bindSocketToDeviceOverride?.invoke(socket, interfaceName) ?: ParcelFileDescriptor.fromSocket(socket).use { pfd ->
            bindFileDescriptorToDevice(
                pfd.fileDescriptor,
                interfaceName,
            )
        }
    }

    private fun bindDatagramToDevice(socket: DatagramSocket, interfaceName: String) {
        bindDatagramToDeviceOverride?.invoke(socket, interfaceName) ?: ParcelFileDescriptor.fromDatagramSocket(socket).use { pfd ->
            bindFileDescriptorToDevice(
                pfd.fileDescriptor,
                interfaceName,
            )
        }
    }

    private fun bindFileDescriptorToDevice(fd: FileDescriptor, interfaceName: String) {
        setsockoptIfreqMethod.invoke(
            null,
            fd,
            OsConstants.SOL_SOCKET,
            OsConstants.SO_BINDTODEVICE,
            interfaceName,
        )
    }
}
