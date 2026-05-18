package com.notcvnt.rknhardering.probe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.LocalProxyOwner
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetAddress

data class LocalSocketListener(
    val protocol: String,
    val host: String,
    val port: Int,
    val state: String,
    val uid: Int?,
    val inode: Long?,
    val owner: LocalProxyOwner?,
)

object LocalSocketInspector {

    private val procNetFiles = listOf(
        "tcp" to "/proc/net/tcp",
        "tcp6" to "/proc/net/tcp6",
        "udp" to "/proc/net/udp",
        "udp6" to "/proc/net/udp6",
    )

    fun collect(context: Context, protocols: Set<String> = procNetFiles.mapTo(linkedSetOf()) { it.first }): List<LocalSocketListener> {
        val ownerResolver: (Int) -> LocalProxyOwner = { uid -> resolveOwner(context, uid) }
        return procNetFiles.flatMap { (protocol, path) ->
            if (protocol !in protocols) return@flatMap emptyList()
            val file = File(path)
            if (!file.exists()) return@flatMap emptyList()
            runCatching {
                BufferedReader(FileReader(file)).use { reader ->
                    parseProcNetListeners(reader.readLines(), protocol, ownerResolver)
                }
            }.getOrDefault(emptyList())
        }
    }

    internal fun parseProcNetListeners(
        lines: List<String>,
        protocol: String,
        ownerResolver: ((Int) -> LocalProxyOwner?)? = null,
    ): List<LocalSocketListener> {
        return lines.drop(1).mapNotNull { line ->
            val parts = line.trim().split("\\s+".toRegex())
            if (parts.size < 10) return@mapNotNull null

            val localAddress = parts[1]
            val state = parts[3]
            if (protocol.startsWith("tcp") && state != "0A") return@mapNotNull null
            if (protocol.startsWith("udp") && state !in setOf("07", "0A")) return@mapNotNull null

            val hostPort = localAddress.split(":")
            if (hostPort.size != 2) return@mapNotNull null

            val host = decodeProcAddress(hostPort[0], ipv6 = protocol.endsWith("6")) ?: return@mapNotNull null
            val port = hostPort[1].toIntOrNull(16) ?: return@mapNotNull null
            val uid = parts.getOrNull(7)?.toIntOrNull()
            val inode = parts.getOrNull(9)?.toLongOrNull()

            LocalSocketListener(
                protocol = protocol,
                host = host.lowercase(),
                port = port,
                state = state,
                uid = uid,
                inode = inode,
                owner = uid?.let { ownerResolver?.invoke(it) },
            )
        }
    }

    internal fun resolveOwner(context: Context, uid: Int): LocalProxyOwner {
        val pm = context.packageManager
        val packageNames = pm.getPackagesForUid(uid)?.filterNotNull().orEmpty()
        val uidName = runCatching { pm.getNameForUid(uid) }.getOrNull()
        return resolveOwner(uid, packageNames, uidName) { packageName ->
            resolveApplicationLabel(pm, packageName)
        }
    }

    internal fun resolveOwner(
        uid: Int,
        packageNames: List<String>,
        uidName: String?,
        appLabelResolver: (String) -> String?,
    ): LocalProxyOwner {
        val distinctPackageNames = packageNames.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        val labels = if (distinctPackageNames.isNotEmpty()) {
            distinctPackageNames.mapNotNull { packageName ->
                appLabelResolver(packageName)?.trim()?.takeIf { it.isNotEmpty() }
            }.distinct()
        } else {
            uidName?.trim()?.takeIf { it.isNotEmpty() }?.let(::listOf).orEmpty()
        }

        val confidence = when {
            distinctPackageNames.size == 1 -> EvidenceConfidence.HIGH
            distinctPackageNames.size > 1 -> EvidenceConfidence.MEDIUM
            labels.isNotEmpty() -> EvidenceConfidence.LOW
            else -> EvidenceConfidence.LOW
        }

        return LocalProxyOwner(
            uid = uid,
            packageNames = distinctPackageNames,
            appLabels = labels,
            confidence = confidence,
        )
    }

    private fun resolveApplicationLabel(pm: PackageManager, packageName: String): String? {
        return runCatching {
            val appInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(packageName, 0)
            }
            pm.getApplicationLabel(appInfo).toString()
        }.getOrNull()
    }

    private fun decodeProcAddress(hexAddress: String, ipv6: Boolean): String? {
        return try {
            val bytes = hexAddress.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val orderedBytes = if (ipv6) {
                bytes
                    .asList()
                    .chunked(4)
                    .flatMap { word -> word.asReversed() }
                    .toByteArray()
            } else {
                bytes.reversedArray()
            }
            InetAddress.getByAddress(orderedBytes).hostAddress
        } catch (_: Exception) {
            null
        }
    }
}
