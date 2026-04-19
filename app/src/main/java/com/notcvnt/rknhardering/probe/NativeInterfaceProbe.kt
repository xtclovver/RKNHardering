package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer

data class NativeInterface(
    val name: String,
    val canonicalName: String?,
    val index: Int,
    val flags: Long,
    val family: String,
    val address: String?,
    val netmask: String?,
    val mtu: Int,
) {
    val isUp: Boolean get() = (flags and IFF_UP) != 0L
    val isLoopback: Boolean get() = (flags and IFF_LOOPBACK) != 0L
    val isPointToPoint: Boolean get() = (flags and IFF_POINTOPOINT) != 0L
    val isRunning: Boolean get() = (flags and IFF_RUNNING) != 0L

    companion object {
        const val IFF_UP = 0x1L
        const val IFF_LOOPBACK = 0x8L
        const val IFF_POINTOPOINT = 0x10L
        const val IFF_RUNNING = 0x40L
    }
}

data class NativeRouteEntry(
    val interfaceName: String,
    val destinationHex: String,
    val gatewayHex: String,
    val flags: Int,
    val isDefault: Boolean,
)

data class NativeMapsFinding(
    val kind: String,
    val marker: String?,
    val detail: String?,
)

data class NativeSymbolInfo(
    val symbol: String,
    val address: String?,
    val library: String?,
    val missing: Boolean,
)

object NativeInterfaceProbe {

    fun parseIfAddrsRows(rows: Array<String>): List<NativeInterface> {
        return rows.mapNotNull { row -> parseIfAddrRow(row) }
    }

    internal fun parseIfAddrRow(row: String): NativeInterface? {
        val parts = row.split('|')
        if (parts.size < 7) return null
        val name = parts[0]
        val index = parts[1].toIntOrNull() ?: 0
        val flags = parts[2].toLongOrNull() ?: 0L
        val family = parts[3]
        val addr = parts[4].takeIf { it.isNotBlank() }
        val mask = parts[5].takeIf { it.isNotBlank() }
        val mtu = parts[6].toIntOrNull() ?: -1
        return NativeInterface(
            name = name,
            canonicalName = NetworkInterfaceNameNormalizer.canonicalName(name),
            index = index,
            flags = flags,
            family = family,
            address = addr,
            netmask = mask,
            mtu = mtu,
        )
    }

    fun collectInterfaces(): List<NativeInterface> {
        val rows = NativeSignsBridge.getIfAddrs()
        return parseIfAddrsRows(rows)
    }

    fun parseProcRoute(content: String?): List<NativeRouteEntry> {
        if (content.isNullOrBlank()) return emptyList()
        val lines = content.lines()
        if (lines.isEmpty()) return emptyList()
        val data = lines.drop(1)
        val result = mutableListOf<NativeRouteEntry>()
        for (line in data) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val parts = trimmed.split(Regex("\\s+"))
            if (parts.size < 4) continue
            val iface = parts[0]
            val dest = parts[1]
            val gateway = parts[2]
            val flags = parts[3].toIntOrNull(16) ?: 0
            val isDefault = dest == "00000000"
            result.add(
                NativeRouteEntry(
                    interfaceName = iface,
                    destinationHex = dest,
                    gatewayHex = gateway,
                    flags = flags,
                    isDefault = isDefault,
                ),
            )
        }
        return result
    }

    fun collectRoutes(): List<NativeRouteEntry> {
        val content = NativeSignsBridge.readProcFile("/proc/net/route")
            ?: NativeSignsBridge.readProcFile("/proc/self/net/route")
        return parseProcRoute(content)
    }

    fun parseMapsSummary(rows: Array<String>): List<NativeMapsFinding> {
        return rows.mapNotNull { row ->
            val parts = row.split('|', limit = 3)
            if (parts.isEmpty()) return@mapNotNull null
            when (parts[0]) {
                "marker" -> NativeMapsFinding(
                    kind = "marker",
                    marker = parts.getOrNull(1)?.takeIf { it.isNotBlank() },
                    detail = parts.getOrNull(2)?.takeIf { it.isNotBlank() },
                )
                "rwx_large" -> NativeMapsFinding(
                    kind = "rwx_large",
                    marker = null,
                    detail = parts.getOrNull(1)?.takeIf { it.isNotBlank() },
                )
                else -> null
            }
        }
    }

    fun collectMapsFindings(): List<NativeMapsFinding> {
        val rows = NativeSignsBridge.readSelfMapsSummary()
        return parseMapsSummary(rows)
    }

    fun parseLibraryIntegrity(rows: Array<String>): List<NativeSymbolInfo> {
        return rows.mapNotNull { row ->
            val parts = row.split('|', limit = 3)
            val symbol = parts.getOrNull(0)?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            val addr = parts.getOrNull(1)?.takeIf { it.isNotBlank() }
            val lib = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
            val missing = addr.isNullOrBlank() || lib == "missing"
            NativeSymbolInfo(
                symbol = symbol,
                address = addr,
                library = if (missing) null else lib,
                missing = missing,
            )
        }
    }

    fun collectLibraryIntegrity(): List<NativeSymbolInfo> {
        val rows = NativeSignsBridge.libraryIntegrity()
        return parseLibraryIntegrity(rows)
    }
}
