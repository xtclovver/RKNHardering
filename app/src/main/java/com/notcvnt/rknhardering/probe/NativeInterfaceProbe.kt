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
    val ifaceType: Int? = null,
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
    val source: RouteSource = RouteSource.PROC,
    val family: Int = 0,
    val destination: String? = null,
    val gateway: String? = null,
    val prefSrc: String? = null,
    val metric: Int? = null,
    val scope: String? = null,
    val type: String? = null,
    val table: Int? = null,
    val prefixLen: Int? = null,
) {
    enum class RouteSource { PROC, NETLINK }
}

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

data class NativeRootFinding(
    val kind: String,
    val detail: String?,
)

data class NativeEmulatorFinding(
    val kind: String,
    val detail: String?,
)

object NativeInterfaceProbe {
    private const val IPV4_DEFAULT_DESTINATION = "00000000"
    private const val IPV6_DEFAULT_DESTINATION = "00000000000000000000000000000000"
    private const val IPV6_DEFAULT_PREFIX_LENGTH = "00"

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
        val ifaceType = parts.getOrNull(7)?.toIntOrNull()?.takeIf { it >= 0 }
        return NativeInterface(
            name = name,
            canonicalName = NetworkInterfaceNameNormalizer.canonicalName(name),
            index = index,
            flags = flags,
            family = family,
            address = addr,
            netmask = mask,
            mtu = mtu,
            ifaceType = ifaceType,
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
            val isDefault = dest == IPV4_DEFAULT_DESTINATION
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

    fun parseProcIpv6Route(content: String?): List<NativeRouteEntry> {
        if (content.isNullOrBlank()) return emptyList()

        return content.lineSequence()
            .mapNotNull { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty()) return@mapNotNull null

                val parts = trimmed.split(Regex("\\s+"))
                if (parts.size < 10) return@mapNotNull null

                val destination = parts[0]
                val prefixLength = parts[1]
                val gateway = parts[4]
                val flags = parts[8].toIntOrNull(16) ?: 0
                val iface = parts[9]

                NativeRouteEntry(
                    interfaceName = iface,
                    destinationHex = destination,
                    gatewayHex = gateway,
                    flags = flags,
                    isDefault = destination == IPV6_DEFAULT_DESTINATION && prefixLength == IPV6_DEFAULT_PREFIX_LENGTH,
                )
            }
            .toList()
    }

    fun parseNetlinkRoutes(rows: Array<String>): List<NativeRouteEntry> {
        if (rows.isEmpty()) return emptyList()
        val result = mutableListOf<NativeRouteEntry>()
        for (row in rows) {
            if (!row.startsWith("route|")) continue
            val tokens = row.split('|')
            var family = 0
            var dst: String? = null
            var prefixLen: Int? = null
            var gateway: String? = null
            var prefSrc: String? = null
            var dev: String? = null
            var oif: Int? = null
            var metric: Int? = null
            var scope: String? = null
            var type: String? = null
            var table: Int? = null
            for (token in tokens) {
                val eq = token.indexOf('=')
                if (eq <= 0) continue
                val key = token.substring(0, eq)
                val value = token.substring(eq + 1)
                when (key) {
                    "family" -> family = value.toIntOrNull() ?: 0
                    "dst" -> {
                        val slash = value.indexOf('/')
                        if (slash > 0) {
                            dst = value.substring(0, slash)
                            prefixLen = value.substring(slash + 1).toIntOrNull()
                        } else {
                            dst = value
                        }
                    }
                    "via" -> gateway = value
                    "prefsrc" -> prefSrc = value
                    "dev" -> dev = value
                    "oif" -> oif = value.toIntOrNull()
                    "metric" -> metric = value.toIntOrNull()
                    "scope" -> scope = value
                    "type" -> type = value
                    "table" -> table = value.toIntOrNull()
                }
            }
            val iface = dev ?: oif?.let { "if$it" } ?: continue
            val isDefault = (dst == null || dst == "default" || dst == "0.0.0.0" || dst == "::") &&
                (prefixLen == null || prefixLen == 0)
            val destHex = dst?.let { destinationToHex(it, family) } ?: defaultDestinationHex(family)
            val gwHex = gateway?.let { destinationToHex(it, family) } ?: zeroDestinationHex(family)
            result.add(
                NativeRouteEntry(
                    interfaceName = iface,
                    destinationHex = destHex,
                    gatewayHex = gwHex,
                    flags = 0,
                    isDefault = isDefault,
                    source = NativeRouteEntry.RouteSource.NETLINK,
                    family = family,
                    destination = dst,
                    gateway = gateway,
                    prefSrc = prefSrc,
                    metric = metric,
                    scope = scope,
                    type = type,
                    table = table,
                    prefixLen = prefixLen,
                ),
            )
        }
        return result
    }

    fun collectNetlinkRoutes(): List<NativeRouteEntry> {
        val rows = runCatching { NativeSignsBridge.netlinkRouteDump(0) }.getOrDefault(emptyArray())
        return parseNetlinkRoutes(rows)
    }

    fun collectRoutes(): List<NativeRouteEntry> {
        val netlinkRoutes = collectNetlinkRoutes()

        val ipv4Routes = parseProcRoute(
            readFirstAvailableProcFile(
                "/proc/net/route",
                "/proc/self/net/route",
            ),
        )
        val ipv6Routes = parseProcIpv6Route(
            readFirstAvailableProcFile(
                "/proc/net/ipv6_route",
                "/proc/self/net/ipv6_route",
            ),
        )
        val procRoutes = ipv4Routes + ipv6Routes

        if (netlinkRoutes.isEmpty()) return procRoutes
        if (procRoutes.isEmpty()) return netlinkRoutes

        val seen = netlinkRoutes.map { routeKey(it) }.toMutableSet()
        val merged = netlinkRoutes.toMutableList()
        for (proc in procRoutes) {
            if (seen.add(routeKey(proc))) merged += proc
        }
        return merged
    }

    private fun routeKey(entry: NativeRouteEntry): String {
        val familyBucket = when {
            entry.family == 10 -> 6
            entry.destinationHex.length > 8 -> 6
            else -> 4
        }
        return buildString {
            append(entry.interfaceName)
            append('|')
            append(familyBucket)
            append('|')
            append(if (entry.isDefault) "default" else entry.destinationHex)
        }
    }

    private fun destinationToHex(value: String, family: Int): String {
        if (value.isBlank()) return zeroDestinationHex(family)
        if (value == "default") return defaultDestinationHex(family)
        return runCatching {
            val addr = java.net.InetAddress.getByName(value)
            val bytes = addr.address
            bytes.joinToString("") { b -> "%02X".format(b.toInt() and 0xFF) }
        }.getOrDefault(zeroDestinationHex(family))
    }

    private fun defaultDestinationHex(family: Int): String {
        return if (family == 10) IPV6_DEFAULT_DESTINATION else IPV4_DEFAULT_DESTINATION
    }

    private fun zeroDestinationHex(family: Int): String {
        return if (family == 10) IPV6_DEFAULT_DESTINATION else IPV4_DEFAULT_DESTINATION
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

    private fun readFirstAvailableProcFile(vararg paths: String): String? {
        for (path in paths) {
            NativeSignsBridge.readProcFile(path)?.let { return it }
        }
        return null
    }

    fun parseRootFindings(rows: Array<String>): List<NativeRootFinding> {
        return rows.mapNotNull { row ->
            val sep = row.indexOf('|')
            if (sep <= 0) return@mapNotNull null
            val kind = row.substring(0, sep)
            val detail = row.substring(sep + 1).takeIf { it.isNotBlank() }
            NativeRootFinding(kind = kind, detail = detail)
        }
    }

    fun collectRootFindings(): List<NativeRootFinding> {
        val rows = NativeSignsBridge.detectRoot()
        return parseRootFindings(rows)
    }

    fun parseEmulatorFindings(rows: Array<String>): List<NativeEmulatorFinding> {
        return rows.mapNotNull { row ->
            val sep = row.indexOf('|')
            if (sep <= 0) return@mapNotNull null
            val kind = row.substring(0, sep)
            val detail = row.substring(sep + 1).takeIf { it.isNotBlank() }
            NativeEmulatorFinding(kind = kind, detail = detail)
        }
    }

    fun collectEmulatorFindings(): List<NativeEmulatorFinding> {
        val rows = NativeSignsBridge.detectEmulator()
        return parseEmulatorFindings(rows)
    }
}
