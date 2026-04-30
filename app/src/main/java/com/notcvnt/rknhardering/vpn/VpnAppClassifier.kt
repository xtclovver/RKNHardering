package com.notcvnt.rknhardering.vpn

import java.nio.charset.StandardCharsets

data class VpnCoreInspectionResult(
    val coreType: String,
    val corePath: String? = null,
    val goVersion: String? = null,
)

object VpnAppClassifier {
    const val APP_TYPE_V2RAYNG = "V2RayNG"
    const val APP_TYPE_CLASH_FOR_ANDROID = "ClashForAndroid"
    const val APP_TYPE_SING_BOX = "sing-box"
    const val APP_TYPE_SAGERNET = "SagerNet"
    const val APP_TYPE_SHADOWSOCKS_ANDROID = "shadowsocks-android"

    const val CORE_TYPE_SING_BOX = "sing-box"
    const val CORE_TYPE_XRAY_V2RAY = "Xray/V2Ray"
    const val CORE_TYPE_CLASH_MIHOMO = "Clash/Mihomo"
    const val CORE_TYPE_WIREGUARD = "WireGuard"
    const val CORE_TYPE_OPENVPN = "OpenVPN"
    const val CORE_TYPE_SHADOWSOCKS = "Shadowsocks"

    private val appTypeMarkers = listOf(
        APP_TYPE_V2RAYNG to listOf(
            "com.v2ray.ang",
            ".dto.V2rayConfig",
            ".service.V2RayVpnService",
        ),
        APP_TYPE_CLASH_FOR_ANDROID to listOf(
            "com.github.kr328.clash",
            ".core.Clash",
            ".service.TunService",
        ),
        APP_TYPE_SING_BOX to listOf("io.nekohasekai.sfa"),
        APP_TYPE_SAGERNET to listOf(
            "io.nekohasekai.sagernet",
            ".fmt.ConfigBuilder",
        ),
        APP_TYPE_SHADOWSOCKS_ANDROID to listOf(
            "com.github.shadowsocks",
            ".bg.VpnService",
            "GuardedProcessPool",
        ),
    )

    private val coreTypeMarkers = listOf(
        CORE_TYPE_SING_BOX to listOf("sing-box", "singbox"),
        CORE_TYPE_XRAY_V2RAY to listOf("xray", "v2ray", "v2fly"),
        CORE_TYPE_CLASH_MIHOMO to listOf("mihomo", "clash"),
        CORE_TYPE_WIREGUARD to listOf("wireguard"),
        CORE_TYPE_OPENVPN to listOf("openvpn", "ovpn"),
        CORE_TYPE_SHADOWSOCKS to listOf("shadowsocks"),
    )

    fun detectAppType(content: ByteArray): String? {
        return detectFirst(content, appTypeMarkers, ignoreCase = false)
    }

    fun detectCore(content: ByteArray, entryName: String? = null): VpnCoreInspectionResult? {
        val searchContent = if (entryName.isNullOrBlank()) {
            content
        } else {
            entryName.encodeToByteArray() + byteArrayOf(0) + content
        }
        val coreType = detectFirst(searchContent, coreTypeMarkers, ignoreCase = true) ?: return null
        return VpnCoreInspectionResult(
            coreType = coreType,
            corePath = entryName,
            goVersion = findGoVersion(content),
        )
    }

    fun findGoVersion(content: ByteArray): String? {
        val text = content.toString(StandardCharsets.ISO_8859_1)
        return Regex("""go1(?:\.\d+){1,2}""").find(text)?.value
    }

    private fun detectFirst(
        content: ByteArray,
        typedMarkers: List<Pair<String, List<String>>>,
        ignoreCase: Boolean,
    ): String? {
        val text = content.toString(StandardCharsets.ISO_8859_1)
        val normalizedDexText = text.replace('/', '.').replace('$', '.')
        return typedMarkers.firstOrNull { (_, markers) ->
            markers.any { marker ->
                text.contains(marker, ignoreCase = ignoreCase) ||
                    normalizedDexText.contains(marker, ignoreCase = ignoreCase)
            }
        }?.first
    }
}
