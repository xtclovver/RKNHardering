package com.notcvnt.rknhardering.vpn

import com.notcvnt.rknhardering.model.VpnAppKind

enum class VpnClientSignal {
    VPN_SERVICE,
    LOCAL_PROXY,
    XRAY_API,
}

data class VpnAppSignature(
    val packageName: String,
    val appName: String,
    val family: String,
    val kind: VpnAppKind,
    val defaultPorts: Set<Int> = emptySet(),
    val signals: Set<VpnClientSignal> = setOf(VpnClientSignal.VPN_SERVICE),
)

object VpnAppCatalog {

    const val FAMILY_XRAY = "Xray/V2Ray"
    const val FAMILY_SING_BOX = "sing-box"
    const val FAMILY_NEKOBOX = "NekoBox"
    const val FAMILY_HAPP = "HAPP"
    const val FAMILY_KARING = "Karing"
    const val FAMILY_NEBULA = "Nebula"
    const val FAMILY_HIDDIFY = "Hiddify"
    const val FAMILY_MIKUBOX = "MikuBox"
    const val FAMILY_AEROBOX = "AeroBox"
    const val FAMILY_FIREFLY = "FireflyVPN"
    const val FAMILY_V2FLY = "V2fly"
    const val FAMILY_FLARE = "FlareVPN"
    const val FAMILY_HUSI = "Husi"
    const val FAMILY_V2RAYTUN = "v2RayTun"
    const val FAMILY_V2BOX = "v2box"
    const val FAMILY_CATBOX = "CatBox"
    const val FAMILY_EXCLAVE = "Exclave"
    const val FAMILY_CLASH = "Clash"
    const val FAMILY_SHADOWSOCKS = "Shadowsocks"
    const val FAMILY_TOR = "Tor/Orbot"
    const val FAMILY_OUTLINE = "Outline"
    const val FAMILY_WIREGUARD = "WireGuard"
    const val FAMILY_IPSEC = "IPSec/L2TP"
    const val FAMILY_PSIPHON = "Psiphon"
    const val FAMILY_LANTERN = "Lantern"
    const val FAMILY_DPI = "DPI bypass"
    const val FAMILY_AMNEZIA = "AmneziaVPN"
    const val FAMILY_TG_WS_PROXY = "tg-ws-proxy"
    const val FAMILY_TERMUX = "Termux"

    val signatures: List<VpnAppSignature> = listOf(
        VpnAppSignature(
            packageName = "com.aerobox",
            appName = "AeroBox",
            family = FAMILY_AEROBOX,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 2080, 2081),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "com.v2ray.ang",
            appName = "v2rayNG",
            family = FAMILY_XRAY,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 10808, 10809),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY, VpnClientSignal.XRAY_API),
        ),
        VpnAppSignature(
            packageName = "io.github.saeeddev94.xray",
            appName = "Xray",
            family = FAMILY_XRAY,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 10808, 10809),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY, VpnClientSignal.XRAY_API),
        ),
        VpnAppSignature(
            packageName = "io.nekohasekai.sfa",
            appName = "sing-box",
            family = FAMILY_SING_BOX,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 2080, 2081),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "moe.nb4a",
            appName = "NekoBox",
            family = FAMILY_NEKOBOX,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 2080, 2081),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "io.nekohasekai.sagernet",
            appName = "CatBox",
            family = FAMILY_CATBOX,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(1080, 2080, 2081),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "uwu.mb4a",
            appName = "MikuBox",
            family = FAMILY_MIKUBOX,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(1080, 2080, 2081),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "xyz.a202132.app",
            appName = "FireflyVPN",
            family = FAMILY_FIREFLY,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(1080, 2080, 2081),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "com.nebula.karing",
            appName = "Karing",
            family = FAMILY_KARING,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(3067),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "app.husi.singbox",
            appName = "Husi",
            family = FAMILY_HUSI,
            kind = VpnAppKind.GENERIC_VPN,
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "com.v2raytun.android",
            appName = "v2RayTun",
            family = FAMILY_V2RAYTUN,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(1080, 10808, 10809),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY, VpnClientSignal.XRAY_API),
        ),
        VpnAppSignature(
            packageName = "dev.hexasoftware.v2box",
            appName = "v2box",
            family = FAMILY_V2BOX,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(1080, 10808, 10809),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY, VpnClientSignal.XRAY_API),
        ),
        VpnAppSignature(
            packageName = "net.defined.mobileNebula",
            appName = "Nebula",
            family = FAMILY_NEBULA,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "com.github.dyhkwong.sagernet",
            appName = "Exclave",
            family = FAMILY_EXCLAVE,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "com.happproxy",
            appName = "HAPP VPN",
            family = FAMILY_HAPP,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 8080),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY, VpnClientSignal.XRAY_API),
        ),
        VpnAppSignature(
            packageName = "app.hiddify.com",
            appName = "Hiddify",
            family = FAMILY_HIDDIFY,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 12334),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "com.github.metacubex.clash.meta",
            appName = "ClashMeta for Android",
            family = FAMILY_CLASH,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(7890, 7891),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "com.github.shadowsocks",
            appName = "Shadowsocks",
            family = FAMILY_SHADOWSOCKS,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(1080),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "com.github.shadowsocks.tv",
            appName = "Shadowsocks TV",
            family = FAMILY_SHADOWSOCKS,
            kind = VpnAppKind.GENERIC_VPN,
            defaultPorts = setOf(1080),
            signals = setOf(VpnClientSignal.VPN_SERVICE, VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "io.github.dovecoteescapee.byedpi",
            appName = "ByeDPI",
            family = FAMILY_DPI,
            kind = VpnAppKind.TARGETED_BYPASS,
        ),
        VpnAppSignature(
            packageName = "com.romanvht.byebyedpi",
            appName = "ByeByeDPI",
            family = FAMILY_DPI,
            kind = VpnAppKind.TARGETED_BYPASS,
        ),
        VpnAppSignature(
            packageName = "org.outline.android.client",
            appName = "Outline",
            family = FAMILY_OUTLINE,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "com.psiphon3",
            appName = "Psiphon",
            family = FAMILY_PSIPHON,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "org.getlantern.lantern",
            appName = "Lantern",
            family = FAMILY_LANTERN,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "com.wireguard.android",
            appName = "WireGuard",
            family = FAMILY_WIREGUARD,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "com.strongswan.android",
            appName = "strongSwan",
            family = FAMILY_IPSEC,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "org.torproject.android",
            appName = "Tor Browser",
            family = FAMILY_TOR,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "info.guardianproject.orfox",
            appName = "Orbot",
            family = FAMILY_TOR,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "org.torproject.torbrowser",
            appName = "Tor Browser (official)",
            family = FAMILY_TOR,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "org.amnezia.vpn",
            appName = "AmneziaVPN",
            family = FAMILY_AMNEZIA,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "org.amnezia.awg",
            appName = "AmneziaWG",
            family = FAMILY_AMNEZIA,
            kind = VpnAppKind.GENERIC_VPN,
        ),
        VpnAppSignature(
            packageName = "com.termux",
            appName = "Termux",
            family = FAMILY_TERMUX,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 1443),
            signals = setOf(VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "org.aspect.tgwsproxy",
            appName = "tg-ws-proxy",
            family = FAMILY_TG_WS_PROXY,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 1443),
            signals = setOf(VpnClientSignal.LOCAL_PROXY),
        ),
        VpnAppSignature(
            packageName = "org.aspect.tgwsproxy.android",
            appName = "tg-ws-proxy (Android)",
            family = FAMILY_TG_WS_PROXY,
            kind = VpnAppKind.TARGETED_BYPASS,
            defaultPorts = setOf(1080, 1443),
            signals = setOf(VpnClientSignal.LOCAL_PROXY),
        ),
    )

    val knownPackageNames: Set<String> = signatures.mapTo(linkedSetOf()) { it.packageName }

    val localhostProxyPorts: List<Int> = signatures
        .flatMapTo(linkedSetOf()) { it.defaultPorts }
        .sorted()

    fun findByPackageName(packageName: String): VpnAppSignature? =
        signatures.firstOrNull { it.packageName == packageName }

    fun familiesForPort(port: Int): Set<String> =
        signatures.filter { port in it.defaultPorts }.mapTo(linkedSetOf()) { it.family }
}
