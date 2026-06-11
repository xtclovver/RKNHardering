package com.notcvnt.rknhardering.network

object NetworkInterfacePatterns {
    val VPN_INTERFACE_PATTERNS: List<Regex> = listOf(
        Regex("^tun\\d+"),
        Regex("^tap\\d+"),
        Regex("^wg\\d+"),
        Regex("^ppp\\d+"),
        Regex("^utun\\d*"),
        Regex("^zt.*"),
        Regex("^tailscale\\d*"),
        Regex("^svpn\\d*"),
        Regex("^gre\\d+"),
        Regex("^l2tp\\d+"),
        Regex("^he-ipv6.*"),
    )

    val IPSEC_INTERFACE_PATTERN: Regex = Regex("^(ipsec|xfrm).*")

    val STANDARD_INTERFACES: List<Regex> = listOf(
        Regex("^wlan.*"),
        Regex("^rmnet.*"),
        Regex("^seth.*"),   // LTE interface on select Qualcomm/MediaTek devices (e.g. Itel, Tecno, Infinix)
        Regex("^eth.*"),
        Regex("^lo$"),
        Regex("^ccmni.*"),
        Regex("^ccemni.*"),
        Regex("^dummy\\d+"),
    )

    // Base interfaces eligible for "v4-" clat de-stacking. Intentionally a strict
    // subset of STANDARD_INTERFACES: seth/dummy are excluded so that e.g.
    // "v4-seth0" keeps its name, matching the historical normalization behavior.
    // Widening this list changes detection results; reconcile with README first.
    val STACKED_BASE_INTERFACES: List<Regex> = listOf(
        Regex("^wlan.*"),
        Regex("^rmnet.*"),
        Regex("^eth.*"),
        Regex("^lo$"),
        Regex("^ccmni.*"),
        Regex("^ccemni.*"),
    )

    fun isVpnInterface(name: String?): Boolean {
        val canonical = NetworkInterfaceNameNormalizer.canonicalName(name)
        if (canonical.isNullOrBlank()) return false
        return VPN_INTERFACE_PATTERNS.any { it.matches(canonical) }
    }

    fun isIpsecInterface(name: String?): Boolean {
        val canonical = NetworkInterfaceNameNormalizer.canonicalName(name)
        if (canonical.isNullOrBlank()) return false
        return IPSEC_INTERFACE_PATTERN.matches(canonical)
    }

    fun isStandardInterface(name: String?): Boolean {
        val canonical = NetworkInterfaceNameNormalizer.canonicalName(name)
        if (canonical.isNullOrBlank()) return false
        return STANDARD_INTERFACES.any { it.matches(canonical) }
    }
}
