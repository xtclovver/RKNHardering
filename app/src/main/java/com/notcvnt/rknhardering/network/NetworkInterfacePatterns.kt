package com.notcvnt.rknhardering.network

object NetworkInterfacePatterns {
    val VPN_INTERFACE_PATTERNS: List<Regex> = listOf(
        Regex("^tun\\d+"),
        Regex("^tap\\d+"),
        Regex("^wg\\d+"),
        Regex("^ppp\\d+"),
    )

    val IPSEC_INTERFACE_PATTERN: Regex = Regex("^ipsec.*")

    val STANDARD_INTERFACES: List<Regex> = listOf(
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
