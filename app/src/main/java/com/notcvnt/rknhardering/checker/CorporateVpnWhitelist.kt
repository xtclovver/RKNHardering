package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.GeoIpFacts

data class CorporateVpnEntry(
    val name: String,
    val asns: Set<String> = emptySet(),
    val orgPatterns: Set<String> = emptySet(),
    val ispPatterns: Set<String> = emptySet(),
    val ipRanges: Set<String> = emptySet(),
) {
    fun matches(facts: GeoIpFacts): Boolean {
        if (facts.asnCode in asns) return true
        if (facts.org?.let { org -> orgPatterns.any { pattern -> org.contains(pattern, ignoreCase = true) } } == true) return true
        if (facts.isp?.let { isp -> ispPatterns.any { pattern -> isp.contains(pattern, ignoreCase = true) } } == true) return true
        return false
    }
}

object CorporateVpnWhitelist {

    private val entries: List<CorporateVpnEntry> = listOf(
        CorporateVpnEntry(
            name = "Sberbank Corporate VPN",
            asns = setOf("35237", "33844", "47457", "206673"),
            orgPatterns = setOf("Sberbank", "Sberbank of Russia", "Sber"),
            ispPatterns = setOf("Sberbank"),
        ),
        CorporateVpnEntry(
            name = "VTB Bank Corporate VPN",
            asns = setOf("41551", "24823", "41430"),
            orgPatterns = setOf("VTB Bank", "VTB-AS"),
            ispPatterns = setOf("VTB"),
        ),
        CorporateVpnEntry(
            name = "Gazprombank Corporate VPN",
            asns = setOf("35022"),
            orgPatterns = setOf("Gazprombank", "GPB"),
        ),
        CorporateVpnEntry(
            name = "Alfa-Bank Corporate VPN",
            asns = setOf("15632", "208811"),
            orgPatterns = setOf("Alfa-Bank", "AlfaBank", "ALFA-BANK"),
        ),
        CorporateVpnEntry(
            name = "Rosselkhozbank Corporate VPN",
            asns = setOf("41615"),
            orgPatterns = setOf("Rosselkhozbank", "Russian Agricultural Bank", "RSHB"),
        ),
        CorporateVpnEntry(
            name = "Central Bank of Russia (CBR)",
            asns = setOf("4783"),
            orgPatterns = setOf("Central Bank of the Russian Federation", "Bank of Russia", "CBR"),
        ),
        CorporateVpnEntry(
            name = "Gazprom Corporate VPN",
            asns = setOf("20576", "39045", "25032", "15757"),
            orgPatterns = setOf("Gazprom", "Gazprom telecom", "Gazsvyaz", "Gaztelecom"),
        ),
        CorporateVpnEntry(
            name = "Rosneft Corporate VPN",
            asns = setOf("48079"),
            orgPatterns = setOf("Rosneft", "NK Rosneft"),
        ),
        CorporateVpnEntry(
            name = "Russian Railways (RZD) Corporate VPN",
            asns = setOf("60569"),
            orgPatterns = setOf("Russian Railways", "RZD", "Rossiyskie Zheleznye Dorogi"),
        ),
        CorporateVpnEntry(
            name = "Aeroflot Corporate VPN",
            asns = setOf("48065"),
            orgPatterns = setOf("Aeroflot"),
        ),
        CorporateVpnEntry(
            name = "Rostelecom Corporate VPN",
            asns = setOf("12389", "8342"),
            orgPatterns = setOf("Rostelecom", "RTComm"),
            ispPatterns = setOf("Rostelecom"),
        ),
        CorporateVpnEntry(
            name = "MTS Corporate VPN",
            asns = setOf("8359", "16256"),
            orgPatterns = setOf("MTS", "Mobile TeleSystems", "MTS PJSC"),
        ),
        CorporateVpnEntry(
            name = "Beeline/VimpelCom Corporate VPN",
            asns = setOf("8402", "3216"),
            orgPatterns = setOf("VimpelCom", "Vimpelcom", "Beeline", "VEON"),
        ),
        CorporateVpnEntry(
            name = "MegaFon Corporate VPN",
            asns = setOf("31133", "6850", "25159"),
            orgPatterns = setOf("MegaFon", "Megafon", "MF-MGSM"),
        ),
        CorporateVpnEntry(
            name = "TransTeleCom Corporate VPN",
            asns = setOf("20485"),
            orgPatterns = setOf("TransTeleCom", "TTK"),
        ),
        CorporateVpnEntry(
            name = "ER-Telecom (Dom.ru) Corporate VPN",
            asns = setOf("9049", "12768", "31363"),
            orgPatterns = setOf("ER-Telecom", "Dom.ru", "JSC ER-Telecom Holding"),
        ),
        CorporateVpnEntry(
            name = "Yandex Cloud Corporate VPN",
            asns = setOf("13238", "44534", "200350", "208682"),
            orgPatterns = setOf("Yandex", "Yandex Cloud", "Yandex.Cloud"),
            ispPatterns = setOf("Yandex"),
        ),
        CorporateVpnEntry(
            name = "VK Corporate VPN",
            asns = setOf("47764", "47541", "28709", "49797"),
            orgPatterns = setOf("VK", "VKontakte", "Mail.Ru", "LLC VK"),
            ispPatterns = setOf("VK", "Mail.Ru"),
        ),
        CorporateVpnEntry(
            name = "Ministry of Digital Development",
            asns = setOf("49604"),
            orgPatterns = setOf("Ministry of Digital Development", "Minkomsvyaz"),
        ),
    )

    @Volatile
    internal var overrides: List<CorporateVpnEntry>? = null

    private val activeEntries: List<CorporateVpnEntry>
        get() = overrides ?: entries

    fun match(facts: GeoIpFacts): CorporateVpnEntry? {
        return activeEntries.firstOrNull { it.matches(facts) }
    }

    fun isWhitelisted(facts: GeoIpFacts): Boolean {
        return match(facts) != null
    }
}
