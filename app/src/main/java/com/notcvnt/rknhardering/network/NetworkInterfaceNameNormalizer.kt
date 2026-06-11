package com.notcvnt.rknhardering.network

object NetworkInterfaceNameNormalizer {
    private const val STACKED_V4_PREFIX = "v4-"

    fun canonicalName(name: String?): String? {
        if (name.isNullOrBlank()) return name
        val baseName = name.removePrefix(STACKED_V4_PREFIX)
        if (baseName == name) return name
        return baseName.takeIf(::isStandardBaseInterface) ?: name
    }

    private fun isStandardBaseInterface(name: String): Boolean {
        return NetworkInterfacePatterns.STACKED_BASE_INTERFACES.any { it.matches(name) }
    }
}
