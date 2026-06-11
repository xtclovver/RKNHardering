package com.notcvnt.rknhardering.customcheck.marketplace

data class MarketplaceCatalog(
    val schemaVersion: Int,
    val updatedAt: String,
    val entries: List<MarketplaceEntry>,
    // True only if catalog.json was downloaded together with a catalog.sig that
    // validated against the bundled marketplace public key. Drives whether the
    // catalog can confer official/verified status on entries.
    val signatureValid: Boolean = false,
)

data class MarketplaceEntry(
    val id: String,
    val name: String,
    val description: String,
    val author: String,
    val version: String,
    val official: Boolean,
    val verified: Boolean,
    val profileUrl: String,
    val tags: List<String>,
    val createdAt: String,
    val updatedAt: String,
    val expectedHash: String? = null,
)
