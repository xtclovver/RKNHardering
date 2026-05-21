package com.notcvnt.rknhardering.customcheck.marketplace

data class MarketplaceCatalog(
    val schemaVersion: Int,
    val updatedAt: String,
    val entries: List<MarketplaceEntry>,
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
    val installCount: Int,
    val tags: List<String>,
    val createdAt: String,
    val updatedAt: String,
)
