package com.notcvnt.rknhardering.vpn

import com.notcvnt.rknhardering.model.VpnAppKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnAppCatalogTest {

    @Test
    fun `finds targeted package by package name`() {
        val signature = VpnAppCatalog.findByPackageName("moe.nb4a")

        assertEquals(VpnAppCatalog.FAMILY_NEKOBOX, signature?.family)
        assertEquals(VpnAppKind.TARGETED_BYPASS, signature?.kind)
    }

    @Test
    fun `exposes family candidates for common localhost port`() {
        val families = VpnAppCatalog.familiesForPort(10808)

        assertTrue(families.contains(VpnAppCatalog.FAMILY_XRAY))
    }

    @Test
    fun `aggregates popular localhost proxy ports`() {
        assertTrue(VpnAppCatalog.localhostProxyPorts.contains(2080))
        assertTrue(VpnAppCatalog.localhostProxyPorts.contains(12334))
    }

    @Test
    fun `detects AmneziaVPN by package name`() {
        val sig = VpnAppCatalog.findByPackageName("org.amnezia.vpn")

        assertEquals(VpnAppCatalog.FAMILY_AMNEZIA, sig?.family)
        assertEquals(VpnAppKind.GENERIC_VPN, sig?.kind)
    }

    @Test
    fun `detects AmneziaWG by package name`() {
        val sig = VpnAppCatalog.findByPackageName("org.amnezia.awg")

        assertEquals(VpnAppCatalog.FAMILY_AMNEZIA, sig?.family)
        assertEquals(VpnAppKind.GENERIC_VPN, sig?.kind)
    }

    @Test
    fun `catalog has no duplicate package names`() {
        val packageNames = VpnAppCatalog.signatures.map { it.packageName }

        assertEquals(packageNames.distinct(), packageNames)
    }

    @Test
    fun `every signature has non-blank package app name and family`() {
        VpnAppCatalog.signatures.forEach { signature ->
            assertTrue("blank packageName in $signature", signature.packageName.isNotBlank())
            assertTrue("blank appName for ${signature.packageName}", signature.appName.isNotBlank())
            assertTrue("blank family for ${signature.packageName}", signature.family.isNotBlank())
        }
    }

    @Test
    fun `every signature declares at least one signal`() {
        VpnAppCatalog.signatures.forEach { signature ->
            assertTrue("no signals for ${signature.packageName}", signature.signals.isNotEmpty())
        }
    }

    @Test
    fun `every default port is in valid range`() {
        VpnAppCatalog.signatures.flatMap { it.defaultPorts }.forEach { port ->
            assertTrue("port $port out of range", port in 1..65535)
        }
    }

    @Test
    fun `known package names mirror the signature list`() {
        assertEquals(
            VpnAppCatalog.signatures.map { it.packageName }.toSet(),
            VpnAppCatalog.knownPackageNames,
        )
    }

    @Test
    fun `localhost proxy ports are the sorted distinct union of default ports`() {
        val expected = VpnAppCatalog.signatures
            .flatMap { it.defaultPorts }
            .distinct()
            .sorted()

        assertEquals(expected, VpnAppCatalog.localhostProxyPorts)
    }

    @Test
    fun `families for every aggregated port resolve to catalog families`() {
        val catalogFamilies = VpnAppCatalog.signatures.map { it.family }.toSet()

        VpnAppCatalog.localhostProxyPorts.forEach { port ->
            val families = VpnAppCatalog.familiesForPort(port)
            assertTrue("no families for port $port", families.isNotEmpty())
            families.forEach { family ->
                assertTrue("unknown family $family for port $port", family in catalogFamilies)
            }
        }
    }

    @Test
    fun `families for unknown port are empty`() {
        assertTrue(VpnAppCatalog.familiesForPort(1).isEmpty())
    }

    @Test
    fun `find by unknown package name returns null`() {
        assertEquals(null, VpnAppCatalog.findByPackageName("com.example.not.in.catalog"))
    }
}
