package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer
import com.notcvnt.rknhardering.network.NetworkInterfacePatterns
import com.notcvnt.rknhardering.probe.NativeInterface
import com.notcvnt.rknhardering.probe.NativeInterfaceProbe
import com.notcvnt.rknhardering.probe.NativeMapsFinding
import com.notcvnt.rknhardering.probe.NativeRouteEntry
import com.notcvnt.rknhardering.probe.NativeSignsBridge
import com.notcvnt.rknhardering.probe.NativeSymbolInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.NetworkInterface

object NativeSignsChecker {

    private val HIGH_CONFIDENCE_HOOK_MARKERS = setOf(
        "frida-agent",
        "frida-gadget",
        "libfrida",
        "libsubstrate",
        "com.saurik.substrate",
        "XposedBridge",
        "libxposed",
        "lspatch",
        "LSPosed",
        "libriru",
        "libzygisk",
    )

    internal data class JvmInterfaceSnapshot(
        val name: String,
        val canonicalName: String?,
        val index: Int,
        val addresses: Set<String>,
        val mtu: Int,
        val isUp: Boolean,
    )

    suspend fun check(context: Context): CategoryResult = withContext(Dispatchers.IO) {
        NativeSignsBridge.initIfNeeded()

        if (!NativeSignsBridge.isLibraryLoaded()) {
            val loadError = NativeSignsBridge.lastLoadErrorMessage()
            val description = if (loadError != null) {
                context.getString(R.string.checker_native_unavailable_with_reason, loadError)
            } else {
                context.getString(R.string.checker_native_unavailable)
            }
            return@withContext CategoryResult(
                name = context.getString(R.string.checker_native_category_name),
                detected = false,
                findings = listOf(Finding(description = description, isInformational = true)),
                needsReview = false,
                evidence = emptyList(),
            )
        }

        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false
        var needsReview = false

        val nativeInterfaces = runCatching { NativeInterfaceProbe.collectInterfaces() }.getOrDefault(emptyList())
        val jvmInterfaces = runCatching { collectJvmInterfaces() }.getOrDefault(emptyList())

        val interfaceOutcome = evaluateInterfaces(context, nativeInterfaces)
        findings += interfaceOutcome.findings
        evidence += interfaceOutcome.evidence
        detected = detected || interfaceOutcome.detected
        needsReview = needsReview || interfaceOutcome.needsReview

        val mismatchOutcome = evaluateJvmNativeMismatch(context, nativeInterfaces, jvmInterfaces)
        findings += mismatchOutcome.findings
        evidence += mismatchOutcome.evidence
        detected = detected || mismatchOutcome.detected
        needsReview = needsReview || mismatchOutcome.needsReview

        val routeOutcome = evaluateRoutes(context)
        findings += routeOutcome.findings
        evidence += routeOutcome.evidence
        detected = detected || routeOutcome.detected

        val hookOutcome = evaluateHookMarkers(context)
        findings += hookOutcome.findings
        evidence += hookOutcome.evidence
        needsReview = needsReview || hookOutcome.needsReview

        val integrityOutcome = evaluateLibraryIntegrity(context)
        findings += integrityOutcome.findings
        evidence += integrityOutcome.evidence
        needsReview = needsReview || integrityOutcome.needsReview

        if (findings.isEmpty()) {
            findings += Finding(
                description = context.getString(R.string.checker_native_no_anomalies),
                isInformational = true,
            )
        }

        CategoryResult(
            name = context.getString(R.string.checker_native_category_name),
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
        )
    }

    internal data class PartialOutcome(
        val findings: List<Finding>,
        val evidence: List<EvidenceItem>,
        val detected: Boolean = false,
        val needsReview: Boolean = false,
    )

    internal fun evaluateInterfaces(
        context: Context,
        nativeInterfaces: List<NativeInterface>,
    ): PartialOutcome {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false

        if (nativeInterfaces.isEmpty()) {
            findings += Finding(
                description = context.getString(R.string.checker_native_interfaces_empty),
                needsReview = true,
                source = EvidenceSource.NATIVE_INTERFACE,
                confidence = EvidenceConfidence.LOW,
            )
            return PartialOutcome(findings, evidence, detected = false, needsReview = true)
        }

        val uniqueByName = nativeInterfaces.distinctBy { it.name }
        findings += Finding(
            description = context.getString(
                R.string.checker_native_interfaces_summary,
                uniqueByName.size,
                uniqueByName.count { it.isUp },
            ),
            isInformational = true,
            source = EvidenceSource.NATIVE_INTERFACE,
        )

        val vpnInterfaces = uniqueByName.filter { iface ->
            iface.isUp && NetworkInterfacePatterns.isVpnInterface(iface.name)
        }
        for (iface in vpnInterfaces) {
            val description = context.getString(
                R.string.checker_native_vpn_interface,
                iface.name,
                iface.index,
                iface.mtu,
            )
            findings += Finding(
                description = description,
                detected = true,
                source = EvidenceSource.NATIVE_INTERFACE,
                confidence = EvidenceConfidence.HIGH,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.NATIVE_INTERFACE,
                detected = true,
                confidence = EvidenceConfidence.HIGH,
                description = "Native getifaddrs() reports VPN-like interface ${iface.name} (index ${iface.index})",
            )
            detected = true
        }

        val ipsecInterfaces = uniqueByName.filter { iface ->
            iface.isUp && NetworkInterfacePatterns.isIpsecInterface(iface.name)
        }
        for (iface in ipsecInterfaces) {
            findings += Finding(
                description = context.getString(
                    R.string.checker_native_ipsec_interface,
                    iface.name,
                    iface.index,
                ),
                isInformational = true,
                source = EvidenceSource.NATIVE_INTERFACE,
            )
        }

        return PartialOutcome(findings, evidence, detected = detected)
    }

    internal fun evaluateJvmNativeMismatch(
        context: Context,
        nativeInterfaces: List<NativeInterface>,
        jvmInterfaces: List<JvmInterfaceSnapshot>,
    ): PartialOutcome {
        if (nativeInterfaces.isEmpty() || jvmInterfaces.isEmpty()) {
            return PartialOutcome(emptyList(), emptyList())
        }

        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false
        var detected = false

        val nativeByName = nativeInterfaces
            .groupBy { it.name }
            .mapValues { (_, list) -> list }

        val jvmByName = jvmInterfaces.associateBy { it.name }

        val nativeNames = nativeByName.keys
        val jvmNames = jvmByName.keys
        val onlyInNative = nativeNames - jvmNames
        val onlyInJvm = jvmNames - nativeNames

        for (name in onlyInNative) {
            val isSensitive = NetworkInterfacePatterns.isVpnInterface(name)
            findings += Finding(
                description = context.getString(
                    R.string.checker_native_mismatch_missing_in_jvm,
                    name,
                ),
                detected = isSensitive,
                needsReview = !isSensitive,
                source = EvidenceSource.NATIVE_JVM_MISMATCH,
                confidence = if (isSensitive) EvidenceConfidence.HIGH else EvidenceConfidence.MEDIUM,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.NATIVE_JVM_MISMATCH,
                detected = true,
                confidence = if (isSensitive) EvidenceConfidence.HIGH else EvidenceConfidence.MEDIUM,
                description = "Interface $name is visible natively but missing from JVM NetworkInterface enumeration",
            )
            needsReview = needsReview || !isSensitive
            detected = detected || isSensitive
        }

        for (name in onlyInJvm) {
            val isSensitive = NetworkInterfacePatterns.isVpnInterface(name)
            findings += Finding(
                description = context.getString(
                    R.string.checker_native_mismatch_missing_in_native,
                    name,
                ),
                detected = isSensitive,
                needsReview = !isSensitive,
                source = EvidenceSource.NATIVE_JVM_MISMATCH,
                confidence = if (isSensitive) EvidenceConfidence.HIGH else EvidenceConfidence.MEDIUM,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.NATIVE_JVM_MISMATCH,
                detected = true,
                confidence = if (isSensitive) EvidenceConfidence.HIGH else EvidenceConfidence.MEDIUM,
                description = "Interface $name is visible in JVM but missing from native getifaddrs()",
            )
            needsReview = needsReview || !isSensitive
            detected = detected || isSensitive
        }

        for ((name, natives) in nativeByName) {
            val jvm = jvmByName[name] ?: continue
            val nativeIndex = natives.firstOrNull { it.index > 0 }?.index ?: continue
            if (jvm.index != 0 && jvm.index != nativeIndex) {
                findings += Finding(
                    description = context.getString(
                        R.string.checker_native_mismatch_index,
                        name,
                        nativeIndex,
                        jvm.index,
                    ),
                    needsReview = true,
                    source = EvidenceSource.NATIVE_JVM_MISMATCH,
                    confidence = EvidenceConfidence.MEDIUM,
                )
                evidence += EvidenceItem(
                    source = EvidenceSource.NATIVE_JVM_MISMATCH,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Interface index mismatch for $name: native=$nativeIndex jvm=${jvm.index}",
                )
                needsReview = true
            }

            val nativeAddrs = natives.mapNotNullTo(linkedSetOf()) { it.address?.lowercase() }
            val jvmAddrs = jvm.addresses.mapTo(linkedSetOf()) { it.lowercase() }
            if (nativeAddrs.isNotEmpty() && jvmAddrs.isNotEmpty() && nativeAddrs != jvmAddrs) {
                val onlyNative = nativeAddrs - jvmAddrs
                val onlyJvm = jvmAddrs - nativeAddrs
                findings += Finding(
                    description = context.getString(
                        R.string.checker_native_mismatch_addresses,
                        name,
                        onlyNative.joinToString(",").ifEmpty { "-" },
                        onlyJvm.joinToString(",").ifEmpty { "-" },
                    ),
                    needsReview = true,
                    source = EvidenceSource.NATIVE_JVM_MISMATCH,
                    confidence = EvidenceConfidence.MEDIUM,
                )
                evidence += EvidenceItem(
                    source = EvidenceSource.NATIVE_JVM_MISMATCH,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "Address set mismatch for $name between native and JVM",
                )
                needsReview = true
            }
        }

        return PartialOutcome(findings, evidence, detected = detected, needsReview = needsReview)
    }

    internal fun evaluateRoutes(context: Context): PartialOutcome {
        val routes = runCatching { NativeInterfaceProbe.collectRoutes() }.getOrDefault(emptyList())
        if (routes.isEmpty()) {
            return PartialOutcome(
                findings = listOf(
                    Finding(
                        description = context.getString(R.string.checker_native_routes_empty),
                        isInformational = true,
                        source = EvidenceSource.NATIVE_ROUTE,
                    ),
                ),
                evidence = emptyList(),
            )
        }

        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var detected = false

        val defaultRoutes = routes.filter { it.isDefault }
        if (defaultRoutes.isEmpty()) {
            findings += Finding(
                description = context.getString(R.string.checker_native_routes_no_default),
                isInformational = true,
                source = EvidenceSource.NATIVE_ROUTE,
            )
        } else {
            for (route in defaultRoutes) {
                val canonical = NetworkInterfaceNameNormalizer.canonicalName(route.interfaceName)
                val iface = canonical ?: route.interfaceName
                val isVpn = NetworkInterfacePatterns.isVpnInterface(iface)
                val isStandard = NetworkInterfacePatterns.isStandardInterface(iface)
                val description = context.getString(
                    R.string.checker_native_route_default,
                    iface,
                )
                if (isVpn) {
                    findings += Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.NATIVE_ROUTE,
                        confidence = EvidenceConfidence.HIGH,
                    )
                    evidence += EvidenceItem(
                        source = EvidenceSource.NATIVE_ROUTE,
                        detected = true,
                        confidence = EvidenceConfidence.HIGH,
                        description = "Native /proc/net/route default gateway on VPN interface $iface",
                    )
                    detected = true
                } else if (!isStandard) {
                    findings += Finding(
                        description = description,
                        detected = true,
                        source = EvidenceSource.NATIVE_ROUTE,
                        confidence = EvidenceConfidence.MEDIUM,
                    )
                    evidence += EvidenceItem(
                        source = EvidenceSource.NATIVE_ROUTE,
                        detected = true,
                        confidence = EvidenceConfidence.MEDIUM,
                        description = "Native /proc/net/route default gateway on non-standard interface $iface",
                    )
                    detected = true
                } else {
                    findings += Finding(
                        description = description,
                        isInformational = true,
                        source = EvidenceSource.NATIVE_ROUTE,
                    )
                }
            }
        }

        return PartialOutcome(findings, evidence, detected = detected)
    }

    internal fun evaluateHookMarkers(context: Context): PartialOutcome {
        val markers = runCatching { NativeInterfaceProbe.collectMapsFindings() }.getOrDefault(emptyList())
        if (markers.isEmpty()) {
            return PartialOutcome(
                findings = listOf(
                    Finding(
                        description = context.getString(R.string.checker_native_hooks_clean),
                        isInformational = true,
                        source = EvidenceSource.NATIVE_HOOK_MARKERS,
                    ),
                ),
                evidence = emptyList(),
            )
        }

        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        for (marker in markers) {
            when (marker.kind) {
                "marker" -> {
                    val name = marker.marker ?: continue
                    val isHighConfidence = HIGH_CONFIDENCE_HOOK_MARKERS.any { name.contains(it) }
                    val confidence = if (isHighConfidence) EvidenceConfidence.HIGH else EvidenceConfidence.MEDIUM
                    findings += Finding(
                        description = context.getString(
                            R.string.checker_native_hook_marker,
                            name,
                        ),
                        needsReview = true,
                        source = EvidenceSource.NATIVE_HOOK_MARKERS,
                        confidence = confidence,
                    )
                    evidence += EvidenceItem(
                        source = EvidenceSource.NATIVE_HOOK_MARKERS,
                        detected = true,
                        confidence = confidence,
                        description = "Hook marker in /proc/self/maps: $name",
                    )
                    needsReview = true
                }
                "rwx_large" -> {
                    val count = marker.detail ?: "?"
                    findings += Finding(
                        description = context.getString(R.string.checker_native_rwx_regions, count),
                        isInformational = true,
                        source = EvidenceSource.NATIVE_HOOK_MARKERS,
                        confidence = EvidenceConfidence.LOW,
                    )
                }
            }
        }

        return PartialOutcome(findings, evidence, needsReview = needsReview)
    }

    internal fun evaluateLibraryIntegrity(context: Context): PartialOutcome {
        val symbols = runCatching { NativeInterfaceProbe.collectLibraryIntegrity() }.getOrDefault(emptyList())
        if (symbols.isEmpty()) return PartialOutcome(emptyList(), emptyList())

        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        val suspicious = symbols.filter { sym ->
            val library = sym.library?.lowercase().orEmpty()
            sym.missing || (library.isNotEmpty() && !library.contains("libc.so") && !library.contains("libc++") && !library.contains("libm.so"))
        }

        if (suspicious.isEmpty()) {
            findings += Finding(
                description = context.getString(R.string.checker_native_symbols_clean),
                isInformational = true,
                source = EvidenceSource.NATIVE_LIBRARY_INTEGRITY,
            )
            return PartialOutcome(findings, evidence)
        }

        for (sym in suspicious) {
            val detail = when {
                sym.missing -> context.getString(R.string.checker_native_symbol_missing, sym.symbol)
                else -> context.getString(
                    R.string.checker_native_symbol_foreign_library,
                    sym.symbol,
                    sym.library ?: "?",
                )
            }
            findings += Finding(
                description = detail,
                needsReview = true,
                source = EvidenceSource.NATIVE_LIBRARY_INTEGRITY,
                confidence = EvidenceConfidence.MEDIUM,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.NATIVE_LIBRARY_INTEGRITY,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = detail,
            )
            needsReview = true
        }

        return PartialOutcome(findings, evidence, needsReview = needsReview)
    }

    internal fun collectJvmInterfaces(): List<JvmInterfaceSnapshot> {
        val result = mutableListOf<JvmInterfaceSnapshot>()
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return result
        while (interfaces.hasMoreElements()) {
            val iface = interfaces.nextElement() ?: continue
            val addresses = linkedSetOf<String>()
            val enumAddrs = iface.inetAddresses
            while (enumAddrs.hasMoreElements()) {
                val addr = enumAddrs.nextElement() ?: continue
                val host = addr.hostAddress?.substringBefore('%')?.lowercase() ?: continue
                addresses.add(host)
            }
            val mtu = runCatching { iface.mtu }.getOrDefault(-1)
            val isUp = runCatching { iface.isUp }.getOrDefault(false)
            val index = runCatching { iface.index }.getOrDefault(0)
            result.add(
                JvmInterfaceSnapshot(
                    name = iface.name ?: continue,
                    canonicalName = NetworkInterfaceNameNormalizer.canonicalName(iface.name),
                    index = index,
                    addresses = addresses,
                    mtu = mtu,
                    isUp = isUp,
                ),
            )
        }
        return result
    }
}

