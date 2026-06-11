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
import com.notcvnt.rknhardering.probe.NativeEmulatorFinding
import com.notcvnt.rknhardering.probe.NativeInterface
import com.notcvnt.rknhardering.probe.NativeInterfaceProbe
import com.notcvnt.rknhardering.probe.NativeMapsFinding
import com.notcvnt.rknhardering.probe.NativeRootFinding
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

    private val HIGH_CONFIDENCE_ROOT_MOUNT_MARKERS = setOf(
        "magisk",
        "zygisk",
        "lsposed",
        "riru",
        "kernelsu",
        "apatch",
        "/data/adb",
        "core-only",
    )

    private val HIGH_CONFIDENCE_EMULATOR_KINDS = setOf(
        "qemu_prop",
        "qemu_pipe",
        "goldfish",
        "bluestacks",
    )

    private val CLONE_USER_IDS = setOf(999)
    private val CLONE_USER_ID_RANGE = 950..959 // MIUI dual-app range

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

        val rootOutcome = evaluateRootIndicators(context)
        findings += rootOutcome.findings
        evidence += rootOutcome.evidence
        needsReview = needsReview || rootOutcome.needsReview

        val emulatorOutcome = evaluateEmulator(
            context,
            runCatching { NativeInterfaceProbe.collectEmulatorFindings() }.getOrDefault(emptyList()),
            collectBuildEmulatorFacts(),
        )
        findings += emulatorOutcome.findings
        evidence += emulatorOutcome.evidence
        needsReview = needsReview || emulatorOutcome.needsReview

        val isolationOutcome = evaluateIsolation(
            context,
            userId = extractUserId(context.dataDir?.absolutePath),
            isProfileOwner = collectIsProfileOwner(context),
        )
        findings += isolationOutcome.findings
        evidence += isolationOutcome.evidence
        needsReview = needsReview || isolationOutcome.needsReview

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

        val defaultRoutes = routes.asSequence()
            .filter { it.isDefault }
            .distinctBy { route ->
                val canonical = NetworkInterfaceNameNormalizer.canonicalName(route.interfaceName)
                    ?: route.interfaceName
                val familyBucket = when {
                    route.family == 10 -> 6
                    route.destinationHex.length > 8 -> 6
                    else -> 4
                }
                "$canonical|$familyBucket"
            }
            .toList()
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
                        description = "Native proc default route on VPN interface $iface",
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
                        description = "Native proc default route on non-standard interface $iface",
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

    internal fun evaluateRootIndicators(context: Context): PartialOutcome {
        val rootFindings = runCatching { NativeInterfaceProbe.collectRootFindings() }.getOrDefault(emptyList())
        if (rootFindings.isEmpty()) {
            return PartialOutcome(
                findings = listOf(
                    Finding(
                        description = context.getString(R.string.checker_native_root_clean),
                        isInformational = true,
                        source = EvidenceSource.NATIVE_ROOT_DETECTION,
                    ),
                ),
                evidence = emptyList(),
            )
        }

        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        for (item in rootFindings) {
            val detail = item.detail ?: "?"
            val (description, confidence) = when (item.kind) {
                "su_binary" -> Pair(
                    context.getString(R.string.checker_native_root_su_binary, detail),
                    EvidenceConfidence.HIGH,
                )
                "root_prop" -> Pair(
                    context.getString(R.string.checker_native_root_property, detail),
                    EvidenceConfidence.MEDIUM,
                )
                "root_mgmt" -> Pair(
                    context.getString(R.string.checker_native_root_mgmt_artifact, detail),
                    EvidenceConfidence.HIGH,
                )
                "system_rw" -> Pair(
                    context.getString(R.string.checker_native_root_system_rw),
                    EvidenceConfidence.HIGH,
                )
                "suspicious_mount" -> Pair(
                    context.getString(R.string.checker_native_root_suspicious_mount, detail),
                    if (containsHighConfidenceRootMountMarker(detail)) {
                        EvidenceConfidence.HIGH
                    } else {
                        EvidenceConfidence.MEDIUM
                    },
                )
                "overlay_mount" -> {
                    if (!containsHighConfidenceRootMountMarker(detail)) {
                        continue
                    }
                    Pair(
                        context.getString(R.string.checker_native_root_overlay_mount, detail),
                        EvidenceConfidence.HIGH,
                    )
                }
                "selinux" -> {
                    if (detail == "permissive") {
                        Pair(
                            context.getString(R.string.checker_native_root_selinux_permissive),
                            EvidenceConfidence.HIGH,
                        )
                    } else {
                        Pair(
                            context.getString(R.string.checker_native_root_selinux_absent),
                            EvidenceConfidence.LOW,
                        )
                    }
                }
                "root_uid" -> Pair(
                    context.getString(R.string.checker_native_root_uid, detail),
                    EvidenceConfidence.HIGH,
                )
                "magisk_prop" -> Pair(
                    context.getString(R.string.checker_native_root_magisk_prop, detail),
                    EvidenceConfidence.HIGH,
                )
                else -> continue
            }

            findings += Finding(
                description = description,
                needsReview = true,
                source = EvidenceSource.NATIVE_ROOT_DETECTION,
                confidence = confidence,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.NATIVE_ROOT_DETECTION,
                detected = true,
                confidence = confidence,
                description = "Root indicator [${item.kind}]: $detail",
            )
            needsReview = true
        }

        return PartialOutcome(findings, evidence, needsReview = needsReview)
    }

    internal fun evaluateEmulator(
        context: Context,
        emulatorFindings: List<NativeEmulatorFinding>,
        buildFacts: List<String>,
    ): PartialOutcome {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        for (finding in emulatorFindings) {
            val detail = finding.detail ?: finding.kind
            val confidence = if (finding.kind in HIGH_CONFIDENCE_EMULATOR_KINDS) {
                EvidenceConfidence.HIGH
            } else {
                EvidenceConfidence.MEDIUM
            }
            findings += Finding(
                description = context.getString(R.string.checker_native_emulator_marker, detail),
                needsReview = true,
                source = EvidenceSource.NATIVE_EMULATOR,
                confidence = confidence,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.NATIVE_EMULATOR,
                detected = true,
                confidence = confidence,
                description = "Emulator marker [${finding.kind}]: $detail",
            )
            needsReview = true
        }

        for (fact in buildFacts) {
            findings += Finding(
                description = context.getString(R.string.checker_native_emulator_build, fact),
                needsReview = true,
                source = EvidenceSource.NATIVE_EMULATOR,
                confidence = EvidenceConfidence.MEDIUM,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.NATIVE_EMULATOR,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = "Build emulator heuristic: $fact",
            )
            needsReview = true
        }

        return PartialOutcome(findings, evidence, needsReview = needsReview)
    }

    internal fun collectBuildEmulatorFacts(): List<String> {
        val facts = mutableListOf<String>()
        val fp = android.os.Build.FINGERPRINT.orEmpty()
        if (fp.startsWith("generic") || fp.startsWith("unknown") ||
            fp.contains("vbox") || fp.contains("emulator") || fp.contains("test-keys")
        ) {
            facts += "Build.FINGERPRINT=$fp"
        }
        val model = android.os.Build.MODEL.orEmpty()
        if (model.contains("google_sdk") || model.contains("Emulator") ||
            model.contains("Android SDK built for")
        ) {
            facts += "Build.MODEL=$model"
        }
        val hw = android.os.Build.HARDWARE.orEmpty()
        if (hw in setOf("goldfish", "ranchu", "vbox86")) {
            facts += "Build.HARDWARE=$hw"
        }
        val product = android.os.Build.PRODUCT.orEmpty()
        if (product.startsWith("sdk_gphone") || product in setOf("vbox86p", "emulator", "sdk", "google_sdk")) {
            facts += "Build.PRODUCT=$product"
        }
        val manufacturer = android.os.Build.MANUFACTURER.orEmpty()
        // "unknown" alone is too broad — some legitimate AOSP/budget devices report it.
        // Only flag named emulator vendors here; weaker signals are covered by FINGERPRINT/PRODUCT above.
        if (manufacturer.equals("Genymotion", ignoreCase = true)) {
            facts += "Build.MANUFACTURER=$manufacturer"
        }
        return facts
    }

    internal fun evaluateIsolation(
        context: Context,
        userId: Int,
        isProfileOwner: Boolean,
    ): PartialOutcome {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        var needsReview = false

        val isClone = userId in CLONE_USER_IDS || userId in CLONE_USER_ID_RANGE

        if (isClone) {
            findings += Finding(
                description = context.getString(R.string.checker_native_isolation_clone, userId),
                needsReview = true,
                source = EvidenceSource.SANDBOX_ISOLATION,
                confidence = EvidenceConfidence.MEDIUM,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.SANDBOX_ISOLATION,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = "Isolation: clone/dual-app container (user $userId)",
            )
            needsReview = true
        } else if (userId != 0) {
            findings += Finding(
                description = context.getString(R.string.checker_native_isolation_secondary_user, userId),
                needsReview = true,
                source = EvidenceSource.SANDBOX_ISOLATION,
                confidence = EvidenceConfidence.MEDIUM,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.SANDBOX_ISOLATION,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = "Isolation: secondary user $userId",
            )
            needsReview = true
        }

        if (isProfileOwner) {
            findings += Finding(
                description = context.getString(R.string.checker_native_isolation_work_profile),
                needsReview = true,
                source = EvidenceSource.SANDBOX_ISOLATION,
                confidence = EvidenceConfidence.MEDIUM,
            )
            evidence += EvidenceItem(
                source = EvidenceSource.SANDBOX_ISOLATION,
                detected = true,
                confidence = EvidenceConfidence.MEDIUM,
                description = "Isolation: managed work profile (profile owner)",
            )
            needsReview = true
        }

        return PartialOutcome(findings, evidence, needsReview = needsReview)
    }

    internal fun extractUserId(dataDirPath: String?): Int {
        if (dataDirPath == null) return 0
        val match = Regex("/data/user/(\\d+)/").find(dataDirPath) ?: return 0
        return match.groupValues[1].toIntOrNull() ?: 0
    }

    internal fun collectIsProfileOwner(context: Context): Boolean {
        return runCatching {
            val dpm = context.getSystemService(android.content.Context.DEVICE_POLICY_SERVICE)
                as? android.app.admin.DevicePolicyManager ?: return false
            dpm.isProfileOwnerApp(context.packageName)
        }.getOrDefault(false)
    }

    internal fun containsHighConfidenceRootMountMarker(detail: String): Boolean {
        val normalized = detail.lowercase()
        return HIGH_CONFIDENCE_ROOT_MOUNT_MARKERS.any { marker ->
            normalized.contains(marker)
        }
    }
}

