package com.notcvnt.rknhardering.checker

import android.app.Application
import android.content.Context
import android.os.Build
import android.os.Process
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.NativeSignsBridge

internal data class SandboxProbeRow(
    val checkId: String,
    val availability: ProbeAvailability,
    val fields: Map<String, String>,
)

internal data class ProcessIdentitySnapshot(
    val uid: Int,
    val applicationUid: Int,
    val packageUid: Int?,
    val packageVisibleForUid: Boolean?,
    val processNameExpected: Boolean?,
)

internal data class SandboxProbeDefinition(
    val checkId: String,
    val source: EvidenceSource,
    val authority: ObservationAuthority,
    val group: String,
    val domain: DetectionDomain,
    val completeFields: Set<String>,
)

internal object SandboxProbeRowParser {
    private const val PREFIX = "beta_v1"
    private const val MAX_ROWS = 16
    private const val MAX_TOTAL_CHARS = 16_384
    private const val MAX_FIELDS = 64

    fun parse(rows: Array<String>, expectedCheckId: String): SandboxProbeRow {
        if (rows.isEmpty()) return unavailable(expectedCheckId)
        if (rows.size > MAX_ROWS || rows.sumOf(String::length) > MAX_TOTAL_CHARS) {
            return SandboxProbeRow(expectedCheckId, ProbeAvailability.TRUNCATED, emptyMap())
        }
        val matching = rows.filter { row ->
            row.split('|').any { it == "check=$expectedCheckId" }
        }
        if (matching.size != 1) {
            return SandboxProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
        }
        val parts = matching.single().split('|')
        if (parts.firstOrNull() != PREFIX || parts.size > MAX_FIELDS + 1) {
            return SandboxProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
        }
        val fields = linkedMapOf<String, String>()
        for (part in parts.drop(1)) {
            val separator = part.indexOf('=')
            if (separator <= 0 || separator == part.lastIndex) {
                return SandboxProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
            }
            val key = part.substring(0, separator)
            if (fields.put(key, part.substring(separator + 1)) != null) {
                return SandboxProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
            }
        }
        if (fields["check"] != expectedCheckId) {
            return SandboxProbeRow(expectedCheckId, ProbeAvailability.MALFORMED_RESPONSE, emptyMap())
        }
        val availability = when (fields["status"]) {
            "available" -> ProbeAvailability.AVAILABLE
            "permission_denied" -> ProbeAvailability.PERMISSION_DENIED
            "unsupported" -> ProbeAvailability.UNSUPPORTED
            "unavailable" -> ProbeAvailability.UNAVAILABLE
            "truncated" -> ProbeAvailability.TRUNCATED
            "malformed_response" -> ProbeAvailability.MALFORMED_RESPONSE
            "race" -> ProbeAvailability.RACE
            "skipped" -> ProbeAvailability.SKIPPED
            "error" -> ProbeAvailability.ERROR
            else -> ProbeAvailability.MALFORMED_RESPONSE
        }
        return SandboxProbeRow(expectedCheckId, availability, fields)
    }

    private fun unavailable(checkId: String) =
        SandboxProbeRow(checkId, ProbeAvailability.UNAVAILABLE, emptyMap())
}

internal object SandboxIntegrityChecker {
    private val definitions = listOf(
        SandboxProbeDefinition(
            "sandbox_identity.filesystem",
            EvidenceSource.BETA_SANDBOX_IDENTITY,
            ObservationAuthority.KERNEL_QUERY,
            "filesystem_identity",
            DetectionDomain.APP_VIRTUALIZATION,
            setOf("existing_count", "statx_count", "statfs_count", "critical_mismatch"),
        ),
        SandboxProbeDefinition(
            "sandbox_identity.namespace",
            EvidenceSource.BETA_NAMESPACE,
            ObservationAuthority.KERNEL_QUERY,
            "namespace_identity",
            DetectionDomain.APP_VIRTUALIZATION,
            setOf("namespace_count", "mountinfo_readable"),
        ),
        SandboxProbeDefinition(
            "fscrypt_identity",
            EvidenceSource.BETA_SANDBOX_IDENTITY,
            ObservationAuthority.KERNEL_QUERY,
            "filesystem_identity",
            DetectionDomain.APP_VIRTUALIZATION,
            setOf("existing_count", "statx_count", "statfs_count", "fscrypt_known_count", "critical_mismatch"),
        ),
        SandboxProbeDefinition(
            "direct_syscall_consistency",
            EvidenceSource.BETA_HOOK_CONSISTENCY,
            ObservationAuthority.KERNEL_QUERY,
            "hook_consistency",
            DetectionDomain.HOOK_OR_TAMPERING,
            setOf("compared_count", "mismatch_count", "critical_mismatch"),
        ),
        SandboxProbeDefinition(
            "fd_identity",
            EvidenceSource.BETA_HOOK_CONSISTENCY,
            ObservationAuthority.KERNEL_QUERY,
            "process_fd",
            DetectionDomain.HOOK_OR_TAMPERING,
            setOf("fstat_match", "critical_mismatch"),
        ),
        SandboxProbeDefinition(
            "linker_integrity",
            EvidenceSource.BETA_HOOK_CONSISTENCY,
            ObservationAuthority.LIBC_OR_PRIVATE_LIBRARY,
            "loader_integrity",
            DetectionDomain.HOOK_OR_TAMPERING,
            setOf("loader_exec_segments", "symbol_owner_known", "symbol_in_owner", "critical_mismatch"),
        ),
    )

    fun check(
        context: Context,
        aggressive: Boolean,
        networkEpochId: String?,
        observedAtElapsedMs: Long,
    ): List<BetaObservation> {
        val processSnapshot = collectProcessIdentity(context)
        val paths = collectPaths(context)
        NativeSignsBridge.initIfNeeded()
        val rows = if (NativeSignsBridge.isLibraryLoaded()) {
            NativeSignsBridge.betaSandboxSnapshot(paths, aggressive)
        } else {
            emptyArray()
        }
        val packageSourceDir = runCatching {
            context.packageManager.getApplicationInfo(context.packageName, 0).sourceDir
        }.getOrNull()
        val splitLayout = context.applicationInfo.splitSourceDirs?.isNotEmpty() == true ||
            (packageSourceDir != null && packageSourceDir != context.applicationInfo.sourceDir)
        val adoptedLayout = paths.any { labeled ->
            val path = labeled.substringAfter('=', "")
            path.startsWith("/mnt/expand/") || path.startsWith("/storage/emulated/")
        }
        val nativeProcess = SandboxProbeRowParser.parse(rows, "sandbox_identity.process")
        return buildList {
            val process = processObservation(processSnapshot, nativeProcess, networkEpochId, observedAtElapsedMs)
            add(process.copy(facts = process.facts + (
                "summary" to context.getString(com.notcvnt.rknhardering.R.string.beta_sandbox_process_checked)
            )))
            definitions.filter { definition ->
                aggressive || definition.checkId !in setOf("fscrypt_identity", "fd_identity", "linker_integrity")
            }.forEach { definition ->
                val suppressions = buildList {
                    if (definition.group == "filesystem_identity" && splitLayout) {
                        add(BetaSuppressionRuleId.SPLIT_APK_OR_UPDATE_LAYOUT)
                    }
                    if (definition.group == "filesystem_identity" && adoptedLayout) {
                        add(BetaSuppressionRuleId.ADOPTED_OR_EMULATED_STORAGE)
                    }
                    if (definition.checkId == "direct_syscall_consistency") {
                        add(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS)
                    }
                }
                val observation = nativeObservation(
                    definition = definition,
                    row = SandboxProbeRowParser.parse(rows, definition.checkId),
                    networkEpochId = networkEpochId,
                    observedAtElapsedMs = observedAtElapsedMs,
                    suppressions = suppressions,
                )
                add(observation.copy(facts = observation.facts + (
                    "summary" to context.getString(summaryResource(definition.checkId))
                )))
            }
        }
    }

    internal fun processObservation(
        snapshot: ProcessIdentitySnapshot,
        nativeRow: SandboxProbeRow,
        networkEpochId: String?,
        observedAtElapsedMs: Long,
    ): BetaObservation {
        val axes = buildSet {
            if (snapshot.applicationUid != snapshot.uid) add("context_uid")
            if (snapshot.packageUid != null && snapshot.packageUid != snapshot.uid) add("package_uid")
            if (snapshot.packageVisibleForUid == false) add("package_identity")
            if (snapshot.processNameExpected == false) add("process_name")
            nativeRow.fields["uid"]?.toIntOrNull()?.let { if (it != snapshot.uid) add("native_uid") }
        }
        val positive = axes.size >= 2
        val checkedAxes = listOfNotNull(
            true,
            snapshot.packageUid?.let { true },
            snapshot.packageVisibleForUid?.let { true },
            snapshot.processNameExpected?.let { true },
            nativeRow.fields["uid"]?.toIntOrNull()?.let { true },
        ).size
        return BetaObservation(
            checkId = "beta.sandbox_identity.process",
            source = EvidenceSource.BETA_SANDBOX_IDENTITY,
            availability = ProbeAvailability.AVAILABLE,
            polarity = when {
                positive -> ObservationPolarity.POSITIVE
                axes.isEmpty() && checkedAxes >= 3 -> ObservationPolarity.AUTHORITATIVE_NEGATIVE
                else -> ObservationPolarity.INCONCLUSIVE
            },
            authority = ObservationAuthority.PUBLIC_ANDROID_API,
            confidence = if (positive) EvidenceConfidence.HIGH else EvidenceConfidence.LOW,
            independenceGroup = "process_identity",
            detectionDomain = DetectionDomain.APP_VIRTUALIZATION,
            facts = mapOf(
                "summary" to "Self process and package identity compared",
                "checked_axes" to checkedAxes.toString(),
                "mismatch_axis_count" to axes.size.toString(),
            ),
            suppressions = if (snapshot.packageVisibleForUid == null) {
                listOf(BetaSuppressionRuleId.PACKAGE_VISIBILITY_REDACTED)
            } else {
                emptyList()
            },
            observedAtElapsedMs = observedAtElapsedMs,
            networkEpochId = networkEpochId,
        )
    }

    internal fun nativeObservation(
        definition: SandboxProbeDefinition,
        row: SandboxProbeRow,
        networkEpochId: String?,
        observedAtElapsedMs: Long,
        suppressions: List<BetaSuppressionRuleId> = emptyList(),
    ): BetaObservation {
        val positive = row.availability == ProbeAvailability.AVAILABLE &&
            row.fields["critical_mismatch"] == "true"
        val complete = row.availability == ProbeAvailability.AVAILABLE &&
            row.fields["critical_mismatch"] == "false" &&
            definition.completeFields.all(row.fields::containsKey) &&
            hasCompleteEvidence(definition.checkId, row.fields)
        return BetaObservation(
            checkId = "beta.${definition.checkId}",
            source = definition.source,
            availability = row.availability,
            polarity = when {
                positive -> ObservationPolarity.POSITIVE
                complete -> ObservationPolarity.AUTHORITATIVE_NEGATIVE
                else -> ObservationPolarity.INCONCLUSIVE
            },
            authority = definition.authority,
            confidence = if (positive) EvidenceConfidence.HIGH else EvidenceConfidence.LOW,
            independenceGroup = definition.group,
            detectionDomain = definition.domain,
            facts = buildMap {
                put("summary", "Self-scoped integrity probe completed")
                row.fields["compared_count"]?.let { put("compared_count", it) }
                row.fields["mismatch_count"]?.let { put("mismatch_count", it) }
                row.fields["existing_count"]?.let { put("existing_count", it) }
                row.fields["namespace_count"]?.let { put("namespace_count", it) }
            },
            suppressions = buildList {
                addAll(suppressions)
                if (positive && definition.checkId == "direct_syscall_consistency") {
                    add(BetaSuppressionRuleId.INSUFFICIENT_REPETITIONS)
                }
            }.distinct(),
            observedAtElapsedMs = observedAtElapsedMs,
            networkEpochId = networkEpochId,
        )
    }

    private fun hasCompleteEvidence(checkId: String, fields: Map<String, String>): Boolean = when (checkId) {
        "sandbox_identity.filesystem" -> fields.positiveCount("existing_count") &&
            fields.positiveCount("statx_count") && fields.positiveCount("statfs_count")
        "sandbox_identity.namespace" -> false
        "fscrypt_identity" -> fields.positiveCount("existing_count") &&
            fields.positiveCount("statx_count") && fields.positiveCount("statfs_count") &&
            fields.positiveCount("fscrypt_known_count")
        "direct_syscall_consistency" -> fields.positiveCount("compared_count")
        "fd_identity" -> fields["fstat_match"] == "true" &&
            (fields["kcmp_result"] == "0" || fields["pidfd_compared"] == "true")
        "linker_integrity" -> fields.positiveCount("loader_exec_segments") &&
            fields["symbol_owner_known"] == "true" && fields["symbol_in_owner"] == "true"
        else -> false
    }

    private fun summaryResource(checkId: String): Int = when (checkId) {
        "sandbox_identity.filesystem" -> com.notcvnt.rknhardering.R.string.beta_sandbox_filesystem_checked
        "sandbox_identity.namespace" -> com.notcvnt.rknhardering.R.string.beta_sandbox_namespace_checked
        "fscrypt_identity" -> com.notcvnt.rknhardering.R.string.beta_sandbox_fscrypt_checked
        "direct_syscall_consistency" -> com.notcvnt.rknhardering.R.string.beta_sandbox_syscall_checked
        "fd_identity" -> com.notcvnt.rknhardering.R.string.beta_sandbox_fd_checked
        else -> com.notcvnt.rknhardering.R.string.beta_sandbox_linker_checked
    }

    private fun Map<String, String>.positiveCount(key: String): Boolean =
        this[key]?.toLongOrNull()?.let { it > 0 } == true

    private fun collectProcessIdentity(context: Context): ProcessIdentitySnapshot {
        val uid = Process.myUid()
        val packageUid = runCatching {
            context.packageManager.getApplicationInfo(context.packageName, 0).uid
        }.getOrNull()
        val packages = runCatching { context.packageManager.getPackagesForUid(uid)?.toSet() }.getOrNull()
        val processNameExpected = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Application.getProcessName().let { name ->
                name == context.packageName || name.startsWith("${context.packageName}:")
            }
        } else {
            null
        }
        return ProcessIdentitySnapshot(
            uid = uid,
            applicationUid = context.applicationInfo.uid,
            packageUid = packageUid,
            packageVisibleForUid = packages?.contains(context.packageName),
            processNameExpected = processNameExpected,
        )
    }

    private fun collectPaths(context: Context): Array<String> = linkedMapOf(
        "ce" to context.dataDir.absolutePath,
        "de" to context.createDeviceProtectedStorageContext().dataDir.absolutePath,
        "files" to context.filesDir.absolutePath,
        "cache" to context.cacheDir.absolutePath,
        "no_backup" to context.noBackupFilesDir.absolutePath,
        "source" to context.applicationInfo.sourceDir,
        "native_lib" to context.applicationInfo.nativeLibraryDir,
    ).mapNotNull { (label, path) -> path?.takeIf(String::isNotBlank)?.let { "$label=$it" } }
        .distinct()
        .take(12)
        .toTypedArray()
}
