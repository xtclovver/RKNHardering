package com.notcvnt.rknhardering.checker

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Process
import android.os.UserManager
import android.system.Os
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.BetaObservation
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.DetectionDomain
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.ExecutionContextFacts
import com.notcvnt.rknhardering.model.ExecutionContextKind
import com.notcvnt.rknhardering.model.ObservationAuthority
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.model.ProbeAvailability
import com.notcvnt.rknhardering.probe.HiddenAndroidApiBridge
import com.notcvnt.rknhardering.probe.HiddenCallResult
import com.notcvnt.rknhardering.probe.UserManagerBinderProbe
import com.notcvnt.rknhardering.probe.UserManagerBinderSnapshot
import java.io.File

internal data class ExecutionContextCheckResult(
    val facts: ExecutionContextFacts,
    val observation: BetaObservation,
    val hiddenAvailability: ProbeAvailability,
)

internal data class ApplicationPathIdentity(
    val sourceDir: String?,
    val publicSourceDir: String?,
    val nativeLibraryDir: String?,
    val splitSourceDirs: List<String>,
)

internal data class ExecutionContextSnapshot(
    val uid: Int,
    val contextUserId: Int?,
    val dataDir: String?,
    val deviceProtectedDataDir: String?,
    val externalStorageDir: String?,
    val publicIsProfile: Boolean?,
    val publicIsManagedProfile: Boolean?,
    val publicUserProfileCount: Int?,
    val publicCurrentUserInProfiles: Boolean?,
    val headlessSystemUserMode: Boolean,
    val packageUid: Int?,
    val contextApplication: ApplicationPathIdentity,
    val packageApplication: ApplicationPathIdentity?,
    val mountNamespaceId: String?,
    val selinuxContext: String?,
    val profileParentUserId: Int? = null,
    val foregroundUserId: Int? = null,
)

internal object ExecutionContextChecker {
    private const val PER_USER_RANGE = 100_000
    private const val PRIVATE_PROFILE = "android.os.usertype.profile.PRIVATE"
    private const val MANAGED_PROFILE = "android.os.usertype.profile.MANAGED"
    private const val CLONE_PROFILE = "android.os.usertype.profile.CLONE"
    private const val SECONDARY_USER = "android.os.usertype.full.SECONDARY"
    private const val MISMATCH_PACKAGE_UID = "package_uid"
    private const val MISMATCH_STORAGE_USER = "storage_user"
    private const val MISMATCH_APPLICATION_PATHS = "application_paths"

    fun check(
        context: Context,
        networkEpochId: String?,
        observedAtElapsedMs: Long,
        hiddenApiEnabled: Boolean = true,
        hiddenProfileTypeLookup: (UserManager) -> HiddenCallResult<String?> =
            HiddenAndroidApiBridge::currentProfileType,
    ): ExecutionContextCheckResult {
        val userManager = context.getSystemService(UserManager::class.java)
        val publicSnapshot = collectSnapshot(context, userManager)
        val binderSnapshot: HiddenCallResult<UserManagerBinderSnapshot> = if (hiddenApiEnabled) {
            UserManagerBinderProbe.inspect(Process.myUid() / PER_USER_RANGE)
        } else {
            HiddenCallResult.Skipped("Disabled by setting")
        }
        val binderFacts = (binderSnapshot as? HiddenCallResult.Success)?.value
        val snapshot = publicSnapshot.copy(
            profileParentUserId = (binderFacts?.profileParentUserId as? HiddenCallResult.Success)?.value,
            foregroundUserId = (binderFacts?.foregroundUserId as? HiddenCallResult.Success)?.value,
        )
        val hidden = when {
            !hiddenApiEnabled -> HiddenCallResult.Skipped("Disabled by setting")
            userManager == null -> HiddenCallResult.Unavailable("UserManager unavailable")
            binderFacts?.profileType != null -> binderFacts.profileType
            else -> hiddenProfileTypeLookup(userManager)
        }
        return evaluate(
            context = context,
            snapshot = snapshot,
            hidden = hidden,
            networkEpochId = networkEpochId,
            observedAtElapsedMs = observedAtElapsedMs,
        )
    }

    internal fun evaluate(
        context: Context,
        snapshot: ExecutionContextSnapshot,
        hidden: HiddenCallResult<String?>,
        networkEpochId: String?,
        observedAtElapsedMs: Long,
    ): ExecutionContextCheckResult {
        val uid = snapshot.uid
        val userId = uid / PER_USER_RANGE
        val hiddenType = (hidden as? HiddenCallResult.Success)?.value
        val dataDirUserId = parseUserId(snapshot.dataDir)
        val deviceProtectedUserId = parseUserId(snapshot.deviceProtectedDataDir)
        val externalStorageUserId = parseUserId(snapshot.externalStorageDir)
        val sourceDirConsistent = comparePaths(
            snapshot.contextApplication.sourceDir,
            snapshot.packageApplication?.sourceDir,
        )
        val publicSourceDirConsistent = comparePaths(
            snapshot.contextApplication.publicSourceDir,
            snapshot.packageApplication?.publicSourceDir,
        )
        val nativeLibraryDirConsistent = comparePaths(
            snapshot.contextApplication.nativeLibraryDir,
            snapshot.packageApplication?.nativeLibraryDir,
        )
        val splitOrUpdateLayout = snapshot.contextApplication.splitSourceDirs.isNotEmpty() ||
            snapshot.packageApplication?.splitSourceDirs?.isNotEmpty() == true ||
            looksLikePackageUpdateTransition(
                contextApplication = snapshot.contextApplication,
                packageApplication = snapshot.packageApplication,
                packageUidConsistent = snapshot.packageUid?.let { it == uid },
            )
        val relevantPaths = listOfNotNull(
            snapshot.dataDir,
            snapshot.deviceProtectedDataDir,
            snapshot.externalStorageDir,
            snapshot.contextApplication.sourceDir,
            snapshot.contextApplication.publicSourceDir,
            snapshot.contextApplication.nativeLibraryDir,
        )
        val adoptedOrEmulatedStorage = relevantPaths.any(::isAdoptedOrEmulatedPath)
        val adoptedApplicationLayout = listOfNotNull(
            snapshot.contextApplication.sourceDir,
            snapshot.contextApplication.publicSourceDir,
            snapshot.contextApplication.nativeLibraryDir,
            snapshot.packageApplication?.sourceDir,
            snapshot.packageApplication?.publicSourceDir,
            snapshot.packageApplication?.nativeLibraryDir,
        ).any(::isAdoptedApplicationPath)
        val packageUidConsistent = snapshot.packageUid?.let { it == uid }
        val storageUserMismatch = storageUserMismatch(
            expectedUserId = userId,
            userIds = listOfNotNull(dataDirUserId, deviceProtectedUserId, externalStorageUserId),
        )
        val rawApplicationPathMismatch = listOfNotNull(
            sourceDirConsistent,
            publicSourceDirConsistent,
            nativeLibraryDirConsistent,
        ).any { !it }
        val applicationPathMismatch = rawApplicationPathMismatch &&
            !splitOrUpdateLayout &&
            !adoptedApplicationLayout
        val mismatchAxes = buildSet {
            if (packageUidConsistent == false) add(MISMATCH_PACKAGE_UID)
            if (storageUserMismatch) add(MISMATCH_STORAGE_USER)
            if (applicationPathMismatch) add(MISMATCH_APPLICATION_PATHS)
        }
        val classifiedUserKind = classify(
            userId = userId,
            hiddenProfileType = hiddenType,
            publicIsProfile = snapshot.publicIsProfile,
            publicIsManagedProfile = snapshot.publicIsManagedProfile,
            headlessSystemUserMode = snapshot.headlessSystemUserMode,
        )
        val kind = if (
            classifiedUserKind in setOf(ExecutionContextKind.MAIN_USER, ExecutionContextKind.UNKNOWN) &&
            mismatchAxes.size >= 2
        ) {
            ExecutionContextKind.VIRTUALIZED_APP
        } else {
            classifiedUserKind
        }
        val suppressions = buildList {
            if (kind != ExecutionContextKind.VIRTUALIZED_APP && rawApplicationPathMismatch && splitOrUpdateLayout) {
                add(BetaSuppressionRuleId.SPLIT_APK_OR_UPDATE_LAYOUT)
            }
            if (kind != ExecutionContextKind.VIRTUALIZED_APP && rawApplicationPathMismatch && adoptedApplicationLayout) {
                add(BetaSuppressionRuleId.ADOPTED_OR_EMULATED_STORAGE)
            }
            if (snapshot.headlessSystemUserMode && userId != 0) {
                add(BetaSuppressionRuleId.HEADLESS_SYSTEM_USER_GUARD)
            }
        }
        val confidence = when {
            kind == ExecutionContextKind.VIRTUALIZED_APP -> EvidenceConfidence.HIGH
            hiddenType != null -> EvidenceConfidence.HIGH
            snapshot.publicIsManagedProfile == true || snapshot.publicIsProfile == true -> EvidenceConfidence.MEDIUM
            else -> EvidenceConfidence.LOW
        }
        val facts = ExecutionContextFacts(
            uid = uid,
            appId = uid % PER_USER_RANGE,
            uidDerivedUserId = userId,
            contextUserId = snapshot.contextUserId,
            dataDirUserId = dataDirUserId,
            deviceProtectedDataDirUserId = deviceProtectedUserId,
            externalStorageUserId = externalStorageUserId,
            publicIsProfile = snapshot.publicIsProfile,
            publicIsManagedProfile = snapshot.publicIsManagedProfile,
            hiddenProfileType = hiddenType,
            profileParentUserId = snapshot.profileParentUserId,
            foregroundUserId = snapshot.foregroundUserId,
            packageUidConsistent = packageUidConsistent,
            sourceDirConsistent = sourceDirConsistent,
            publicSourceDirConsistent = publicSourceDirConsistent,
            nativeLibraryDirConsistent = nativeLibraryDirConsistent,
            publicUserProfileCount = snapshot.publicUserProfileCount,
            publicCurrentUserInProfiles = snapshot.publicCurrentUserInProfiles,
            mountNamespaceId = snapshot.mountNamespaceId,
            selinuxContext = snapshot.selinuxContext,
            virtualizationMismatchAxes = mismatchAxes,
            splitOrUpdateLayout = splitOrUpdateLayout,
            adoptedOrEmulatedStorage = adoptedOrEmulatedStorage,
            kind = kind,
            confidence = confidence,
        )
        val positive = kind !in setOf(ExecutionContextKind.MAIN_USER, ExecutionContextKind.UNKNOWN)
        val summary = when (kind) {
            ExecutionContextKind.PRIVATE_PROFILE -> context.getString(R.string.beta_profile_private)
            ExecutionContextKind.MANAGED_PROFILE -> context.getString(R.string.beta_profile_managed)
            ExecutionContextKind.CLONE_PROFILE -> context.getString(R.string.beta_profile_clone)
            ExecutionContextKind.SECONDARY_USER -> context.getString(R.string.beta_profile_secondary)
            ExecutionContextKind.UNKNOWN_PROFILE -> context.getString(R.string.beta_profile_unknown)
            ExecutionContextKind.VIRTUALIZED_APP -> context.getString(R.string.beta_profile_virtualized)
            else -> context.getString(R.string.beta_profile_checked)
        }
        return ExecutionContextCheckResult(
            facts = facts,
            observation = BetaObservation(
                checkId = if (kind == ExecutionContextKind.VIRTUALIZED_APP) {
                    "beta.sandbox_identity.filesystem"
                } else {
                    "beta.user_profile"
                },
                source = if (kind == ExecutionContextKind.VIRTUALIZED_APP) {
                    EvidenceSource.BETA_SANDBOX_IDENTITY
                } else {
                    EvidenceSource.BETA_USER_PROFILE
                },
                availability = ProbeAvailability.AVAILABLE,
                polarity = if (positive) ObservationPolarity.POSITIVE else ObservationPolarity.AUTHORITATIVE_NEGATIVE,
                authority = when {
                    kind == ExecutionContextKind.VIRTUALIZED_APP -> ObservationAuthority.HEURISTIC
                    hiddenType != null -> ObservationAuthority.HIDDEN_ANDROID_API
                    else -> ObservationAuthority.PUBLIC_ANDROID_API
                },
                confidence = confidence,
                independenceGroup = if (kind == ExecutionContextKind.VIRTUALIZED_APP) {
                    "filesystem_identity"
                } else {
                    "android_user_manager"
                },
                detectionDomain = if (kind == ExecutionContextKind.VIRTUALIZED_APP) {
                    DetectionDomain.APP_VIRTUALIZATION
                } else {
                    DetectionDomain.ISOLATED_PROFILE
                },
                facts = mapOf(
                    "summary" to summary,
                    "kind" to kind.name,
                    "mismatch_axes" to mismatchAxes.sorted().joinToString(","),
                ),
                suppressions = suppressions,
                observedAtElapsedMs = observedAtElapsedMs,
                networkEpochId = networkEpochId,
            ),
            hiddenAvailability = hidden.toAvailability(),
        )
    }

    private fun collectSnapshot(context: Context, userManager: UserManager?): ExecutionContextSnapshot {
        val packageApplication = runCatching {
            context.packageManager.getApplicationInfo(context.packageName, 0)
        }.getOrNull()
        val userProfiles = userManager?.let { manager ->
            runCatching { manager.userProfiles }.getOrNull()
        }
        return ExecutionContextSnapshot(
            uid = Process.myUid(),
            contextUserId = null,
            dataDir = context.applicationInfo.dataDir,
            deviceProtectedDataDir = runCatching {
                context.createDeviceProtectedStorageContext().applicationInfo.dataDir
            }.getOrNull(),
            externalStorageDir = runCatching { context.getExternalFilesDir(null)?.absolutePath }.getOrNull(),
            publicIsProfile = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                userManager?.let { manager -> runCatching { manager.isProfile }.getOrNull() }
            } else {
                null
            },
            publicIsManagedProfile = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                userManager?.let { manager -> runCatching { manager.isManagedProfile }.getOrNull() }
            } else {
                null
            },
            publicUserProfileCount = userProfiles?.size,
            publicCurrentUserInProfiles = userProfiles?.contains(Process.myUserHandle()),
            headlessSystemUserMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                runCatching { UserManager.isHeadlessSystemUserMode() }.getOrDefault(false)
            } else {
                false
            },
            packageUid = packageApplication?.uid,
            contextApplication = context.applicationInfo.toPathIdentity(),
            packageApplication = packageApplication?.toPathIdentity(),
            mountNamespaceId = runCatching { Os.readlink("/proc/self/ns/mnt") }.getOrNull(),
            selinuxContext = readFirstLine("/proc/self/attr/current"),
        )
    }

    internal fun classify(
        userId: Int,
        hiddenProfileType: String?,
        publicIsProfile: Boolean?,
        publicIsManagedProfile: Boolean?,
        headlessSystemUserMode: Boolean,
    ): ExecutionContextKind = when {
        hiddenProfileType == PRIVATE_PROFILE -> ExecutionContextKind.PRIVATE_PROFILE
        hiddenProfileType == MANAGED_PROFILE || publicIsManagedProfile == true -> ExecutionContextKind.MANAGED_PROFILE
        hiddenProfileType == CLONE_PROFILE -> ExecutionContextKind.CLONE_PROFILE
        hiddenProfileType == SECONDARY_USER -> ExecutionContextKind.SECONDARY_USER
        publicIsProfile == true -> ExecutionContextKind.UNKNOWN_PROFILE
        userId == 0 || headlessSystemUserMode -> ExecutionContextKind.MAIN_USER
        publicIsProfile == false && publicIsManagedProfile == false -> ExecutionContextKind.SECONDARY_USER
        else -> ExecutionContextKind.UNKNOWN
    }

    internal fun parseUserId(path: String?): Int? {
        if (path.isNullOrBlank()) return null
        val patterns = listOf(
            Regex("/data/user(?:_de)?/(\\d+)(?:/|$)"),
            Regex("/mnt/expand/[^/]+/user(?:_de)?/(\\d+)(?:/|$)"),
            Regex("/storage/emulated/(\\d+)(?:/|$)"),
        )
        return patterns.firstNotNullOfOrNull { regex ->
            regex.find(path)?.groupValues?.getOrNull(1)?.toIntOrNull()
        }
    }

    private fun storageUserMismatch(expectedUserId: Int, userIds: List<Int>): Boolean {
        if (userIds.size < 2) return false
        return userIds.distinct().size > 1 || userIds.all { it != expectedUserId }
    }

    private fun comparePaths(first: String?, second: String?): Boolean? {
        if (first.isNullOrBlank() || second.isNullOrBlank()) return null
        return normalizePath(first) == normalizePath(second)
    }

    private fun normalizePath(path: String): String = path
        .replace('\\', '/')
        .replace(Regex("/+"), "/")
        .removeSuffix("/")

    private fun isAdoptedOrEmulatedPath(path: String): Boolean {
        val normalized = normalizePath(path)
        return normalized.startsWith("/mnt/expand/") || normalized.startsWith("/storage/emulated/")
    }

    private fun isAdoptedApplicationPath(path: String): Boolean =
        normalizePath(path).startsWith("/mnt/expand/")

    private fun looksLikePackageUpdateTransition(
        contextApplication: ApplicationPathIdentity,
        packageApplication: ApplicationPathIdentity?,
        packageUidConsistent: Boolean?,
    ): Boolean {
        if (packageUidConsistent != true || packageApplication == null) return false
        val contextSource = contextApplication.sourceDir?.let(::normalizePath) ?: return false
        val packageSource = packageApplication.sourceDir?.let(::normalizePath) ?: return false
        if (contextSource == packageSource) return false
        return contextSource.endsWith("/base.apk") &&
            packageSource.endsWith("/base.apk") &&
            isTrustedInstalledAppPath(contextSource) &&
            isTrustedInstalledAppPath(packageSource)
    }

    private fun isTrustedInstalledAppPath(path: String): Boolean =
        path.startsWith("/data/app/") ||
            (path.startsWith("/mnt/expand/") && path.contains("/app/"))

    private fun readFirstLine(path: String): String? = runCatching {
        File(path).bufferedReader().use { reader ->
            reader.readLine()?.take(4_096)?.trim()?.takeIf { it.isNotEmpty() }
        }
    }.getOrNull()

    private fun ApplicationInfo.toPathIdentity(): ApplicationPathIdentity = ApplicationPathIdentity(
        sourceDir = sourceDir,
        publicSourceDir = publicSourceDir,
        nativeLibraryDir = nativeLibraryDir,
        splitSourceDirs = splitSourceDirs?.toList().orEmpty(),
    )

    private fun HiddenCallResult<*>.toAvailability(): ProbeAvailability = when (this) {
        is HiddenCallResult.Success -> ProbeAvailability.AVAILABLE
        is HiddenCallResult.PermissionDenied -> ProbeAvailability.PERMISSION_DENIED
        is HiddenCallResult.Unsupported -> ProbeAvailability.UNSUPPORTED
        is HiddenCallResult.Skipped -> ProbeAvailability.SKIPPED
        is HiddenCallResult.Unavailable -> ProbeAvailability.UNAVAILABLE
        is HiddenCallResult.Failure -> ProbeAvailability.ERROR
    }
}
