package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.BetaSuppressionRuleId
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.ExecutionContextKind
import com.notcvnt.rknhardering.model.ObservationPolarity
import com.notcvnt.rknhardering.probe.HiddenCallResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ExecutionContextCheckerTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `parses supported CE DE expanded and external paths`() {
        assertEquals(10, ExecutionContextChecker.parseUserId("/data/user/10/com.example"))
        assertEquals(12, ExecutionContextChecker.parseUserId("/data/user_de/12/com.example"))
        assertEquals(15, ExecutionContextChecker.parseUserId("/mnt/expand/uuid/user/15/com.example"))
        assertEquals(16, ExecutionContextChecker.parseUserId("/mnt/expand/uuid/user_de/16/com.example"))
        assertEquals(11, ExecutionContextChecker.parseUserId("/storage/emulated/11/Android/data/com.example"))
    }

    @Test
    fun `malformed paths remain unknown`() {
        assertNull(ExecutionContextChecker.parseUserId(null))
        assertNull(ExecutionContextChecker.parseUserId("/data/data/com.example"))
        assertNull(ExecutionContextChecker.parseUserId("/data/user/not-a-user/com.example"))
    }

    @Test
    fun `exact profile types win over numeric user heuristics`() {
        assertEquals(
            ExecutionContextKind.PRIVATE_PROFILE,
            classify("android.os.usertype.profile.PRIVATE"),
        )
        assertEquals(
            ExecutionContextKind.MANAGED_PROFILE,
            classify("android.os.usertype.profile.MANAGED"),
        )
        assertEquals(
            ExecutionContextKind.CLONE_PROFILE,
            classify("android.os.usertype.profile.CLONE"),
        )
    }

    @Test
    fun `managed public signal does not require profile owner`() {
        assertEquals(
            ExecutionContextKind.MANAGED_PROFILE,
            ExecutionContextChecker.classify(
                userId = 10,
                hiddenProfileType = null,
                publicIsProfile = null,
                publicIsManagedProfile = true,
                headlessSystemUserMode = false,
            ),
        )
    }

    @Test
    fun `headless system user guard does not label nonzero human user secondary`() {
        assertEquals(
            ExecutionContextKind.MAIN_USER,
            ExecutionContextChecker.classify(
                userId = 10,
                hiddenProfileType = null,
                publicIsProfile = false,
                publicIsManagedProfile = false,
                headlessSystemUserMode = true,
            ),
        )
    }

    @Test
    fun `nonzero user without exact type remains neutral unknown`() {
        assertEquals(
            ExecutionContextKind.UNKNOWN,
            ExecutionContextChecker.classify(
                userId = 10,
                hiddenProfileType = null,
                publicIsProfile = false,
                publicIsManagedProfile = null,
                headlessSystemUserMode = false,
            ),
        )
    }

    @Test
    fun `public non-profile non-managed nonzero user is secondary`() {
        assertEquals(
            ExecutionContextKind.SECONDARY_USER,
            ExecutionContextChecker.classify(
                userId = 10,
                hiddenProfileType = null,
                publicIsProfile = false,
                publicIsManagedProfile = false,
                headlessSystemUserMode = false,
            ),
        )
    }

    @Test
    fun `public profile without exact type remains unknown profile`() {
        assertEquals(
            ExecutionContextKind.UNKNOWN_PROFILE,
            ExecutionContextChecker.classify(
                userId = 10,
                hiddenProfileType = null,
                publicIsProfile = true,
                publicIsManagedProfile = false,
                headlessSystemUserMode = false,
            ),
        )
    }

    @Test
    fun `safe self scoped facts are retained without becoming evidence`() {
        val result = evaluate(
            snapshot(
                contextUserId = 0,
                externalStorageDir = "/storage/emulated/0/Android/data/com.example/files",
                publicUserProfileCount = 2,
                publicCurrentUserInProfiles = true,
                mountNamespaceId = "mnt:[4026533001]",
                selinuxContext = "u:r:untrusted_app:s0:c1,c2",
            ),
        )

        assertEquals(0, result.facts.externalStorageUserId)
        assertEquals(2, result.facts.publicUserProfileCount)
        assertEquals(true, result.facts.publicCurrentUserInProfiles)
        assertEquals("mnt:[4026533001]", result.facts.mountNamespaceId)
        assertEquals("u:r:untrusted_app:s0:c1,c2", result.facts.selinuxContext)
        assertEquals(true, result.facts.packageUidConsistent)
        assertEquals(true, result.facts.sourceDirConsistent)
        assertEquals(true, result.facts.publicSourceDirConsistent)
        assertEquals(true, result.facts.nativeLibraryDirConsistent)
        assertEquals(ExecutionContextKind.MAIN_USER, result.facts.kind)
        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, result.observation.polarity)
    }

    @Test
    fun `uid and storage mismatch classify multi axis virtualization`() {
        val result = evaluate(
            snapshot(
                packageUid = 20_123,
                dataDir = "/data/user/10/com.example",
                deviceProtectedDataDir = "/data/user_de/10/com.example",
                externalStorageDir = null,
            ),
        )

        assertEquals(ExecutionContextKind.VIRTUALIZED_APP, result.facts.kind)
        assertEquals(setOf("package_uid", "storage_user"), result.facts.virtualizationMismatchAxes)
        assertEquals(EvidenceConfidence.HIGH, result.facts.confidence)
        assertEquals(ObservationPolarity.POSITIVE, result.observation.polarity)
        val evaluated = BetaEvidencePolicy.evaluate(result.observation, BetaEvaluationContext("epoch"))
        assertTrue(evaluated.finding.needsReview)
        assertFalse(evaluated.finding.detected)
    }

    @Test
    fun `uid and package path mismatch classify multi axis virtualization`() {
        val result = evaluate(
            snapshot(
                packageUid = 20_123,
                packageApplication = applicationIdentity(root = "/data/app/other"),
            ),
        )

        assertEquals(ExecutionContextKind.VIRTUALIZED_APP, result.facts.kind)
        assertEquals(setOf("package_uid", "application_paths"), result.facts.virtualizationMismatchAxes)
        assertEquals(ObservationPolarity.POSITIVE, result.observation.polarity)
    }

    @Test
    fun `single mismatch remains neutral`() {
        val result = evaluate(snapshot(packageUid = 20_123))

        assertEquals(ExecutionContextKind.MAIN_USER, result.facts.kind)
        assertEquals(setOf("package_uid"), result.facts.virtualizationMismatchAxes)
        assertEquals(ObservationPolarity.AUTHORITATIVE_NEGATIVE, result.observation.polarity)
    }

    @Test
    fun `split apk layout suppresses package path mismatch`() {
        val contextApplication = applicationIdentity(
            root = "/data/app/version-one",
            splits = listOf("/data/app/version-one/split_config.en.apk"),
        )
        val result = evaluate(
            snapshot(
                packageUid = 20_123,
                contextApplication = contextApplication,
                packageApplication = applicationIdentity(root = "/data/app/version-two"),
            ),
        )

        assertEquals(ExecutionContextKind.MAIN_USER, result.facts.kind)
        assertEquals(setOf("package_uid"), result.facts.virtualizationMismatchAxes)
        assertTrue(result.facts.splitOrUpdateLayout)
        assertTrue(BetaSuppressionRuleId.SPLIT_APK_OR_UPDATE_LAYOUT in result.observation.suppressions)
    }

    @Test
    fun `package update transition suppresses trusted install path mismatch`() {
        val result = evaluate(
            snapshot(
                dataDir = "/data/user/10/com.example",
                deviceProtectedDataDir = "/data/user_de/10/com.example",
                contextApplication = applicationIdentity(root = "/data/app/version-one"),
                packageApplication = applicationIdentity(root = "/data/app/version-two"),
            ),
        )

        assertEquals(ExecutionContextKind.MAIN_USER, result.facts.kind)
        assertEquals(setOf("storage_user"), result.facts.virtualizationMismatchAxes)
        assertTrue(result.facts.splitOrUpdateLayout)
        assertTrue(BetaSuppressionRuleId.SPLIT_APK_OR_UPDATE_LAYOUT in result.observation.suppressions)
    }

    @Test
    fun `adopted storage layout suppresses package path mismatch`() {
        val result = evaluate(
            snapshot(
                packageUid = 20_123,
                contextApplication = applicationIdentity(root = "/mnt/expand/volume/app/current"),
                packageApplication = applicationIdentity(root = "/mnt/expand/volume/app/package"),
            ),
        )

        assertEquals(ExecutionContextKind.MAIN_USER, result.facts.kind)
        assertEquals(setOf("package_uid"), result.facts.virtualizationMismatchAxes)
        assertTrue(result.facts.adoptedOrEmulatedStorage)
        assertTrue(BetaSuppressionRuleId.ADOPTED_OR_EMULATED_STORAGE in result.observation.suppressions)
    }

    @Test
    fun `public profile classification wins over unrelated path anomalies`() {
        val result = evaluate(
            snapshot(
                packageUid = 20_123,
                dataDir = "/data/user/10/com.example",
                deviceProtectedDataDir = "/data/user_de/10/com.example",
                publicIsProfile = true,
                publicIsManagedProfile = true,
            ),
        )

        assertEquals(ExecutionContextKind.MANAGED_PROFILE, result.facts.kind)
        assertFalse(result.facts.kind == ExecutionContextKind.VIRTUALIZED_APP)
    }

    private fun classify(type: String) = ExecutionContextChecker.classify(
        userId = 10,
        hiddenProfileType = type,
        publicIsProfile = true,
        publicIsManagedProfile = false,
        headlessSystemUserMode = false,
    )

    private fun evaluate(snapshot: ExecutionContextSnapshot): ExecutionContextCheckResult =
        ExecutionContextChecker.evaluate(
            context = context,
            snapshot = snapshot,
            hidden = HiddenCallResult.Skipped("test"),
            networkEpochId = "epoch",
            observedAtElapsedMs = 1L,
        )

    private fun snapshot(
        uid: Int = 10_123,
        contextUserId: Int? = 0,
        dataDir: String? = "/data/user/0/com.example",
        deviceProtectedDataDir: String? = "/data/user_de/0/com.example",
        externalStorageDir: String? = "/storage/emulated/0/Android/data/com.example/files",
        publicIsProfile: Boolean? = false,
        publicIsManagedProfile: Boolean? = false,
        publicUserProfileCount: Int? = 1,
        publicCurrentUserInProfiles: Boolean? = true,
        packageUid: Int? = uid,
        contextApplication: ApplicationPathIdentity = applicationIdentity(),
        packageApplication: ApplicationPathIdentity? = contextApplication,
        mountNamespaceId: String? = null,
        selinuxContext: String? = null,
    ) = ExecutionContextSnapshot(
        uid = uid,
        contextUserId = contextUserId,
        dataDir = dataDir,
        deviceProtectedDataDir = deviceProtectedDataDir,
        externalStorageDir = externalStorageDir,
        publicIsProfile = publicIsProfile,
        publicIsManagedProfile = publicIsManagedProfile,
        publicUserProfileCount = publicUserProfileCount,
        publicCurrentUserInProfiles = publicCurrentUserInProfiles,
        headlessSystemUserMode = false,
        packageUid = packageUid,
        contextApplication = contextApplication,
        packageApplication = packageApplication,
        mountNamespaceId = mountNamespaceId,
        selinuxContext = selinuxContext,
    )

    private fun applicationIdentity(
        root: String = "/data/app/com.example",
        splits: List<String> = emptyList(),
    ) = ApplicationPathIdentity(
        sourceDir = "$root/base.apk",
        publicSourceDir = "$root/base.apk",
        nativeLibraryDir = "$root/lib/arm64",
        splitSourceDirs = splits,
    )
}
