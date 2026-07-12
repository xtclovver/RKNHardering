package com.notcvnt.rknhardering.probe

import android.os.Binder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class HiddenAndroidBinderProbeTest {
    @Test
    fun descriptorMustMatchExactly() {
        val binder = Binder().apply { attachInterface(null, "android.os.IUserManager") }

        assertTrue(
            HiddenAndroidApiBridge.validateBinderDescriptor(binder, "android.os.IUserManager")
                is HiddenCallResult.Success,
        )
        assertTrue(
            HiddenAndroidApiBridge.validateBinderDescriptor(binder, "android.net.IVpnManager")
                is HiddenCallResult.Unavailable,
        )
    }

    @Test
    fun exactMethodSignatureIsRequired() {
        val target = ExactMethodFixture()
        val valid = HiddenAndroidApiBridge.invokeOnClass(
            target,
            ExactMethodFixture::class.java,
            HiddenMethodSpec(
                "read",
                listOf(Int::class.javaPrimitiveType!!),
                String::class.java,
            ),
            arrayOf(7),
        )
        val wrongReturnType = HiddenAndroidApiBridge.invokeOnClass(
            target,
            ExactMethodFixture::class.java,
            HiddenMethodSpec(
                "read",
                listOf(Int::class.javaPrimitiveType!!),
                Int::class.javaPrimitiveType!!,
            ),
            arrayOf(7),
        )

        assertEquals("user-7", (valid as HiddenCallResult.Success).value)
        assertTrue(wrongReturnType is HiddenCallResult.Unavailable)
    }

    @Test
    fun securityExceptionIsPermissionDenied() {
        val result = HiddenAndroidApiBridge.invokeOnClass(
            SecurityFixture(),
            SecurityFixture::class.java,
            HiddenMethodSpec("read", emptyList(), String::class.java),
            emptyArray(),
        )

        assertTrue(result is HiddenCallResult.PermissionDenied)
    }

    @Test
    fun vpnServiceAndAllowlistNamesAreVersionPinned() {
        val r = VpnManagerBinderProbe.serviceSpecForSdk(30)
        val s = VpnManagerBinderProbe.serviceSpecForSdk(31)

        assertEquals("connectivity", r.serviceName)
        assertEquals("android.net.IConnectivityManager", r.descriptor)
        assertEquals("vpn_management", s.serviceName)
        assertEquals("android.net.IVpnManager", s.descriptor)
        assertTrue("getVpnLockdownWhitelist" in VpnManagerBinderProbe.readOnlyMethodNames)
        assertTrue("getVpnLockdownAllowlist" in VpnManagerBinderProbe.readOnlyMethodNames)
    }

    @Test
    fun binderContractsContainOnlyReadOnlyCalls() {
        val names = VpnManagerBinderProbe.readOnlyMethodNames +
            UserManagerBinderProbe.readOnlyMethodNames +
            ConnectivityBinderProbe.readOnlyMethodNames

        assertTrue(names.isNotEmpty())
        assertTrue(names.none { name ->
            name.startsWith("set") || name.startsWith("prepare") || name.startsWith("start") ||
                name.startsWith("stop") || name.startsWith("delete") || name.startsWith("remove")
        })
    }

    @Test
    fun connectivityApiFamiliesCoverSupportedSdkRange() {
        assertEquals(ConnectivityBinderApiFamily.O_TO_R, ConnectivityBinderProbe.familyForSdk(26))
        assertEquals(ConnectivityBinderApiFamily.O_TO_R, ConnectivityBinderProbe.familyForSdk(30))
        assertEquals(ConnectivityBinderApiFamily.S_TO_U, ConnectivityBinderProbe.familyForSdk(31))
        assertEquals(ConnectivityBinderApiFamily.S_TO_U, ConnectivityBinderProbe.familyForSdk(34))
        assertEquals(ConnectivityBinderApiFamily.V_AND_NEWER, ConnectivityBinderProbe.familyForSdk(35))
    }

    class ExactMethodFixture {
        fun read(userId: Int): String = "user-$userId"
    }

    class SecurityFixture {
        fun read(): String = throw SecurityException("denied")
    }
}
