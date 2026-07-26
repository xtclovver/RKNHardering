---
title: "RKNHardering is the profile owner"
permalink: /help/en/native/isolation-work-profile/
---

# RKNHardering is the profile owner

> **ID:** `ISOLATION_WORK_PROFILE`
> **Category:** Emulation, profiles, and isolation
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The checker obtains `DevicePolicyManager` and calls `isProfileOwnerApp(context.packageName)`. The signal appears only when the RKNHardering package itself is registered as the profile owner. This is narrower than asking whether the app runs inside a work profile: an ordinary app in a managed profile without the DPC role may not produce this line.

### Exact trigger condition

`isProfileOwnerApp()` returns true for the RKNHardering package.

## What the result means

The medium-confidence review finding indicates the very specific DPC/profile-owner role, not merely the presence of a work profile on the device.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The signal name is broader than the implementation. For an ordinary app in Shelter or Insular, the user-ID-based secondary-user signal is more likely to trigger than this line.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If the profile is not part of the test, install and run the app under the primary user (`user 0`). Export its data before deleting a work, private, or clone profile: deleting the profile erases its apps and storage. Shelter and Insular are useful for managed profiles, but they do not hide the existence of a separate Android user. If RKNHardering was accidentally assigned as the DPC, remove profile management through Shelter, Insular, or Settings after exporting the data.

### With root

Using root to spoof the user ID, `/data/user/<id>` path, or `DevicePolicyManager` responses creates an inconsistent state and can damage the profile. It is safer to run the app under the correct user rather than masking the profile. Hooks placed in the target process for a single check may additionally trigger `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, and `LIBRARY_INTEGRITY`. Hooking `DevicePolicyManager` only for this line leaves the real user ID and management state visible through other APIs.

### How to verify the result

```bash
adb shell dpm list-owners
adb shell dumpsys device_policy | grep -A8 -B2 -i 'profile owner'
```
The commands may require shell access; the app’s own detail remains authoritative.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Removing the profile owner usually removes the work profile and its data. Export everything important first.

### Rollback

Recreate the managed profile through a trusted DPC and restore the data.

## Evidence level

**Medium.** Verified against the exact `isProfileOwnerApp` call; this documentation corrects the previous overly broad interpretation.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [DevicePolicyManager.isProfileOwnerApp](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#isProfileOwnerApp%28java.lang.String%29).
- External primary documentation or official project: [AOSP managed profiles](https://source.android.com/docs/devices/admin/managed-profiles).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `isolation-secondary-user`, `isolation-profile`.

[Back to the Native signs reference](../)
