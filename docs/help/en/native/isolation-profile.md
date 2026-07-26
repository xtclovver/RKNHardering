---
title: "Android user/profile isolation summary"
permalink: /help/en/native/isolation-profile/
---

# Android user/profile isolation summary

> **ID:** `ISOLATION_PROFILE`
> **Category:** Emulation, profiles, and isolation
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Service

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

This is an umbrella ID. The current checker extracts the user ID from `/data/user/<id>/` and separately calls `DevicePolicyManager.isProfileOwnerApp()`; positive lines receive `ISOLATION_CLONE`, `ISOLATION_SECONDARY_USER`, or `ISOLATION_WORK_PROFILE`. There is no separate `ISOLATION_PROFILE` producer.

### Exact trigger condition

The ID itself does not trigger; see the three child signals.

## What the result means

A profile is not treated as VPN evidence, but it changes package visibility, UIDs, per-profile VPN behavior, and data access. A “second space” is therefore not a transparent bypass.

**How the line affects the report:** This is an umbrella or fallback ID. It links a group of lines to the documentation, but does not always have its own positive producer.

## Limitations and possible false positives

Private Space and OEM clones use different user types; the current implementation mainly sees the numeric user ID and whether the app itself is the profile owner.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If the profile is not part of the test, install and run the app under the primary user (`user 0`). Export its data before deleting a work, private, or clone profile: deleting the profile erases its apps and storage. Shelter and Insular are useful for managed profiles, but they do not hide the existence of a separate Android user.

### With root

Using root to spoof the user ID, `/data/user/<id>` path, or `DevicePolicyManager` responses creates an inconsistent state and can damage the profile. It is safer to run the app under the correct user rather than masking the profile. Hooks placed in the target process for a single check may additionally trigger `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, and `LIBRARY_INTEGRITY`.

### How to verify the result

```bash
adb shell pm list users
adb shell am get-current-user
adb shell dumpsys user | head -160
```
Compare the user ID with the `dataDir` path in the detail.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Deleting a profile erases its apps and data. Export the data before experimenting.

### Rollback

Recreate the profile through the normal DPC or Settings flow and restore the data from backup.

## Evidence level

**Service.** Verified against `evaluateIsolation()` and the absence of direct assignment of the umbrella ID.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- External primary documentation or official project: [AOSP managed profiles](https://source.android.com/docs/devices/admin/managed-profiles).
- External primary documentation or official project: [AOSP Private Space](https://source.android.com/docs/security/features/private-space).
- External primary documentation or official project: [Application Sandbox](https://source.android.com/docs/security/app-sandbox).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `isolation-clone`, `isolation-secondary-user`, `isolation-work-profile`.

[Back to the Native signs reference](../)
