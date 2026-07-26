---
title: "OEM clone/dual-app userId"
permalink: /help/en/native/isolation-clone/
---

# OEM clone/dual-app userId

> **ID:** `ISOLATION_CLONE`
> **Category:** Emulation, profiles, and isolation
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The user ID is extracted from `dataDir`. The value `999` or the range `950..959` is treated as a clone/dual-app container (identified in the code as the MIUI dual-app range) and creates a medium-confidence review finding.

### Exact trigger condition

The app path matches `/data/user/999/` or `/data/user/950..959/`.

## What the result means

The signal identifies the actual Android user rather than a specific app-cloning product. It explains separate UIDs, package visibility, and network settings.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

An OEM may use a different user ID, and the listed range could theoretically belong to another user type. The `dataDir` parser does not read the `UserManager` type.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If the profile is not part of the test, install and run the app under the primary user (`user 0`). Export its data before deleting a work, private, or clone profile: deleting the profile erases its apps and storage. Shelter and Insular are useful for managed profiles, but they do not hide the existence of a separate Android user. In the OEM settings, disable Dual Apps or Second Space specifically for RKNHardering and reinstall it under the owner user.

### With root

Using root to spoof the user ID, `/data/user/<id>` path, or `DevicePolicyManager` responses creates an inconsistent state and can damage the profile. It is safer to run the app under the correct user rather than masking the profile. Hooks placed in the target process for a single check may additionally trigger `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, and `LIBRARY_INTEGRITY`.

### How to verify the result

```bash
adb shell pm list users
adb shell dumpsys package com.notcvnt.rknhardering | grep -E 'userId=|dataDir='
```
On newer Android versions, the package dump may hide some paths.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Deleting the clone erases its separate data. Do not manually move `dataDir` contents between UIDs.

### Rollback

Re-enable the OEM clone and restore the exported data through the app’s normal mechanism.

## Evidence level

**Medium.** Verified against `CLONE_USER_IDS={999}` and the `950..959` range.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android multi-user](https://source.android.com/docs/devices/admin/multi-user).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `isolation-secondary-user`, `isolation-work-profile`.

[Back to the Native signs reference](../)
