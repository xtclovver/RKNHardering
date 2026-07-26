---
title: "Running outside the primary user"
permalink: /help/en/native/isolation-secondary-user/
---

# Running outside the primary user

> **ID:** `ISOLATION_SECONDARY_USER`
> **Category:** Emulation, profiles, and isolation
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

If the extracted user ID is not 0 and is not in the clone set, the checker creates `ISOLATION_SECONDARY_USER` with a medium-confidence review finding.

### Exact trigger condition

A `dataDir` of the form `/data/user/<id>/`, where `<id> != 0` and is not 999 or in 950..959.

## What the result means

It identifies a separate Android user. This is a normal multi-user mode, but it changes the installed-app set, VPN configuration, and network policies relative to the owner user.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The `/data/user_de/` path and vendor-specific behavior may not match the regular expression. Private or work profiles may also fall into this branch when they have a nonzero user ID.

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
adb shell cmd user list
```
Confirm which user has the package installed: `adb shell pm list packages --user 0 | grep rknhardering`.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Deleting a secondary user erases all of that user’s data, not only RKNHardering.

### Rollback

Recreate the user and restore the backup. Do not manually copy app data between UIDs.

## Evidence level

**Medium.** Verified against the `else if (userId != 0)` branch.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android multi-user](https://source.android.com/docs/devices/admin/multi-user).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `isolation-clone`, `isolation-work-profile`.

[Back to the Native signs reference](../)
