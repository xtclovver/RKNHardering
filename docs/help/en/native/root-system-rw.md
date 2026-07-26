---
title: "Write Access to /system"
permalink: /help/en/native/root-system-rw/
---

# Write Access to /system

> **ID:** `ROOT_SYSTEM_RW`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe calls `access("/system", W_OK)` from the app UID. Success produces `system_rw|/system is writable` and a high-confidence review finding.

### Exact trigger condition

The app process sees `/system` as writable.

## What the result means

On a modern production Android device, `/system` is normally read-only and protected by verified boot. Write access for an ordinary UID is a strong anomaly indicating the environment, a permissive sandbox, or virtualization.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

`access(W_OK)` checks effective permissions and mount flags but does not perform an actual write. An unusual container may return an inaccurate result. Running the RKNHardering process as root also legitimately triggers the check.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Use stock firmware and do not run the app in a container that grants expanded filesystem permissions. A factory reset does not repair a modified system image.

### With root

Do not grant root to RKNHardering and do not remount the system globally as read-write. Systemless modules should leave the app’s view read-only. If `/system` is writable because of a debugging remount, restore it to read-only and reboot.

### How to verify the result

```bash
adb shell mount | grep -E ' /system( |/)| / '
adb shell test -w /system; echo $?
```
Exit code `0` means writable for the shell, but the app UID may see a different result.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Remounting and writing to system partitions can violate AVB, break OTA updates, and cause boot failure. Do not verify this by actually creating a file.

### Rollback

Reboot after removing the remount. If the system image was modified, restore the factory image and verified-boot metadata according to the device instructions.

## Evidence level

**Medium.** Verified from the single `access(W_OK)` condition; the checker assigns a high-confidence review finding.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-overlay-mount`, `root-suspicious-mount`, `root-selinux`.

[Back to the Native signs reference](../)
