---
title: "Native Root Indicator Summary"
permalink: /help/en/native/root-indicators/
---

# Native Root Indicator Summary

> **ID:** `ROOT_INDICATORS`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Service

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

This is the umbrella ID for the state of the root check. When `nativeDetectRoot()` returns no rows, the checker displays an informational “no native root indicators found” line under `ROOT_INDICATORS`. When artifacts are present, separate IDs are used for `su`, properties, management paths, mounts, SELinux, UID, and Magisk properties.

### Exact trigger condition

There is no separate positive trigger. Positive findings are distributed across the nine child pages.

## What the result means

A clean result means only that the fixed list of native artifacts produced no rows. It does not check the bootloader, Play Integrity, hardware-backed attestation, every KernelSU/APatch variant, or every custom mount namespace.

**How the line affects the report:** This is an umbrella or fallback ID. It links a group of lines to the documentation, but does not always have its own positive producer.

## Limitations and possible false positives

Every root-detection model is heuristic. A concealed `su` binary may not be covered by the list, while an OEM test build may use `test-keys` without user-installed root access.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If root is not needed, the reliable fix is to return the device to stock condition through the official process: remove root through its manager, or flash factory `boot`/`init_boot` and system partitions that exactly match the installed build. An unlocked bootloader, custom kernel, and leftover directories may continue to reveal modification even after the manager is removed. Back up the device before recovery; relocking the bootloader on modified firmware can cause data loss or leave the device unbootable.

### With root

Root access can only reduce the observable surface; it cannot prove the absence of root. Grant `su` to as few apps as possible, do not grant it to RKNHardering, disable unnecessary modules, and do not switch SELinux to permissive mode. App Profile/DenyList behavior and mount isolation must be verified on the specific firmware. SUSFS and similar solutions are experimental: they require a compatible kernel and may introduce their own artifacts. A separate stock device is still required for a reference test.

### How to verify the result

Open the child details. For general orientation:
```bash
adb shell getprop ro.build.tags
adb shell getprop ro.debuggable
adb shell id
adb shell cat /sys/fs/selinux/enforce 2>/dev/null
```
The shell UID does not reproduce the app’s mount namespace.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Treating a clean aggregate result as a complete guarantee is a mistake. Restoring stock state may erase data, and relocking the bootloader on incompatible firmware can prevent the device from booting.

### Rollback

Diagnostic actions require no rollback. To unroot, use the official removal procedure for the chosen root solution and a saved factory image.

## Evidence level

**Structural.** Verified from the `rootFindings.isEmpty()` branch in `evaluateRootIndicators()` and from `nativeDetectRoot()`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Android SELinux](https://source.android.com/docs/security/features/selinux).
- External primary documentation or official project: [Magisk install/uninstall guidance](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-su-binary`, `root-management`, `root-suspicious-mount`, `root-selinux`.

[Back to the Native signs reference](../)
