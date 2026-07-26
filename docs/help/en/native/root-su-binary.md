---
title: "su File in Known Paths"
permalink: /help/en/native/root-su-binary/
---

# su File in Known Paths

> **ID:** `ROOT_SU_BINARY`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

C++ calls `access(F_OK)` for 12 paths: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su`, `/data/local/su`, `/data/local/bin/su`, `/data/local/xbin/su`, `/system/sd/xbin/su`, `/system/bin/failsafe/su`, `/vendor/bin/su`, `/product/bin/su`, and `/apex/com.android.runtime/bin/su`. A matching path receives high confidence, but the category sets a review finding rather than `detected` on its own.

### Exact trigger condition

Any fixed path in the list is visible to an existence check from the app UID.

## What the result means

This is a strong local root artifact. The file’s presence does not prove that RKNHardering can execute `su`, while its absence does not rule out kernel-based root or a nonstandard path.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

A mount namespace may hide the path only from selected UIDs. Older ROMs, engineering builds, and remnants of an incomplete unroot procedure may leave a nonfunctional `su` binary.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If root is not needed, the reliable fix is to return the device to stock condition through the official process: remove root through its manager, or flash factory `boot`/`init_boot` and system partitions that exactly match the installed build. An unlocked bootloader, custom kernel, and leftover directories may continue to reveal modification even after the manager is removed. Back up the device before recovery; relocking the bootloader on modified firmware can cause data loss or leave the device unbootable. If root has already been removed, do not manually erase the file from a read-only partition. First identify the image or module that introduced it, then restore the partition through the normal procedure.

### With root

Root access can only reduce the observable surface; it cannot prove the absence of root. Grant `su` to as few apps as possible, do not grant it to RKNHardering, disable unnecessary modules, and do not switch SELinux to permissive mode. App Profile/DenyList behavior and mount isolation must be verified on the specific firmware. SUSFS and similar solutions are experimental: they require a compatible kernel and may introduce their own artifacts. A separate stock device is still required for a reference test. Simply renaming `su` does not hide mounts, management paths, properties, or UID state. Restrict visibility through the official App Profile/DenyList feature of your root solution and test the actual app UID.

### How to verify the result

```bash
adb shell 'for p in /system/bin/su /system/xbin/su /sbin/su /su/bin/su /data/local/su /data/local/bin/su /data/local/xbin/su /system/sd/xbin/su /system/bin/failsafe/su /vendor/bin/su /product/bin/su /apex/com.android.runtime/bin/su; do [ -e "$p" ] && ls -l "$p"; done'
```
Empty shell output does not guarantee that the app namespace is the same.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Removing a binary from a system partition may break OTA updates or boot. Do not run `rm` before backing up the image and identifying the mount source.

### Rollback

Restore the saved boot or system image, or reinstall root through the official manager if the file was part of its normal installation.

## Evidence level

**Medium.** Verified from the exact `kSuPaths` array; Kotlin assigns high confidence and `needsReview=true`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Magisk official install](https://github.com/topjohnwu/Magisk/blob/master/docs/install.md).
- External primary documentation or official project: [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next).
- External primary documentation or official project: [APatch](https://github.com/bmax121/APatch).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-management`, `root-suspicious-mount`, `root-uid`.

[Back to the Native signs reference](../)
