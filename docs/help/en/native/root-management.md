---
title: "Root Manager Directories and Files"
permalink: /help/en/native/root-management/
---

# Root Manager Directories and Files

> **ID:** `ROOT_MANAGEMENT`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`nativeDetectRoot()` checks `/data/adb/magisk`, `/data/adb/modules`, `/data/adb/ksu`, `/data/adb/ksud`, legacy Superuser/SuperSU APKs and directories, `daemonsu`, an init.d script, and `/dev/com.koushikdutta.superuser.daemon`. An accessible path produces a high-confidence review finding.

### Exact trigger condition

`access(F_OK)` succeeds for any path in the fixed list.

## What the result means

This is a strong artifact of an installed or incompletely removed root stack. It does not prove that the module is currently active.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

A modern manager may store data elsewhere, and SELinux or a mount namespace may hide the path. `/data/adb/modules` may remain from an older installation even when `su` is no longer active.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If root is not needed, the reliable fix is to return the device to stock condition through the official process: remove root through its manager, or flash factory `boot`/`init_boot` and system partitions that exactly match the installed build. An unlocked bootloader, custom kernel, and leftover directories may continue to reveal modification even after the manager is removed. Back up the device before recovery; relocking the bootloader on modified firmware can cause data loss or leave the device unbootable. After a normal unroot procedure, inspect leftovers read-only. Do not delete `/data/adb` blindly: it may contain module data and recovery mechanisms.

### With root

Root access can only reduce the observable surface; it cannot prove the absence of root. Grant `su` to as few apps as possible, do not grant it to RKNHardering, disable unnecessary modules, and do not switch SELinux to permissive mode. App Profile/DenyList behavior and mount isolation must be verified on the specific firmware. SUSFS and similar solutions are experimental: they require a compatible kernel and may introduce their own artifacts. A separate stock device is still required for a reference test. Path isolation for the target UID must remain consistent with `/proc/self/mounts` and overlay state. If the path is hidden but the mount remains visible, a neighboring check will trigger.

### How to verify the result

```bash
adb shell 'for p in /data/adb/magisk /data/adb/modules /data/adb/ksu /data/adb/ksud /system/app/Superuser.apk /system/app/SuperSU.apk /system/app/SuperSU /system/xbin/daemonsu /system/etc/init.d/99SuperSUDaemon /dev/com.koushikdutta.superuser.daemon; do [ -e "$p" ] && echo "$p"; done'
```
The shell cannot read some `/data/adb` paths without root.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Manually deleting a module directory may remove safe-mode or rollback support, or leave mounts in a partially configured state. Use the root manager’s UI.

### Rollback

If you tested a hiding module, disable it through its normal mechanism. For complete removal, use the official uninstall procedure and restore the boot image.

## Evidence level

**Medium.** Verified from `kRootMgmtPaths`; every matching row receives a high-confidence review finding.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Magisk](https://github.com/topjohnwu/Magisk).
- External primary documentation or official project: [KernelSU Next](https://github.com/KernelSU-Next/KernelSU-Next).
- External primary documentation or official project: [APatch](https://github.com/bmax121/APatch).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-su-binary`, `root-suspicious-mount`, `root-overlay-mount`.

[Back to the Native signs reference](../)
