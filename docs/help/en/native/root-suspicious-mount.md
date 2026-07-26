---
title: "Mount Rows Containing Magisk/core-only and Root Markers"
permalink: /help/en/native/root-suspicious-mount/
---

# Mount Rows Containing Magisk/core-only and Root Markers

> **ID:** `ROOT_SUSPICIOUS_MOUNT`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

C++ reads `/proc/self/mounts` and produces `suspicious_mount` when a row contains `magisk` or `core-only`. Kotlin additionally evaluates the detail for the markers `magisk`, `zygisk`, `lsposed`, `riru`, `kernelsu`, `apatch`, `/data/adb`, and `core-only`: a match receives high confidence; otherwise confidence is medium.

### Exact trigger condition

A row with a fixed C++ marker is visible in the process’s mount namespace. In the current producer, that marker is effectively either `magisk` or `core-only`.

## What the result means

This is a strong sign of a systemless or root mount. The check inspects the app process’s own namespace, so a global `mount` listing from the shell may not match.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

KernelSU or APatch mounts without the word `magisk` may not reach the C++ producer, even though Kotlin is prepared to recognize those markers in the detail. A bind mount from a legitimate sandbox may also look unusual.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If root is not needed, the reliable fix is to return the device to stock condition through the official process: remove root through its manager, or flash factory `boot`/`init_boot` and system partitions that exactly match the installed build. An unlocked bootloader, custom kernel, and leftover directories may continue to reveal modification even after the manager is removed. Back up the device before recovery; relocking the bootloader on modified firmware can cause data loss or leave the device unbootable.

### With root

Root access can only reduce the observable surface; it cannot prove the absence of root. Grant `su` to as few apps as possible, do not grant it to RKNHardering, disable unnecessary modules, and do not switch SELinux to permissive mode. App Profile/DenyList behavior and mount isolation must be verified on the specific firmware. SUSFS and similar solutions are experimental: they require a compatible kernel and may introduce their own artifacts. A separate stock device is still required for a reference test. Verify that App Profile or mount isolation is actually applied before the process starts. After a change, force-stop the app; a reboot may also be necessary.

### How to verify the result

```bash
adb shell cat /proc/self/mounts | grep -Ei 'magisk|core-only|zygisk|lsposed|riru|kernelsu|apatch|/data/adb'
```
These are the shell process’s mounts. For the exact app namespace, use the built-in detail or `run-as` on a debuggable build.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Manually unmounting root-manager mount points may hang processes or break the system. Do not apply a lazy unmount blindly.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Medium.** Verified from the `/proc/self/mounts` read and the two levels of marker logic.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/pid/mounts namespaces](https://man7.org/linux/man-pages/man5/proc_pid_mounts.5.html).
- External primary documentation or official project: [mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-overlay-mount`, `root-management`, `hook-markers`.

[Back to the Native signs reference](../)
