---
title: "Overlay Mount Over /system or /vendor"
permalink: /help/en/native/root-overlay-mount/
---

# Overlay Mount Over /system or /vendor

> **ID:** `ROOT_OVERLAY_MOUNT`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

C++ produces `overlay_mount` for a `/proc/self/mounts` row that contains `overlay` and either `/system` or `/vendor`. Kotlin deliberately discards the row, however, unless its detail contains a high-confidence root marker (`magisk`, `zygisk`, `lsposed`, `riru`, `kernelsu`, `apatch`, `/data/adb`, or `core-only`). Only a confirmed marker becomes a high-confidence review finding.

### Exact trigger condition

An overlay over system or vendor together with a root marker in the same detail row.

## What the result means

The signal distinguishes ordinary overlayfs use from a root or systemless mount. The current checker does not display an overlay by itself when no marker is present.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The mount-string format depends on the kernel and root manager. A marker may be hidden while the overlay remains; the current Kotlin filter will omit such a row.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If root is not needed, the reliable fix is to return the device to stock condition through the official process: remove root through its manager, or flash factory `boot`/`init_boot` and system partitions that exactly match the installed build. An unlocked bootloader, custom kernel, and leftover directories may continue to reveal modification even after the manager is removed. Back up the device before recovery; relocking the bootloader on modified firmware can cause data loss or leave the device unbootable.

### With root

Root access can only reduce the observable surface; it cannot prove the absence of root. Grant `su` to as few apps as possible, do not grant it to RKNHardering, disable unnecessary modules, and do not switch SELinux to permissive mode. App Profile/DenyList behavior and mount isolation must be verified on the specific firmware. SUSFS and similar solutions are experimental: they require a compatible kernel and may introduce their own artifacts. A separate stock device is still required for a reference test. Do not disable overlayfs while modules depend on it until a boot rollback is prepared. Reducing the number of modules reduces the overlay surface.

### How to verify the result

```bash
adb shell cat /proc/self/mounts | grep -E 'overlay.*(/system|/vendor)|(/system|/vendor).*overlay'
```
Compare the complete row with the marker shown in the built-in detail.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Unmounting the overlay or changing its lower, upper, or work directory may crash system services and cause a boot loop.

### Rollback

Disable the responsible module through the root manager’s safe mode, or restore a known-good boot image. Do not delete the upper directory before successfully booting into a clean state.

## Evidence level

**Medium.** Verified from the C++ overlay/system/vendor condition and the Kotlin high-confidence-marker filter.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [overlayfs documentation](https://docs.kernel.org/filesystems/overlayfs.html).
- External primary documentation or official project: [Magisk modules](https://github.com/topjohnwu/Magisk).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-suspicious-mount`, `root-system-rw`, `root-management`.

[Back to the Native signs reference](../)
