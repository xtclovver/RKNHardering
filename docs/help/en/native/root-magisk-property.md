---
title: "Magisk-Specific System Properties"
permalink: /help/en/native/root-magisk-property/
---

# Magisk-Specific System Properties

> **ID:** `ROOT_MAGISK_PROPERTY`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe checks `init.svc.magisk_daemon`, `init.svc.magisk_pfs`, and `persist.magisk.hide`. Any nonempty value produces `magisk_prop` and a high-confidence review finding.

### Exact trigger condition

At least one of the three properties exists and is nonempty in the process’s property view.

## What the result means

This is a strong Magisk artifact, especially on older or compatibility-oriented configurations. A current version may not use all of these names, so a clean result does not rule out Magisk.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

An OEM component or third-party module could theoretically create a property with the same name. `resetprop` may hide it only in some contexts while leaving mount or path artifacts.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

If root is not needed, the reliable fix is to return the device to stock condition through the official process: remove root through its manager, or flash factory `boot`/`init_boot` and system partitions that exactly match the installed build. An unlocked bootloader, custom kernel, and leftover directories may continue to reveal modification even after the manager is removed. Back up the device before recovery; relocking the bootloader on modified firmware can cause data loss or leave the device unbootable.

### With root

Root access can only reduce the observable surface; it cannot prove the absence of root. Grant `su` to as few apps as possible, do not grant it to RKNHardering, disable unnecessary modules, and do not switch SELinux to permissive mode. App Profile/DenyList behavior and mount isolation must be verified on the specific firmware. SUSFS and similar solutions are experimental: they require a compatible kernel and may introduce their own artifacts. A separate stock device is still required for a reference test. If the property comes from a legacy module, update or remove that module through its official manager. Do not use an arbitrary hiding script that rewrites `init.svc.*` properties in bulk.

### How to verify the result

```bash
adb shell getprop init.svc.magisk_daemon
adb shell getprop init.svc.magisk_pfs
adb shell getprop persist.magisk.hide
```
Compare the values with the detail after force-stopping and relaunching the app.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Substituting an init-service property may disrupt service management and make diagnostics harder. Modifying boot scripts may cause a boot loop.

### Rollback

Remove the `resetprop` rule or legacy module you added, then reboot. For complete unrooting, follow the official Magisk instructions.

## Evidence level

**Medium.** Verified from `kMagiskProps`; Kotlin assigns a high-confidence review finding.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Magisk official repository](https://github.com/topjohnwu/Magisk).
- External primary documentation or official project: [Magisk releases](https://github.com/topjohnwu/Magisk/releases/latest).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-property`, `root-management`, `root-suspicious-mount`.

[Back to the Native signs reference](../)
