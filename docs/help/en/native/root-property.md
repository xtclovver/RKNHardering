---
title: "Suspicious Root/Debug System Properties"
permalink: /help/en/native/root-property/
---

# Suspicious Root/Debug System Properties

> **ID:** `ROOT_PROPERTY`
> **Category:** Root and system state
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe checks the exact pairs `ro.debuggable=1`, `ro.secure=0`, `ro.build.selinux=0`, `service.adb.root=1`, and `ro.build.tags=test-keys`. Only an exact match produces `root_prop`; the checker evaluates it as a medium-confidence review finding.

### Exact trigger condition

At least one fixed property has the exact suspicious value.

## What the result means

The signal more often identifies a debug or engineering ROM, or a modified boot image, than a particular root manager. `test-keys` is especially common in community custom ROMs.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

A production root configuration may leave these properties unchanged. Conversely, an AOSP userdebug build can legitimately trigger the check even when `su` has not been granted.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Use an official manufacturer user build when a clean baseline is required. A factory reset does not replace the firmware or change `ro.*` properties. Do not download an arbitrary `build.prop`; it must match the installed image.

### With root

`resetprop` can change the visible value, but inconsistencies with boot state, the build fingerprint, and mounts may become separate indicators. Use spoofing only as a laboratory test, not as proof that the device is clean. SELinux cannot be “fixed” with a single property value.

### How to verify the result

```bash
adb shell getprop ro.debuggable
adb shell getprop ro.secure
adb shell getprop ro.build.selinux
adb shell getprop service.adb.root
adb shell getprop ro.build.tags
```
Compare the values with the detail; the property namespace may differ after root-level substitution.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Changing early-boot properties or the boot image may cause a boot loop. An incorrect fingerprint can break OTA updates, Play services, and compatibility.

### Rollback

Remove only the `resetprop` rule you created and reboot. If the boot image was modified, restore the original image from the same build.

## Evidence level

**Medium.** Verified from `kRootProps`; the checker assigns medium confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android build variants](https://source.android.com/docs/setup/build/building).
- External primary documentation or official project: [Magisk resetprop documentation](https://topjohnwu.github.io/Magisk/tools.html#resetprop).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `root-magisk-property`, `emulator-build-profile`, `root-selinux`.

[Back to the Native signs reference](../)
