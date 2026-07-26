---
title: "Emulator indicators summary"
permalink: /help/en/native/emulator-indicators/
---

# Emulator indicators summary

> **ID:** `EMULATOR_INDICATORS`
> **Category:** Emulation, profiles, and isolation
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Service

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

This is the category’s umbrella ID. The current `evaluateEmulator()` assigns specific IDs for QEMU properties, pipes, goldfish/ranchu, the driver, BlueStacks, and the build profile. It does not currently emit a separate positive `EMULATOR_INDICATORS` line.

### Exact trigger condition

The ID itself has no producer; it serves as a stable documentation entry and a placeholder for future aggregation.

## What the result means

Evaluate the child lines. The absence of all listed markers does not prove that the device is physical; a modern emulator may mask standard indicators.

**How the line affects the report:** This is an umbrella or fallback ID. It links a group of lines to the documentation, but does not always have its own positive producer.

## Limitations and possible false positives

The list does not include hardware attestation, sensors, telephony, graphics timing, or a full fingerprint analysis.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

To avoid this class of indicators, use a physical device running a production build. QEMU properties, goldfish/ranchu markers, special devices, and the build fingerprint are part of the environment; an ordinary app cannot change them consistently without system modification. Treat a cloud phone or OEM clone as a separate environment as well, and compare it against a physical-device baseline.

### With root

Spoofing a couple of `getprop` values does not turn an emulator into a physical device: drivers, `/dev` nodes, the hardware profile, ABI, and kernel behavior remain. Root modules used for spoofing can remove one marker while creating hook, property, or library mismatches. They may be acceptable as an experiment during development, but RKNHardering should be run on a real device for a valid result.

### How to verify the result

```bash
adb shell getprop ro.kernel.qemu
adb shell getprop ro.hardware
adb shell getprop ro.product.board
adb shell getprop ro.build.fingerprint
adb shell ls -l /dev/qemu_pipe /dev/socket/qemud 2>/dev/null
```
See the individual child pages for the exact criteria.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Spoofing a large set of build properties can break OTA updates, Play services, and app compatibility.

### Rollback

Remove the spoofing module or property rules and return to an emulator snapshot or the stock boot image.

## Evidence level

**Service.** Verified against the catalog and `evaluateEmulator()`; the umbrella ID is not assigned to positive findings in version 2.10.0.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Android Emulator](https://developer.android.com/studio/run/emulator).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `emulator-qemu-property`, `emulator-build-profile`, `emulator-qemu-pipe`.

[Back to the Native signs reference](../)
