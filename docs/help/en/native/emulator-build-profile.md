---
title: "Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT heuristics"
permalink: /help/en/native/emulator-build-profile/
---

# Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT heuristics

> **ID:** `EMULATOR_BUILD`
> **Category:** Emulation, profiles, and isolation
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

Kotlin flags the fingerprint if it starts with `generic` or `unknown`, or contains `vbox`, `emulator`, or `test-keys`; the model if it contains `google_sdk`, `Emulator`, or `Android SDK built for`; hardware for the exact values `goldfish`, `ranchu`, or `vbox86`; product for `sdk_gphone*`, `vbox86p`, `emulator`, `sdk`, or `google_sdk`; and manufacturer for the exact value `Genymotion`. Each fact produces a medium-confidence review finding.

### Exact trigger condition

A match against any of the listed build patterns.

## What the result means

This is a broad heuristic, so `test-keys` may indicate custom firmware on a physical device rather than an emulator. Combine the result with QEMU and device-node markers.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

Build fields are easy to spoof and vary across OEMs. A production GSI or development board may legitimately look generic.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

To avoid this class of indicators, use a physical device running a production build. QEMU properties, goldfish/ranchu markers, special devices, and the build fingerprint are part of the environment; an ordinary app cannot change them consistently without system modification. Treat a cloud phone or OEM clone as a separate environment as well, and compare it against a physical-device baseline. For a physical device running a custom ROM, the only clean baseline is an official production build; a factory reset does not change the fingerprint.

### With root

Spoofing a couple of `getprop` values does not turn an emulator into a physical device: drivers, `/dev` nodes, the hardware profile, ABI, and kernel behavior remain. Root modules used for spoofing can remove one marker while creating hook, property, or library mismatches. They may be acceptable as an experiment during development, but RKNHardering should be run on a real device for a valid result. Changing fingerprint, model, product, and hardware consistently is difficult; partial spoofing remains visible in other layers and may break Play Integrity.

### How to verify the result

```bash
adb shell getprop ro.build.fingerprint
adb shell getprop ro.product.model
adb shell getprop ro.hardware
adb shell getprop ro.product.name
adb shell getprop ro.product.manufacturer
```
Check the exact substrings used by the implementation.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

An invalid fingerprint can break OTA updates or Play services; spoofing hardware or product values may select an incompatible HAL.

### Rollback

Remove the spoofing module and restore the build properties from the original image.

## Evidence level

**Medium.** Verified against `collectBuildEmulatorFacts()`; all emitted lines are medium-confidence review findings.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android Build API](https://developer.android.com/reference/android/os/Build).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `emulator-qemu-property`, `emulator-goldfish`, `root-property`.

[Back to the Native signs reference](../)
