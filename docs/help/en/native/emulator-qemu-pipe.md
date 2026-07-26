---
title: "QEMU/Genymotion devices and sockets"
permalink: /help/en/native/emulator-qemu-pipe/
---

# QEMU/Genymotion devices and sockets

> **ID:** `EMULATOR_QEMU_PIPE`
> **Category:** Emulation, profiles, and isolation
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe checks for `/dev/qemu_pipe`, `/dev/socket/qemud`, `/dev/socket/genyd`, and `/dev/socket/baseband_genyd`. Any accessible path emits `qemu_pipe` with a high-confidence review finding.

### Exact trigger condition

`access(F_OK)` succeeds for one of the four paths.

## What the result means

This is a strong emulator device-node marker. Unlike a build property, it reflects actual guest/host infrastructure.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

SELinux may hide the path from the app, and a vendor test device could theoretically expose a similar socket. Absence does not exclude a different hypervisor.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

To avoid this class of indicators, use a physical device running a production build. QEMU properties, goldfish/ranchu markers, special devices, and the build fingerprint are part of the environment; an ordinary app cannot change them consistently without system modification. Treat a cloud phone or OEM clone as a separate environment as well, and compare it against a physical-device baseline.

### With root

Spoofing a couple of `getprop` values does not turn an emulator into a physical device: drivers, `/dev` nodes, the hardware profile, ABI, and kernel behavior remain. Root modules used for spoofing can remove one marker while creating hook, property, or library mismatches. They may be acceptable as an experiment during development, but RKNHardering should be run on a real device for a valid result. Bind-mounting an empty path hides one marker, but creates a mount artifact and does not change the drivers.

### How to verify the result

```bash
adb shell ls -l /dev/qemu_pipe /dev/socket/qemud /dev/socket/genyd /dev/socket/baseband_genyd 2>/dev/null
```
Check access specifically from the app context when a debuggable build is available.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Deleting or masking the QEMU pipe breaks emulator communication with the host, telephony, and shutdown/control functions.

### Rollback

Restore the snapshot, or remove the mount-hiding module and restart the AVD.

## Evidence level

**Medium.** Verified against `kPipePaths`; the checker assigns high confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Android Emulator architecture](https://developer.android.com/studio/run/emulator-acceleration).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `emulator-qemu-property`, `emulator-qemu-driver`, `emulator-build-profile`.

[Back to the Native signs reference](../)
