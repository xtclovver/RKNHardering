---
title: "Goldfish in `/proc/tty/drivers`"
permalink: /help/en/native/emulator-qemu-driver/
---

# Goldfish in `/proc/tty/drivers`

> **ID:** `EMULATOR_QEMU_DRIVER`
> **Category:** Emulation, profiles, and isolation
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The function reads `/proc/tty/drivers` line by line and searches for the literal string `goldfish`. A match emits `qemu_driver`; Kotlin treats it as medium confidence because this kind is not in the high-confidence allowlist.

### Exact trigger condition

The substring `goldfish` appears in the procfs list of TTY drivers.

## What the result means

It indicates an emulator-platform driver in the kernel. Under the current policy, confidence is medium despite the specificity of the marker.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

Access to procfs may vary by Android version and SELinux policy. The kernel may include the driver even when the corresponding device is not in use.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

To avoid this class of indicators, use a physical device running a production build. QEMU properties, goldfish/ranchu markers, special devices, and the build fingerprint are part of the environment; an ordinary app cannot change them consistently without system modification. Treat a cloud phone or OEM clone as a separate environment as well, and compare it against a physical-device baseline.

### With root

Spoofing a couple of `getprop` values does not turn an emulator into a physical device: drivers, `/dev` nodes, the hardware profile, ABI, and kernel behavior remain. Root modules used for spoofing can remove one marker while creating hook, property, or library mismatches. They may be acceptable as an experiment during development, but RKNHardering should be run on a real device for a valid result. Hiding one procfs line requires a kernel/proc hook and does not change the actual hardware profile.

### How to verify the result

```bash
adb shell grep -i goldfish /proc/tty/drivers 2>/dev/null
```
`permission denied` means insufficient permissions, not a clean result.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Patching the driver list or disabling the TTY driver may break the console and guest/host communication.

### Rollback

Restore the original kernel or snapshot.

## Evidence level

**Medium.** Verified against `fileContains('/proc/tty/drivers', 'goldfish')`; medium confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/tty/drivers ABI](https://docs.kernel.org/admin-guide/devices.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `emulator-goldfish`, `emulator-qemu-pipe`.

[Back to the Native signs reference](../)
