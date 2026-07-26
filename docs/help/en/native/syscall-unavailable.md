---
title: "Native Syscall/Socket Probe Unavailable"
permalink: /help/en/native/syscall-unavailable/
---

# Native Syscall/Socket Probe Unavailable

> **ID:** `SYSCALL_UNAVAILABLE`
> **Category:** Service signals
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Availability

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The legacy checker collects all `unavailable*` rows from the syscall group. The current producer emits either `unavailable|ip_recverr|denied` or `unavailable|ip_recverr|not_supported`. These are displayed as low-confidence informational data under the `SYSCALL_UNAVAILABLE` ID.

### Exact trigger condition

The probe cannot enable `IP_RECVERR` because of `EACCES`/`EPERM` or `ENOPROTOOPT`.

## What the result means

Unavailability does not mean the system is clean. It means this path produced no measurement; review findings from neighboring signals remain valid.

**How the line affects the report:** The signal means that the probe could not be performed. `unavailable` must not be interpreted as proof that no VPN is present.

## Limitations and possible false positives

The ID is an aggregate and may include new unavailable kinds in future versions. Without an errno or context log, the current detail does not sufficiently distinguish SELinux restrictions from a missing kernel feature.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Keep SELinux enforcing. Record whether the result is `denied` or `not_supported`, along with the device model, Android version, and kernel. Do not obtain root merely for this diagnostic.

### With root

Check AVC logs and kernel compatibility, but do not add a broad allow rule. For testing, reproduce the behavior in a separate minimal APK.

### How to verify the result

```bash
adb logcat -d | grep -E 'avc: denied|IP_RECVERR' | tail -80
adb shell uname -a
```
Availability from a shell socket is not equivalent to availability in the app domain.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

A broad sepolicy rule for network options weakens the sandbox. An `unavailable` result is safer than an incorrectly exposed privilege.

### Rollback

Remove the test sepolicy rule or module and reboot.

## Evidence level

**Availability.** Verified from the `unavailableSyscalls` aggregation and the only current producer.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- External primary documentation or official project: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `ip-recverr`, `native-library`.

[Back to the Native signs reference](../)
