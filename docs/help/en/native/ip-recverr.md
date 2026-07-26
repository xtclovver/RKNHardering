---
title: "Reserved positive `IP_RECVERR` ID"
permalink: /help/en/native/ip-recverr/
---

# Reserved positive `IP_RECVERR` ID

> **ID:** `IP_RECVERR`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** ID retained for compatibility; no separate producer exists in 2.10.0
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectIpRecvErr()` only attempts to enable `IP_RECVERR`. On success, it emits nothing. On `EACCES`/`EPERM` or `ENOPROTOOPT`, it emits `unavailable|ip_recverr|...`, which Kotlin maps to `SYSCALL_UNAVAILABLE` rather than `IP_RECVERR`. The positive ID therefore does not currently appear.

### Exact trigger condition

There is no separate `ip_recverr` producer. An availability error belongs to the neighboring ID.

## What the result means

The `IP_RECVERR` line in the UI is normally “not found.” This must not be interpreted as either support or absence of a VPN; see `syscall-unavailable`.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

The catalog and legacy description remain from a broader design. The code does not read the error queue or analyze PMTU errors.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not change anything for this ID. If an unavailable result appears, record the errno and ROM version.

### With root

Do not grant the app `CAP_NET_ADMIN` merely to make setsockopt succeed: `IP_RECVERR` normally does not require it, and broader privileges create new signals. Change policy only for a confirmed platform bug.

### How to verify the result

```bash
rg -n 'detectIpRecvErr|ip_recverr|SYSCALL_UNAVAILABLE' app/src/main
```
At runtime, use the `syscall-unavailable` detail.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Weakening socket or SELinux policy for a diagnostic probe increases the attack surface.

### Rollback

Remove only the added sepolicy or capability rule and reboot.

## Evidence level

**Registry/compatibility.** Verified against the `EACCES`/`EPERM`/`ENOPROTOOPT` branches and the unavailable mapper.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [ip(7) IP_RECVERR](https://man7.org/linux/man-pages/man7/ip.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `syscall-unavailable`, `udp-pmtu-fail`.

[Back to the Native signs reference](../)
