---
title: "`NETLINK_SOCK_DIAG` is unavailable to the app"
permalink: /help/en/native/inet-diag-denied/
---

# `NETLINK_SOCK_DIAG` is unavailable to the app

> **ID:** `INET_DIAG_DENIED`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe only calls `socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)`. If socket creation returns `EACCES` or `EPERM`, it emits `inet_diag_denied`; a successfully created socket is immediately closed without a dump. The kind produces a medium-confidence review finding.

### Exact trigger condition

The kernel or SELinux prevents creation of a `NETLINK_SOCK_DIAG` socket.

## What the result means

This describes the sandbox or ROM. Denial does not prove a VPN; rather, it prevents socket diagnostics from being read. Use the line to explain unavailable coverage.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The probe does not test whether a `SOCK_DIAG` request can be sent after socket creation, and it does not distinguish policies by protocol family. Denial may be expected on stock Android.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not attempt to bypass the restriction. Compare against a baseline on the same firmware, and remember that the other socket checks operate independently.

### With root

Do not grant `NET_ADMIN` or `NET_RAW`, and do not broaden RKNHardering’s sepolicy. When developing a ROM, test the minimum policy in a dedicated test domain rather than the production `untrusted_app` domain.

### How to verify the result

```bash
adb shell 'cat /proc/net/netlink 2>/dev/null | head'
adb logcat -d | grep -Ei 'avc: denied.*sock_diag|NETLINK_SOCK_DIAG' | tail -30
```
The exact result is visible only from the app domain.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Allowing ordinary apps to open inet_diag can expose sockets belonging to other UIDs and weaken privacy.

### Rollback

Remove the capability or sepolicy change and reboot. Confirm that SELinux is enforcing.

## Evidence level

**Medium.** Verified against the single `EACCES`/`EPERM` branch and the checker’s medium-confidence path.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [sock_diag kernel documentation](https://www.kernel.org/doc/html/latest/networking/diagnostic.html).
- External primary documentation or official project: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `established-vpn-socket`, `syscall-unavailable`, `fib-trie-denied`.

[Back to the Native signs reference](../)
