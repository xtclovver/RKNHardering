---
title: "An unbound UDP socket immediately received a private IPv4 address"
permalink: /help/en/native/getsockname-leak/
---

# An unbound UDP socket immediately received a private IPv4 address

> **ID:** `GETSOCKNAME_LEAK`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectGetsocknameLeak()` creates an `AF_INET/SOCK_DGRAM` socket and immediately calls `getsockname()` without calling `bind()` or `connect()`. If the address is not 0.0.0.0 and falls within 10/8, 172.16/12, or 192.168/16, it emits `getsockname_leak` with the IP address.

### Exact trigger condition

An unconnected, unbound UDP socket has a nonzero private IPv4 address immediately after creation.

## What the result means

The checker treats this as a high-confidence indicator of unusual socket interposition or environment behavior, because a normal Linux socket generally remains at 0.0.0.0 until bind or connect. The private IP itself does not prove that it is a VPN address.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The label “VPN IP leak” is stronger than what the probe actually establishes. A private address may belong to the physical Wi-Fi or LAN. The signal will likely be absent on ordinary Android; if it appears, reproduce it and investigate hooks or virtualization.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

First repeat the test on a clean device with the release APK. Disable rootless virtualization, LSPatch, VPN SDKs, and network sandboxes. Do not change the LAN address merely for this signal.

### With root

Exclude RKNHardering from in-process Zygisk/Xposed hooks and verify libc/socket integrity. Do not replace the private IP with a public one: the correct baseline before bind/connect is 0.0.0.0.

### How to verify the result

For exact reproduction, build a minimal native test:
```c
int fd = socket(AF_INET, SOCK_DGRAM, 0);
struct sockaddr_in a = {}; socklen_t n = sizeof(a);
getsockname(fd, (struct sockaddr *)&a, &n);
```
The expected address before `bind/connect` is `0.0.0.0`. The `ss` command does not reproduce this probe.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

A global `getsockname()` hook breaks applications and may create network leaks. Do not modify the system libc.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified by the absence of bind/connect and the exact private ranges; the current checker classifies the kind as high confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [getsockname(2)](https://man7.org/linux/man-pages/man2/getsockname.2.html).
- External primary documentation or official project: [ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `so-bindtodevice`, `library-integrity`, `hook-markers`.

[Back to the Native signs reference](../)
