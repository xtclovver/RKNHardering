---
title: "Legacy Socket Identity Under the Historical SO_BINDTODEVICE Name"
permalink: /help/en/native/so-bindtodevice/
---

# Legacy Socket Identity Under the Historical SO_BINDTODEVICE Name

> **ID:** `SO_BINDTODEVICE`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The `detectSocketLeaks()` function does not call `SO_BINDTODEVICE`. It creates an unconnected UDP/IPv4 socket, calls `getsockname()`, and emits `so_bindtodevice|local_ip=...` only when the local address is nonzero. An unconnected socket normally returns `0.0.0.0`, so this line is rare. The legacy policy treats it as a medium-confidence review finding.

### Exact trigger condition

An unconnected UDP socket immediately has a nonzero local IPv4 address.

## What the result means

This is a suspicious socket identity, but the page name is historically inaccurate. The actual `SO_BINDTODEVICE` check is documented under `bindtodevice-leak`.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

On standard Linux, the address is selected after `connect()` or `bind()`, so the current probe normally emits nothing. A container or hook may alter this behavior.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

No network changes are required when the line is absent. If it appears, repeat the test on a clean device and investigate virtualization or proxy SDKs.

### With root

Look for a hook that automatically binds or connects the socket rather than masking the detail. Exclude the target from in-process modules.

### How to verify the result

Reproduction requires a small native test: `socket(AF_INET, SOCK_DGRAM)` followed by `getsockname()` without `bind()` or `connect()`. The `ss` command does not display an unregistered, short-lived socket. In the source code:
```bash
rg -n 'detectSocketLeaks|so_bindtodevice' app/src/main/cpp/native_signs_probe.cpp
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Changing global socket binding breaks application routing.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Medium.** Verified from the actual implementation; this documentation corrects the mismatch in the historical name.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html).
- External primary documentation or official project: [ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `bindtodevice-leak`, `getsockname-leak`.

[Back to the Native signs reference](../)
