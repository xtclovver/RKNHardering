---
title: "Reserved Legacy ID for TCP VPN Ports"
permalink: /help/en/native/tcp-vpn-port/
---

# Reserved Legacy ID for TCP VPN Ports

> **ID:** `TCP_VPN_PORT`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** ID retained for compatibility; no separate producer exists in 2.10.0
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`TCP_VPN_PORT` and the `tcp_vpn_port` mapping exist in the catalog and legacy loop, but the current C++ code does not emit this kind. TCP connections are checked separately under `established_vpn`, while localhost port occupancy is handled by `loopback_port_conflict`.

### Exact trigger condition

There is no separate positive producer; the UI normally shows “not found.”

## What the result means

Do not confuse this row with the actual TCP socket scan. The active `established-vpn-socket` producer reads `/proc/net/tcp` and searches for a remote port.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

A future version may restore a separate port probe; this page records the behavior in version 2.10.0.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

No action is required for this ID. Close any actual local API or listener and inspect the neighboring signals.

### With root

Do not install a port-hiding module for a registry-only row. If `loopback-port-conflict` triggers, use a narrowly scoped port or firewall configuration.

### How to verify the result

```bash
rg -n 'tcp_vpn_port|established_vpn|loopback_port_conflict' app/src/main
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

The main risk is a false sense of being clean while a port remains open.

### Rollback

None required.

## Evidence level

**Registry/compatibility.** Verified from the absence of a literal C++ producer and the presence of the catalog mapping.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `established-vpn-socket`, `loopback-port-conflict`.

[Back to the Native signs reference](../)
