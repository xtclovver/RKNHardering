---
title: "Reserved Legacy ID for UDP VPN Ports"
permalink: /help/en/native/udp-vpn-port/
---

# Reserved Legacy ID for UDP VPN Ports

> **ID:** `UDP_VPN_PORT`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** ID retained for compatibility; no separate producer exists in 2.10.0
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`UDP_VPN_PORT` and `udp_vpn_port` remain in the catalog and are even marked as legacy high confidence, but the current C++ code does not produce a row of this kind. The active UDP checks cover conflicts on the physical IP and PMTU/GSO diagnostics.

### Exact trigger condition

There is no separate producer; the high-confidence policy is not activated without a row.

## What the result means

This page exists for compatibility. Occupied UDP ports 500, 4500, 1194, 1701, and 51820 are checked by `udp-port-conflict-physical`.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

A high-confidence ID in Kotlin may create the false impression that the check is active; this documentation explicitly distinguishes the registry from the producer.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Close an unnecessary UDP listener or move the VPN to a gateway. A catalog-only ID requires no bypass.

### With root

A narrowly scoped UID firewall rule is appropriate only for a listener that has actually been identified. Do not block IKE or WireGuard ports globally when the VPN needs them.

### How to verify the result

```bash
rg -n 'udp_vpn_port|udp_port_conflict_physical' app/src/main
adb shell ss -lun 2>/dev/null | head -80
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Globally blocking UDP 500/4500 breaks IPsec; port 51820 may be used by WireGuard.

### Rollback

Remove only the firewall rule you created and restart the VPN.

## Evidence level

**Registry/compatibility.** Verified from the catalog mapping and the absence of a producer.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `udp-port-conflict-physical`, `udp-pmtu-ok`, `udp-pmtu-fail`.

[Back to the Native signs reference](../)
