---
title: "ARP entries with a zero or broadcast MAC address"
permalink: /help/en/native/hidden-mac-neighbors/
---

# ARP entries with a zero or broadcast MAC address

> **ID:** `HIDDEN_MAC_NEIGHBORS`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectArpNeighbors()` reads `/proc/net/arp`, counts all rows, and counts rows whose MAC is `00:00:00:00:00:00` or contains `ff:ff:ff:ff:ff:ff`. If hidden > 0, the legacy policy classifies the kind as high confidence.

### Exact trigger condition

At least one ARP row has a zero or broadcast MAC address.

## What the result means

The project’s high-confidence policy treats this as evidence of hidden neighbors, but incomplete ARP/NUD resolution and stale entries can be ordinary network states. The total/hidden detail is important.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

ARP applies only to IPv4 and layer 2. A zero MAC may be temporary while an address is being resolved, and a broadcast MAC may be legitimate. The interface is not checked for VPN characteristics.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Repeat the check after Wi-Fi is stable and after generating a small amount of traffic to the gateway. Toggle the network if an entry is stuck. Do not flush ARP merely to obtain a green line without understanding the address.

### With root

Do not hide the entire ARP table; doing so creates count mismatches and disrupts LAN diagnostics. If a VPN module generates a synthetic neighbor row, correct its configuration or use an external gateway.

### How to verify the result

```bash
adb shell cat /proc/net/arp 2>&1
adb shell ip neigh show 2>/dev/null
```
Capture two runs separated by a short interval; a temporary `INCOMPLETE` entry may disappear.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Flushing the neighbor table temporarily interrupts local connections and increases ARP traffic.

### Rollback

Reconnect Wi-Fi or the network; the neighbor cache will repopulate automatically.

## Evidence level

**High.** Verified against the exact MAC conditions; the legacy policy marks it high confidence, although false positives are possible.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [arp(7)](https://man7.org/linux/man-pages/man7/arp.7.html).
- External primary documentation or official project: [ip-neighbour](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `arp-vpn-interface`, `interface-enumeration`.

[Back to the Native signs reference](../)
