---
title: "Reserved legacy ARP ID for a VPN interface"
permalink: /help/en/native/arp-vpn-interface/
---

# Reserved legacy ARP ID for a VPN interface

> **ID:** `ARP_VPN_INTERFACE`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** ID retained for compatibility; no separate producer exists in 2.10.0
> **Role in the verdict:** Registry/compatibility

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`ARP_VPN_INTERFACE`/`arp_vpn_iface` is present in the catalog and marked as legacy high, but `detectArpNeighbors()` in version 2.10.0 does not emit this kind. It counts zero and broadcast MAC addresses and emits only `hidden_mac_neighbors`.

### Exact trigger condition

There is no separate producer.

## What the result means

ARP is still read, but the actual active signal is `hidden-mac-neighbors`. In the current code, the interface from the ARP line is not matched against VPN-like names.

**How the line affects the report:** The ID remains in the catalog and UI, but version 2.10.0 does not emit a separate positive line of this kind. A more specific neighboring signal usually covers the case.

## Limitations and possible false positives

A future parser may add `arp_vpn_iface`; for now, the URL is retained for compatibility.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

There is no absent kind to bypass. Review the actual zero-MAC entries on the adjacent page.

### With root

A root-level ARP filter is not needed for this ID. Do not flush the neighbor table: doing so causes delays and loss of local connectivity.

### How to verify the result

```bash
rg -n 'arp_vpn_iface|hidden_mac_neighbors|detectArpNeighbors' app/src/main
adb shell cat /proc/net/arp 2>&1
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

`ip neigh flush all` disrupts active LAN connections and does not remove the producer.

### Rollback

No rollback is required; after an accidental flush, the neighbor table is repopulated by traffic or reconnection.

## Evidence level

**Registry/compatibility.** Verified by the absence of a producer and the actual `hidden_mac_neighbors` output.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [arp(7)](https://man7.org/linux/man-pages/man7/arp.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `hidden-mac-neighbors`.

[Back to the Native signs reference](../)
