---
title: "Reverse Path Filtering Disabled Globally"
permalink: /help/en/native/sysctl-rp-filter/
---

# Reverse Path Filtering Disabled Globally

> **ID:** `SYSCTL_RP_FILTER`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectSysctl()` reads `/proc/sys/net/ipv4/conf/all/rp_filter`; an exact value of `0` produces `sysctl_rp_filter|rp_filter=0`. The legacy policy treats it as a medium-confidence review finding.

### Exact trigger condition

Global `rp_filter == 0`.

## What the result means

A disabled reverse-path filter occurs with complex policy routing, VPNs, tethering, and multihoming. It is not unusual on Android and is not direct proof.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

Actual behavior depends on per-interface values and the kernel’s `max(all, interface)` semantics. The check reads only `all`.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not change the sysctl merely to remove a review finding. Compare it with a clean baseline from the same firmware; the OEM may legitimately use 0.

### With root

Changing the value to 1 or 2 can break asymmetric routing and VPNs. Before testing, save the `all`, `default`, and per-interface values, then verify network connectivity.

### How to verify the result

```bash
adb shell cat /proc/sys/net/ipv4/conf/all/rp_filter
adb shell 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do printf "%s=" "$f"; cat "$f"; done' 2>/dev/null
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Strict `rp_filter` settings may drop legitimate split-tunnel or multi-WAN traffic.

### Rollback

Restore the saved sysctl values, or reboot the device if the change was not persistent.

## Evidence level

**Medium.** Verified from the exact `rp_filter==0` condition; medium-confidence review.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [ip-sysctl rp_filter](https://docs.kernel.org/networking/ip-sysctl.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `sysctl-forwarding`, `vpn-policy-rules-netlink`.

[Back to the Native signs reference](../)
