---
title: "Main Routing Table and Default Route"
permalink: /help/en/native/route-table/
---

# Main Routing Table and Default Route

> **ID:** `ROUTE_TABLE`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Mixed

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The native probe collects IPv4 and IPv6 routes, including netlink metadata. `evaluateRoutes()` identifies default routes and deduplicates them by canonical interface and address family. A default route on a VPN-like interface is assigned high confidence. A default route on an unknown, nonstandard interface is assigned medium confidence, but the current checker also sets `detected=true`. Standard interfaces matching `wlan*`, `rmnet*`, `eth*`, `lo`, `ccmni*`, `ccemni*`, `seth*`, and `dummy*` are reported as informational data.

### Exact trigger condition

The check triggers when a default route points to a VPN pattern or to an interface outside the allowlist of standard names. The absence of a default route is informational only.

## What the result means

A VPN default route is a strong local signal. An unusual interface requires investigation because an OEM stack, tethering, CLAT, or an enterprise network stack may use a nonstandard name.

**How the line affects the report:** The same ID is used for both informational summaries and suspicious lines. The outcome depends on the specific detail and checker branch.

## Limitations and possible false positives

Android policy routing is more complex than a single main table; the actual route for a particular UID may be selected through an fwmark and `ip rule`. A clean default route therefore does not rule out a VPN, and a route dump may be briefly unstable during handover.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, address the routing design rather than the way the table is displayed. Use an external gateway for a clean phone. If the VPN remains in `VpnService`, configure split routing so that the app under test actually exits through the expected physical network, but do not treat this as hiding local routes: the interface and policy rules may remain visible. Do not delete routes with `ip route` on a live device—Android and the VPN service will recreate them, and connectivity may be interrupted.

### With root

On a rooted device, the backend must filter the data source rather than libc alone. In upstream VPNHide, the kernel backends are intended for `ioctl`, netlink, and some route/procfs vectors; Zygisk remains a conditional fallback. Do not install kmod and KPM together, because they may intercept the same kernel functions. VPNHide Next claims broader PMTU/MSS/qdisc/BPF coverage, but this is an external claim that must be reproduced on the specific kernel.

### How to verify the result

```bash
adb shell ip -4 route show table all
adb shell ip -6 route show table all
adb shell ip rule show
```
Compare the interface, address family, table, and default route. A shell snapshot is insufficient to determine the route of a particular app because of UID- and fwmark-based routing.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Manually deleting the default route leaves the device without network access. Incorrectly filtering a route dump can create inconsistencies with the interface index or Java `LinkProperties`.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Mixed.** Verified from `evaluateRoutes()`, canonicalization, and the standard/VPN interface lists.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NetworkInterfacePatterns.kt` — interface-name rules](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- External primary documentation or official project: [Android VpnService.Builder routes](https://developer.android.com/reference/android/net/VpnService.Builder).
- External primary documentation or official project: [VPNHide route coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `host-route`, `route-vpn-interface`, `vpn-policy-rules-netlink`, `route-count`.

[Back to the Native signs reference](../)
