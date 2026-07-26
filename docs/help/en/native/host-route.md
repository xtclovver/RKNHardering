---
title: "Public /32 or /128 host route through a physical interface"
permalink: /help/en/native/host-route/
---

# Public /32 or /128 host route through a physical interface

> **ID:** `HOST_ROUTE`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`isVpnServerHostRouteCandidate()` considers only netlink rows that are not default routes, have a `/32` or `/128` prefix, use the `unicast` type and `global` or `link` scope, are not in local table 255, and do not use the kernel protocol. The destination must be publicly routable and the interface must be a standard physical interface. Such a route resembles pinning a VPN server address outside the tunnel, but it can also be created by carrier and system services.

### Exact trigger condition

A matching public host route sets `needsReview=true` with medium confidence. `detected` remains false.

## What the result means

This is a candidate, not proof. On typical Android, a `VpnService` server socket is usually excluded from the VPN through `protect()` or fwmark without a separate host route, so the signal is more relevant to root/kernel VPNs or nonstandard clients.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

A CDN, captive portal, carrier IMS, OEM security service, or static network configuration may legitimately create a /32 route. Without process or socket correlation, the address cannot be identified as a VPN endpoint.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

First identify the route’s owner by when it appears: compare snapshots before the VPN starts, after it starts, and after it is disabled. If your client creates the route, prefer its standard `VpnService.protect()` or split-route mechanism; do not delete the route manually. An external gateway removes the local host route from the phone.

### With root

A kernel backend can hide this route shape, but shape-based filtering risks removing a legitimate /32. Upstream VPNHide documents host-route logic primarily for desktop-style or rooted VPNs. Verify that target traffic truly uses the physical network and that the server socket does not route back into the tunnel.

### How to verify the result

```bash
adb shell ip -4 route show table all | grep -E '(^| )/32| scope link'
adb shell ip -6 route show table all | grep '/128'
```
Capture three states: VPN off, VPN on, and client stopped. Do not publish the address in an issue without redacting it.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Deleting the host route may send the VPN connection into its own tunnel and break it. Filtering too broad a class of routes can disrupt carrier services.

### Rollback

Restart the VPN client or the network so that it recreates the route. Disable any root hook through its manager and reboot.

## Evidence level

**Medium.** Verified against the strict allowlist conditions in `isVpnServerHostRouteCandidate()` and the host-route unit tests. The signal is intentionally review-only.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [Unit tests for the native catalog/checker](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [VpnService.protect()](https://developer.android.com/reference/android/net/VpnService).
- External primary documentation or official project: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- External primary documentation or official project: [VPNHide host-route notes](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `route-table`, `vpn-policy-rules-netlink`, `established-vpn-socket`.

[Back to the Native signs reference](../)
