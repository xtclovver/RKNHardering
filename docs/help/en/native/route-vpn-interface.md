---
title: "Legacy Routes Through Fixed VPN Interface Names"
permalink: /help/en/native/route-vpn-interface/
---

# Legacy Routes Through Fixed VPN Interface Names

> **ID:** `ROUTE_VPN_INTERFACE`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectVpnRoutes()` reads `/proc/net/route`, counts rows for `tun0`, `tun1`, `utun0`, `ppp0`, `wg0`, and `wg1`, and emits `route_vpn_iface|vpn_routes=N` when the count is greater than 0. This is a legacy high-confidence signal.

### Exact trigger condition

At least one row in `/proc/net/route` uses a fixed VPN interface name.

## What the result means

This is a direct IPv4 procfs leak. It does not depend on whether the route is the default route.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

On newer Android versions, SELinux often blocks procfs access for ordinary apps; in that case, the absence of the line does not mean the system is clean. IPv6 and netlink are covered by other signals.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, address the routing design rather than the way the table is displayed. Use an external gateway for a clean phone. If the VPN remains in `VpnService`, configure split routing so that the app under test actually exits through the expected physical network, but do not treat this as hiding local routes: the interface and policy rules may remain visible. Do not delete routes with `ip route` on a live device—Android and the VPN service will recreate them, and connectivity may be interrupted.

### With root

On a rooted device, the backend must filter the data source rather than libc alone. In upstream VPNHide, the kernel backends are intended for `ioctl`, netlink, and some route/procfs vectors; Zygisk remains a conditional fallback. Do not install kmod and KPM together, because they may intercept the same kernel functions. VPNHide Next claims broader PMTU/MSS/qdisc/BPF coverage, but this is an external claim that must be reproduced on the specific kernel. Upstream VPNHide documents filtering for `/proc/net/route`; a kernel backend must cover raw open/read access when the ROM’s SELinux policy allows the file to be read.

### How to verify the result

```bash
adb shell cat /proc/net/route 2>&1 | head -80
```
`permission denied` means the path is inaccessible to the shell; the app may obtain a different result.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

procfs cannot be edited like a regular file. Deleting routes breaks network connectivity.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified from the `/proc/net/route` parser and the fixed-name list; high kind.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- External primary documentation or official project: [VPNHide proc route coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `route-table`, `proc-ipv6-route-vpn`, `vpn-policy-rules`.

[Back to the Native signs reference](../)
