---
title: "Legacy Nonstandard IPv4 Routes on a VPN Interface"
permalink: /help/en/native/vpn-policy-rules/
---

# Legacy Nonstandard IPv4 Routes on a VPN Interface

> **ID:** `VPN_POLICY_RULES`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

While reading `/proc/net/route`, every row on a fixed VPN interface whose destination is neither 0 nor `FFFFFFFF` emits `vpn_policy_rules|iface=... dest=<hex>`. The legacy kind is high confidence.

### Exact trigger condition

A nondefault, non-`FFFFFFFF` IPv4 route through `tun0`, `tun1`, `utun0`, `ppp0`, `wg0`, or `wg1`.

## What the result means

The signal reflects split or policy routes through a tunnel, but its historical name is broader than the implementation: these are ordinary route rows, not `ip rule` entries.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

Only IPv4 procfs and fixed names are covered. Actual netlink policy rules are checked separately.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, address the routing design rather than the way the table is displayed. Use an external gateway for a clean phone. If the VPN remains in `VpnService`, configure split routing so that the app under test actually exits through the expected physical network, but do not treat this as hiding local routes: the interface and policy rules may remain visible. Do not delete routes with `ip route` on a live device—Android and the VPN service will recreate them, and connectivity may be interrupted.

### With root

On a rooted device, the backend must filter the data source rather than libc alone. In upstream VPNHide, the kernel backends are intended for `ioctl`, netlink, and some route/procfs vectors; Zygisk remains a conditional fallback. Do not install kmod and KPM together, because they may intercept the same kernel functions. VPNHide Next claims broader PMTU/MSS/qdisc/BPF coverage, but this is an external claim that must be reproduced on the specific kernel.

### How to verify the result

```bash
adb shell cat /proc/net/route 2>&1
adb shell ip -4 route show table all
```
The destination in procfs is represented as little-endian hexadecimal.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Deleting split routes may send private-network traffic to the wrong path or cut off access entirely.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified from the destination conditions and fixed VPN names; legacy high confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- External primary documentation or official project: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `vpn-policy-rules-netlink`, `route-vpn-interface`, `route-table`.

[Back to the Native signs reference](../)
