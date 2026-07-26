---
title: "VPN Interface in /proc/net/ipv6_route"
permalink: /help/en/native/proc-ipv6-route-vpn/
---

# VPN Interface in /proc/net/ipv6_route

> **ID:** `PROC_IPV6_ROUTE_VPN`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe reads `/proc/net/ipv6_route` and then `/proc/self/net/ipv6_route`. Each line is split into ten tokens, with the tenth token treated as the interface name. Matches for `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, and `xfrm0` increase the count.

### Exact trigger condition

At least one IPv6 route row uses a fixed VPN interface name.

## What the result means

The IPv6 routing table directly references a VPN-like interface. Disabling IPv4 does not close this path.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The procfs format is kernel-specific and may be blocked by SELinux. The probe reports only a count, not the destination, prefix, or table, so analysis requires a raw snapshot. Nonstandard interface names are not detected.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Without root, address the routing design rather than the way the table is displayed. Use an external gateway for a clean phone. If the VPN remains in `VpnService`, configure split routing so that the app under test actually exits through the expected physical network, but do not treat this as hiding local routes: the interface and policy rules may remain visible. Do not delete routes with `ip route` on a live device—Android and the VPN service will recreate them, and connectivity may be interrupted. Disabling IPv6 in the profile reduces the exposed surface, but it may allow IPv6 traffic to bypass the VPN or eliminate IPv6 connectivity entirely. Test this first on a separate network.

### With root

On a rooted device, the backend must filter the data source rather than libc alone. In upstream VPNHide, the kernel backends are intended for `ioctl`, netlink, and some route/procfs vectors; Zygisk remains a conditional fallback. Do not install kmod and KPM together, because they may intercept the same kernel functions. VPNHide Next claims broader PMTU/MSS/qdisc/BPF coverage, but this is an external claim that must be reproduced on the specific kernel. The filter must cover procfs and IPv6 `RTM_GETROUTE` consistently. Substituting only `/proc/net/ipv6_route` leaves the netlink dump exposed.

### How to verify the result

```bash
adb shell 'cat /proc/net/ipv6_route 2>/dev/null || cat /proc/self/net/ipv6_route 2>/dev/null'
adb shell ip -6 route show table all
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Manually deleting IPv6 routes can break DNS or NAT64 and will not survive VPN recreation. A faulty kernel seq-file hook can corrupt procfs reads.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified from both proc paths, token `[9]`, and the six-name list; high kind.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- External primary documentation or official project: [rtnetlink routes](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `route-table`, `rtm-getlink-vpn`, `proc-if-inet6-vpn`.

[Back to the Native signs reference](../)
