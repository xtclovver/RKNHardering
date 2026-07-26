---
title: "VPN-like name returned by `if_indextoname()`"
permalink: /help/en/native/ifindexname-vpn/
---

# VPN-like name returned by `if_indextoname()`

> **ID:** `IFINDEXNAME_VPN`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectIfindexnameVpn()` iterates over ifindex values 1 through 127, calls `if_indextoname()`, and searches for the exact names `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, and `xfrm0`. The detail contains the name and index.

### Exact trigger condition

Reverse resolution of at least one index returns one of the fixed VPN-like names.

## What the result means

Even when the app cannot enumerate a directory or route dump, the kernel/libc resolves an index to a VPN-like name. This is strong evidence of incomplete hiding.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

Indices above 127 are not checked. The exact-name list is narrow. A userspace `if_indextoname()` hook can hide the line, but VPNHide’s regression oracle and the RTM dump test its consistency.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy.

### With root

Laboratory-grade hiding usually requires a system Java layer and one native backend. With VPNHide, this means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod/KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but also warns about possible boot loops and kernel panics; it should be tested only on a test device. Do not return a fabricated “clean” name only from `if_indextoname()`: a discrepancy between `SIOCGIFINDEX`/`SIOCGIFNAME` and `RTM_GETLINK` creates an oracle. The kernel backend must filter the data consistently.

### How to verify the result

```bash
adb shell 'for i in $(seq 1 127); do n=$(cat /sys/class/net/*/ifindex 2>/dev/null | grep -x "$i" -m1); [ -n "$n" ] && :; done'
adb shell ip -o link show
```
The exact API is best reproduced with a native harness using `if_indextoname()`; `ip` provides only a comparison snapshot.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Inconsistent index spoofing breaks bind-to-device behavior and route resolution, and may cause system-service failures.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified against the [1, 127] range and the exact-name list; the kind is high confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`vpnhide_regression_probe.cpp` — consistency and oracle probes](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/vpnhide_regression_probe.cpp).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [if_nametoindex(3)](https://man7.org/linux/man-pages/man3/if_nametoindex.3.html).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `vpnhide`, `trim-oracle`, `rtm-getlink-vpn`, `interface-enumeration`.

[Back to the Native signs reference](../)
