---
title: "VPN Interface in Netlink RTM_GETLINK"
permalink: /help/en/native/rtm-getlink-vpn/
---

# VPN Interface in Netlink RTM_GETLINK

> **ID:** `RTM_GETLINK_VPN`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe opens `AF_NETLINK/NETLINK_ROUTE`, sends `RTM_GETLINK` with `NLM_F_DUMP`, and parses `RTM_NEWLINK` messages and the `IFLA_IFNAME` attribute. It searches for the exact names `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, and `xfrm0`; the receive loop uses `poll(..., 2000)` and `recv()`.

### Exact trigger condition

The complete link dump contains at least one `RTM_NEWLINK` message with a fixed VPN interface name.

## What the result means

This is one of the most important paths: an ordinary app obtains the network-device list directly from the kernel even when `/proc` or `/sys` is inaccessible. A match is a strong local indicator.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

Only six exact names are checked. The probe does not strictly validate multipart truncation or sequence/PID values; a send, poll, or receive failure silently produces no result. A userspace hook that covers only `getifaddrs()` does not close this path.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy. A secondary Android user does not receive a separate network namespace, so work and personal profiles normally see the same `RTM_GETLINK` dump.

### With root

Laboratory-grade hiding usually requires both a system Java layer and one native backend. With VPNHide, that means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod or KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but it also warns about possible boot loops and kernel panics; test it only on a dedicated device. Raw netlink requires a kernel-level filter or equivalent system isolation. Zygisk would need to intercept the specific family of receive calls and would still remain bypassable; upstream VPNHide explicitly documents this limitation.

### How to verify the result

```bash
adb shell ip -details link show
adb shell 'ip -o link | grep -E "tun0|tun1|utun0|wg0|ppp0|xfrm0"'
```
`ip` also uses rtnetlink, but the shell UID may receive a differently filtered view.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

A faulty skb/netlink filter may hang during a dump, corrupt a multipart reply, or break networking for system UIDs.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified from `RTM_GETLINK`, `RTM_NEWLINK`, `IFLA_IFNAME`, the six-name allowlist, and the `HIGH_CONFIDENCE` set.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- External primary documentation or official project: [netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `getifaddrs-vpn`, `trim-oracle`, `ifindexname-vpn`, `interface-enumeration`.

[Back to the Native signs reference](../)
