---
title: "Legacy ioctl check for fixed VPN interfaces"
permalink: /help/en/native/inet6-vpn-interface/
---

# Legacy ioctl check for fixed VPN interfaces

> **ID:** `INET6_VPN_INTERFACE`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectVpnInterfaces()` iterates over the exact names `tun0`, `tun1`, `utun0`, `utun1`, `wg0`, `wg1`, `ppp0`, and `xfrm0`. Both `ifaceExists()` and a second `SIOCGIFFLAGS` call must succeed; the detail includes the name and flags. The kind is legacy high confidence.

### Exact trigger condition

A fixed name exists and is accessible through the `SIOCGIFFLAGS` socket ioctl.

## What the result means

This is a strong but narrow name-based signal. Despite the historical `inet6` name, the check is not limited to IPv6 and does not read an address; it performs an `AF_INET` ioctl for flags.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

A renamed or nonstandard interface is not in the list; the main pattern, type, or netlink checks may still find it. The page title does not fully match the implementation.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy.

### With root

Laboratory-grade hiding usually requires a system Java layer and one native backend. With VPNHide, this means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod/KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but also warns about possible boot loops and kernel panics; it should be tested only on a test device. The backend must intercept `SIOCGIFFLAGS`, not only `getifaddrs`.

### How to verify the result

```bash
for i in tun0 tun1 utun0 utun1 wg0 wg1 ppp0 xfrm0; do adb shell ip link show "$i" 2>/dev/null; done
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

An inconsistent ioctl error can create a JVM/native mismatch and an ifindex oracle.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified against the exact `tunNames` list and the two `SIOCGIFFLAGS` calls; the kind is high confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [netdevice ioctls](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- External primary documentation or official project: [VPNHide ioctl coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `interface-enumeration`, `ifindexname-vpn`, `getifaddrs-vpn`.

[Back to the Native signs reference](../)
