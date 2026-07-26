---
title: "VPN Interface in /proc/net/if_inet6"
permalink: /help/en/native/proc-if-inet6-vpn/
---

# VPN Interface in /proc/net/if_inet6

> **ID:** `PROC_IF_INET6_VPN`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe checks `/proc/net/if_inet6` and `/proc/self/net/if_inet6`. Each line is split into six tokens, with the sixth token treated as the interface name. It counts `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, and `xfrm0`; the function stops after the first accessible file that contains matches.

### Exact trigger condition

One or more rows with a fixed VPN interface name are found in the IPv6 interface table.

## What the result means

A VPN-like network device has an IPv6 address and is visible through procfs. This is a direct artifact even when the primary traffic is IPv4.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

An interface without an IPv6 address does not appear here. Access to procfs depends on the Android version and SELinux policy. The name list is narrow, while multiple addresses on one interface increase the count.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy. Disabling IPv6 inside the VPN may remove this particular line, but it degrades connectivity and does not hide the interface through IPv4 or netlink. It is not a complete bypass.

### With root

Laboratory-grade hiding usually requires both a system Java layer and one native backend. With VPNHide, that means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod or KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but it also warns about possible boot loops and kernel panics; test it only on a dedicated device. At the time of its documentation, upstream VPNHide listed `/proc/net/if_inet6` as a Zygisk-only gap for kernel backends. Check the current release and the specific backend rather than relying on the module name.

### How to verify the result

```bash
adb shell 'cat /proc/net/if_inet6 2>/dev/null || cat /proc/self/net/if_inet6 2>/dev/null'
adb shell 'ip -6 addr show'
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Disabling IPv6 globally breaks IPv6-only and NAT64 networks, DNS64, and some mobile connectivity. Do not use it as the first step.

### Rollback

Restore the VPN and system IPv6 settings, remove the targeted filter, and reboot. Test mobile data and Wi-Fi separately.

## Evidence level

**High.** Verified from both paths, parser token `[5]`, and the six-name list; high kind.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/net documentation](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- External primary documentation or official project: [VPNHide coverage gaps](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `proc-ipv6-route-vpn`, `getifaddrs-vpn`, `sysfs-vpn-leak`.

[Back to the Native signs reference](../)
