---
title: "VPN Interface Accessible Through sysfs and proc/sys"
permalink: /help/en/native/sysfs-vpn-leak/
---

# VPN Interface Accessible Through sysfs and proc/sys

> **ID:** `SYSFS_VPN_LEAK`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectSysfsLeak()` does not enumerate entire directories; it calls `stat()` for the fixed names `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, and `xfrm0`. It checks `/sys/class/net`, `/sys/devices/virtual/net`, and the `/proc/sys/net/{ipv4,ipv6}/{conf,neigh}` branches. Every existing path is combined into one `sysfs_vpn_leak` line.

### Exact trigger condition

At least one of the 36 fixed paths exists and is accessible to `stat()` from the app process.

## What the result means

This directly confirms that a kernel object with a typical VPN name remains visible through the network filesystem view. The line has high confidence, but it confirms the interface name rather than proving that RKNHardering traffic necessarily uses that interface.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The name list is intentionally narrow. A renamed interface may be missed here but detected by the main matcher, type 65534, netlink, the ifindex oracle, or route checks. On stock Android with SELinux enforcing, some paths may be inaccessible; the absence of the line then means only that this path did not provide access.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy. Clearing caches, using Private Space, or configuring per-app bypass does not remove `/sys/class/net/<iface>` from the shared kernel namespace. An external gateway is the only non-root option that genuinely avoids creating this object on the phone.

### With root

Laboratory-grade hiding usually requires both a system Java layer and one native backend. With VPNHide, that means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod or KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but it also warns about possible boot loops and kernel panics; test it only on a dedicated device. For this vector, the backend must filter lookup, `stat()`, and `readdir()` operations, or hide the network device itself consistently. Upstream VPNHide documents `/sys/class/net` as a gap that SELinux usually masks; VPNHide Next claims filesystem-level hiding at its highest level, but that must be verified on the specific ROM.

### How to verify the result

```bash
adb shell 'for b in /sys/class/net /sys/devices/virtual/net /proc/sys/net/ipv4/conf /proc/sys/net/ipv6/conf /proc/sys/net/ipv4/neigh /proc/sys/net/ipv6/neigh; do for n in tun0 tun1 utun0 wg0 ppp0 xfrm0; do [ -e "$b/$n" ] && echo "$b/$n"; done; done'
```
The command runs under the shell UID. To evaluate the target UID, rely on the RKNHardering detail; after a change, force-stop and relaunch the app.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Globally hiding `/sys` or `/proc/sys/net` breaks diagnostics and may affect system services. A faulty kernel hook can cause a boot loop or kernel panic.

### Rollback

Disable the module from recovery or safe mode, restore the original boot image, and reboot. Do not leave SELinux in permissive mode as a “workaround.”

## Evidence level

**High.** Verified from the six names, two sysfs bases, and four proc/sys bases in `detectSysfsLeak()`; the kind is included in `HIGH_CONFIDENCE`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- External primary documentation or official project: [Linux sysfs networking ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net).
- External primary documentation or official project: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- External primary documentation or official project: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `sysclassnet-vpn`, `getifaddrs-vpn`, `tuntap-type`, `ifindexname-vpn`.

[Back to the Native signs reference](../)
