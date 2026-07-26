---
title: "Fixed VPN Interfaces in /sys/class/net"
permalink: /help/en/native/sysclassnet-vpn/
---

# Fixed VPN Interfaces in /sys/class/net

> **ID:** `SYSCLASSNET_VPN`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectSysclassnetVpn()` calls `stat()` only for `/sys/class/net/{tun0,tun1,utun0,wg0,ppp0,xfrm0}` and lists the names it finds. This is a narrower duplicate of part of `sysfs-vpn-leak`, retained as a separate diagnostic ID.

### Exact trigger condition

At least one of the six fixed `/sys/class/net/<name>` directories exists.

## What the result means

Kernel sysfs exposes a network device with a typical VPN name. A match is treated as a high-confidence local artifact.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The check does not inspect `type`, `mtu`, or `operstate`, and does not cover nonstandard names. SELinux may block traversal, in which case the line is absent even when the interface exists. Conversely, a disabled but not deleted network device still triggers the check.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy.

### With root

Laboratory-grade hiding usually requires both a system Java layer and one native backend. With VPNHide, that means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod or KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but it also warns about possible boot loops and kernel panics; test it only on a dedicated device. Verify that the solution covers not only `readdir()` but also a direct `stat("/sys/class/net/tun0")`; otherwise this exact-path probe bypasses a filtered directory listing.

### How to verify the result

```bash
adb shell 'for n in tun0 tun1 utun0 wg0 ppp0 xfrm0; do [ -e /sys/class/net/$n ] && { echo "[$n]"; cat /sys/class/net/$n/type /sys/class/net/$n/mtu /sys/class/net/$n/operstate 2>/dev/null; }; done'
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Broad sysfs substitution may disrupt NetworkStack, netd, and OEM services. Do not change ownership or permissions of sysfs files; the kernel creates them.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified from the exact `stat()` calls and the `HIGH_CONFIDENCE` mapping.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [sysfs class net ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net).
- External primary documentation or official project: [AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `sysfs-vpn-leak`, `tuntap-type`, `proc-net-dev-vpn`.

[Back to the Native signs reference](../)
