---
title: "SO_BINDTODEVICE confirms that a VPN interface exists"
permalink: /help/en/native/bindtodevice-leak/
---

# SO_BINDTODEVICE confirms that a VPN interface exists

> **ID:** `BINDTODEVICE_LEAK`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

A UDP socket is created for each of `tun0`, `tun1`, `utun0`, `wg0`, and `ppp0`. The probe calls `setsockopt(SO_BINDTODEVICE, name)`, followed by `getsockopt(SO_BINDTODEVICE)`, and requires the returned string to contain the same name. `xfrm0` is not included in this list.

### Exact trigger condition

Both setting and reading `SO_BINDTODEVICE` succeed for one of the five fixed VPN-like names.

## What the result means

The kernel socket API accepts binding to a VPN-like network device, which means the interface actually exists and is accessible to the process. This is stronger evidence than a simple file check.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

On Linux, `SO_BINDTODEVICE` may be restricted by permissions or policy; failure does not prove that the interface is absent. The exact-name list is narrow. The probe sends no traffic and does not confirm that traffic is routed through the device.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy. Ordinary VPN settings cannot prevent the target app from calling `setsockopt`. A second profile shares the same kernel network stack.

### With root

Laboratory-grade hiding usually requires a system Java layer and one native backend. With VPNHide, this means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod/KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but also warns about possible boot loops and kernel panics; it should be tested only on a test device. The backend must return a consistent “interface not found” error for the target UID while also hiding the interface from getifaddrs, netlink, and ifindex-based checks. A userspace hook can be bypassed with a raw syscall.

### How to verify the result

```bash
adb shell su -c 'for n in tun0 tun1 utun0 wg0 ppp0; do ip link show dev "$n" 2>/dev/null && echo present:$n; done'
```
An exact test requires a native harness using `SO_BINDTODEVICE`; the command above uses root only for orientation and does not reproduce the app’s UID/SELinux context.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Blocking `SO_BINDTODEVICE` globally can break VPNs, DHCP, tethering, and system services. Any errno substitution must be scoped per UID.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified against the five-name loop, setsockopt/getsockopt confirmation, and the `HIGH_CONFIDENCE` set.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [socket(7) SO_BINDTODEVICE](https://man7.org/linux/man-pages/man7/socket.7.html).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `so-bindtodevice`, `getifaddrs-vpn`, `ifindexname-vpn`.

[Back to the Native signs reference](../)
