---
title: "MTU of the First Non-Tunnel Interface"
permalink: /help/en/native/normal-pmtu/
---

# MTU of the First Non-Tunnel Interface

> **ID:** `NORMAL_PMTU`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe iterates over `getifaddrs()` and selects the first entry whose name is not `lo` and does not contain the substrings `tun`, `wg`, or `ppp`. It obtains the MTU through `fetchMtu()` and reports the interface name and value. `xfrm`, `utun`, and `tailscale` are not excluded here. The line is informational.

### Exact trigger condition

The first matching interface with an MTU greater than 0 is found; there is no threshold.

## What the result means

This provides a reference point for the physical path MTU when comparing other indicators. A value of 1500, 1400, 1350, or similar does not prove the presence of a VPN by itself.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

The order returned by `getifaddrs()` does not guarantee that the selected interface carries the primary default route; one interface may also have several address records. The substring filter is incomplete and may select a VPN-like interface. There is no correlation with the route destination.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not try to “fix” anything at first. Record a baseline on the same device without the VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between the two series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Compare the interface name with the default route. Do not change the MTU merely to obtain a “typical” value of 1500: mobile and overlay networks legitimately use other values.

### With root

A root module can alter this indicator, but tuning it to a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter several indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback procedure. Any MTU substitution must remain consistent across ioctl, sysfs, netlink, TCP MSS, and actual forwarding. An inconsistent value creates additional signals and packet loss.

### How to verify the result

```bash
adb shell ip route get 1.1.1.1
adb shell 'for i in /sys/class/net/*; do echo -n "${i##*/} "; cat "$i/mtu" 2>/dev/null; done'
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

An MTU that is too high can cause black-hole routing or fragmentation; one that is too low reduces performance. Do not apply a global change without testing ICMP, QUIC, and TCP.

### Rollback

Restore the original MTU in the VPN or interface configuration, or restart NetworkStack and the VPN. Record the original value before changing it.

## Evidence level

**Low.** Verified from the first-match algorithm and the absence of thresholds; informational.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [netdevice(7) MTU](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- External primary documentation or official project: [Path MTU Discovery](https://docs.kernel.org/networking/ip-sysctl.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `pmtu-mss-combined`, `udp-pmtu-ok`, `tuntap-type`.

[Back to the Native signs reference](../)
