---
title: "VPN Interface Counters in /proc/net/dev"
permalink: /help/en/native/proc-net-dev-vpn/
---

# VPN Interface Counters in /proc/net/dev

> **ID:** `PROC_NET_DEV_VPN`
> **Category:** Interfaces
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe checks `/proc/net/dev` and `/proc/self/net/dev`. After the two header lines, the parser extracts the interface name before the colon and looks for the exact names `tun0`, `tun1`, `utun0`, `wg0`, `ppp0`, and `xfrm0`. RX and TX byte counts are reported for the first match.

### Exact trigger condition

The procfs device statistics contain a row for one of the six VPN interfaces; nonzero traffic is not required.

## What the result means

The network interface remains visible in global statistics. Zero-valued counters still confirm that the object exists, while nonzero counters help correlate it with activity.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

SELinux blocks this read on some Android versions. Only exact names are checked. The probe returns the first match and does not analyze packet, error, or drop counters.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy. Clearing statistics does not remove the row and is unnecessary. An external gateway eliminates the local network device itself.

### With root

Laboratory-grade hiding usually requires both a system Java layer and one native backend. With VPNHide, that means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod or KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but it also warns about possible boot loops and kernel panics; test it only on a dedicated device. This path requires a seq-file or procfs filter. Upstream VPNHide does not claim `/proc/net/dev` coverage for its stable kernel backends in its matrix; VPNHide Next claims it at the highest level, with the same kernel risks.

### How to verify the result

```bash
adb shell 'cat /proc/net/dev 2>/dev/null || cat /proc/self/net/dev 2>/dev/null'
adb shell ip -s link show
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Zeroing global counters breaks system traffic accounting and may affect Data Saver, usage statistics, and firewall policy.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**High.** Verified from the proc parser and the `HIGH_CONFIDENCE` mapping.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- External primary documentation or official project: [VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- External primary documentation or official project: [VPNHide Next](https://github.com/soranerai/vpnhide_next).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `vpn-qdisc`, `deep-vpn-qdisc`, `bpf-map-accessible`, `sysclassnet-vpn`.

[Back to the Native signs reference](../)
