---
title: "Legacy tun0/wg0 Traffic Counters Under the qdisc Name"
permalink: /help/en/native/vpn-qdisc/
---

# Legacy tun0/wg0 Traffic Counters Under the qdisc Name

> **ID:** `VPN_QDISC`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

Despite its name, `detectQdisc()` does not query qdisc state. It reads `/proc/net/dev`, parses RX/TX bytes and packets, and emits `vpn_qdisc` only for the exact names `tun0` and `wg0`. The legacy policy treats the row as a medium-confidence review finding.

### Exact trigger condition

`tun0` or `wg0` is present in `/proc/net/dev`; the traffic counters may be zero.

## What the result means

This is another procfs interface leak, not packet-scheduler analysis. The current deep pipeline effectively has no separate producer for actual qdisc state.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The name is historical and potentially misleading. Only two names are checked, and only when procfs is accessible.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

The most reliable non-root approach is not to create a VPN interface on the phone being tested: move the tunnel to a router, travel router, separate gateway phone, or another network node. Per-app bypass in `VpnService` changes the route used by the selected app, but `establish()` still creates a system VPN interface, so local interface checks may continue to trigger. A local HTTP/SOCKS proxy mode without TUN can sometimes remove this specific vector, but it leaves listening ports and proxy settings and does not cover apps that ignore the proxy.

### With root

Laboratory-grade hiding usually requires both a system Java layer and one native backend. With VPNHide, that means the APK plus Vector/LSPosed scoped only to `System Framework`, and exactly one of kmod, KPM, or Zygisk. For a check that may use a direct syscall or netlink, kmod or KPM is preferable: a userspace Zygisk hook can be bypassed and leaves traces inside the process. Review the [VPNHide coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md) first, and download builds only from the [official release page](https://github.com/okhsunrog/vpnhide/releases/latest). VPNHide Next claims broader coverage, but it also warns about possible boot loops and kernel panics; test it only on a dedicated device. Filtering `/proc/net/dev` is required separately from netlink. Upstream VPNHide does not claim complete coverage of this file through its kernel backend; VPNHide Next claims an expanded proc/qdisc layer.

### How to verify the result

```bash
adb shell cat /proc/net/dev 2>&1 | grep -E '(^|:)[[:space:]]*(tun0|wg0):'
adb shell tc qdisc show 2>/dev/null
```
The second command illustrates that actual qdisc state is a different surface.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Do not zero real counters or change qdisc settings unnecessarily; doing so affects QoS and latency.

### Rollback

Revert the most recent change: disable the added module or rule through its normal manager, reboot the device, and repeat the baseline scan. Do not layer another hook on top of an unknown state.

## Evidence level

**Medium.** Verified from the `/proc/net/dev` parser; this documentation explicitly corrects the historical name.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- External primary documentation or official project: [Linux traffic control](https://man7.org/linux/man-pages/man8/tc.8.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `proc-net-dev-vpn`, `deep-vpn-qdisc`.

[Back to the Native signs reference](../)
