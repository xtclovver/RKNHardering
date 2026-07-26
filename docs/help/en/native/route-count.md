---
title: "Informational Route and Interface Count"
permalink: /help/en/native/route-count/
---

# Informational Route and Interface Count

> **ID:** `ROUTE_COUNT`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectRouteCount()` calls the shared `netlinkRouteDump(0)`, counts rows with the `route|` prefix, and counts unique values after `|dev=`. It always emits `route_count|total=N interfaces=M`, even when N is 0. The checker marks the kind as low-confidence informational data.

### Exact trigger condition

The line is produced whenever the function completes; it is telemetry, not an anomaly threshold.

## What the result means

The numbers provide a baseline and help identify abrupt changes after enabling a VPN or module. There is no universal normal route count, and the value does not affect `detected`.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

The snapshot depends on Wi-Fi or mobile data, IPv4 and IPv6, the OEM, tethering, profiles, and the time of execution. The function counts only rows successfully produced by its internal parser; a netlink error may appear as a zero.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not try to “fix” anything at first. Record a baseline on the same device without the VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between the two series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Capture at least three to five runs without the VPN and with the VPN on the same network. Do not delete routes merely to make the count match.

### With root

A root module can alter this indicator, but tuning it to a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter several indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback procedure. If a filter changes the count, it must remain consistent with `RTM_GETLINK`, `getifaddrs()`, and actual route lookups; the goal is not a fixed N.

### How to verify the result

```bash
adb shell 'ip -4 route show table all; ip -6 route show table all'
adb shell 'ip -o link show | wc -l'
```
Compare the trend rather than expecting exact equality between shell and app snapshots.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Manually deleting routes can immediately interrupt network ADB, DNS, mobile connectivity, and the VPN.

### Rollback

Do not change routing for an informational line. If you already changed it, disable the experimental module and restart the network or device.

## Evidence level

**Low.** Verified from the unconditional result and `INFORMATIONAL_KINDS`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- External primary documentation or official project: [ip-route(8)](https://man7.org/linux/man-pages/man8/ip-route.8.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `route-table`, `vpn-policy-rules-netlink`, `trim-oracle`.

[Back to the Native signs reference](../)
