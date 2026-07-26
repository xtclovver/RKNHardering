---
title: "`SIOCSHWTSTAMP` was successfully configured on loopback"
permalink: /help/en/native/hardware-timestamp/
---

# `SIOCSHWTSTAMP` was successfully configured on loopback

> **ID:** `HW_TIMESTAMP`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe calls `ioctl(SIOCSHWTSTAMP)` for interface `lo` with `HWTSTAMP_TX_ON`. Only rc=0 emits `hw_timestamp|lo configured`. It separately attempts to enable software `SO_TIMESTAMPING`, but does not report that result. The finding is low-confidence informational data.

### Exact trigger condition

The kernel allowed `SIOCSHWTSTAMP` on loopback for an ordinary app socket.

## What the result means

This reflects driver and kernel permissions, not a VPN. On many systems, loopback does not support hardware timestamping or the operation requires privileges, so an absent line is expected.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

The probe does not read the negotiated configuration, obtain a timestamp, or test a tunnel or physical interface. Success may be specific to the vendor kernel or a hook.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not “fix” anything at first. Record a baseline on the same device without a VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between series is useful for analysis. A single MTU, timing, or GSO value is not evidence. No changes are required. Compare against a clean device running the same firmware.

### With root

A root module can change this metric, but tuning for a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter a number of indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback path. Do not grant `CAP_NET_ADMIN` to the app. For a valid timestamp benchmark, use a separate privileged test tool on a test device.

### How to verify the result

```bash
adb shell uname -r
adb shell 'ethtool -T lo 2>/dev/null || true'
```
`ethtool` may be unavailable; the native probe itself reports the exact `SIOCSHWTSTAMP` result.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Changing timestamping drivers or permissions may affect PTP, logging, and network performance. This informational signal does not require a bypass.

### Rollback

Remove the test capability or sepolicy rule and reboot. Restore the stock kernel if it was replaced.

## Evidence level

**Low.** Verified against `SIOCSHWTSTAMP` rc==0 and the informational mapping.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Linux timestamping](https://docs.kernel.org/networking/timestamping.html).
- External primary documentation or official project: [netdevice(7)](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `timing-oracle`, `gso-ok`, `normal-pmtu`.

[Back to the Native signs reference](../)
