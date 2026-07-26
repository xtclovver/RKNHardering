---
title: "Loopback UDP flood: 50,000 packets of 1,400 bytes"
permalink: /help/en/native/backpressure/
---

# Loopback UDP flood: 50,000 packets of 1,400 bytes

> **ID:** `BACKPRESSURE`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The cancellation-aware probe attempts to send up to 50,000 datagrams of 1,400 bytes each to `127.0.0.1:53` with `MSG_DONTWAIT`. It stops at the first error and reports sent/total, elapsed time, and estimated MB/s. The result is informational.

### Exact trigger condition

If the scan has not been cancelled and the socket was created, the line is normally emitted for any number of successful send calls; there is no threshold.

## What the result means

It shows the local throughput of the send path and the point at which backpressure occurs. It does not confirm delivery and does not measure Internet or VPN throughput.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

Loopback behavior, socket buffers, CPU load, scheduling, and packet discard all affect the result. A 70 MB user payload creates a noticeable short-lived load. If the operation is cancelled, the line may be absent.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not “fix” anything at first. Record a baseline on the same device without a VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Do not run many repetitions back-to-back on a low-powered or hot device. Three to five series after the device has cooled are sufficient.

### With root

A root module can change this metric, but tuning for a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter a number of indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback path. Do not increase global socket buffers or disable the firewall merely to produce an attractive number. Any changes should be part of a separate benchmark, not anti-detection.

### How to verify the result

```bash
adb shell dumpsys thermalservice | head -80
adb shell 'cat /proc/net/softnet_stat 2>/dev/null | head'
```
Compare sent/time values between equivalent states, but do not establish a supposed “normal” threshold.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Repeated flooding loads the CPU, battery, and local network stack. On some devices it may cause temporary lag or watchdog pressure.

### Rollback

Stop the scan, force-stop the app, and let the device cool down. The probe does not change any persistent setting.

## Evidence level

**Low.** Verified against the 50k × 1,400-byte loopback loop, cancellation checks, and informational mapping.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- External primary documentation or official project: [sendto(2)](https://man7.org/linux/man-pages/man2/sendto.2.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `timing-oracle`, `udp-pmtu-ok`, `gso-ok`.

[Back to the Native signs reference](../)
