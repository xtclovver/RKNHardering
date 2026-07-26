---
title: "ARM64 socket/sendto Timing via CNTVCT_EL0"
permalink: /help/en/native/timing-oracle/
---

# ARM64 socket/sendto Timing via CNTVCT_EL0

> **ID:** `TIMING_ORACLE`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

On arm64, the probe performs 10 iterations: read the cycle counter, create a UDP socket, send 64 bytes to `127.0.0.1:53`, close the socket, and read the counter again. It reports minimum, maximum, and average cycle counts. On another ABI, it reports `not_arm64`. Both variants are low-confidence informational data.

### Exact trigger condition

A line is always produced when the function runs: numeric values on arm64 or `not_arm64` otherwise. There is no “VPN detected” threshold.

## What the result means

This is raw performance telemetry. Without a baseline, statistical analysis, and CPU-frequency control, the values are not interpretable. In the current version, timing does not affect `detected` or review status.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

Ten measurements are too few; scheduler behavior, DVFS, thermal throttling, emulation, background load, and timer frequency have a larger effect than a VPN. The loopback send does not traverse the VPN data path. The result is not normalized by `cntfrq`.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not try to “fix” anything at first. Record a baseline on the same device without the VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between the two series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Before each series, stop background load, stabilize the device temperature, and collect at least 20 runs. Compare distributions rather than one average.

### With root

A root module can alter this indicator, but tuning it to a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter several indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback procedure. Do not substitute `CNTVCT` or scheduler behavior for the sake of this documentation; that would affect cryptography, timers, and anti-tamper logic. Use Perfetto or Simpleperf in a dedicated build for benchmarking.

### How to verify the result

```bash
adb shell getprop ro.product.cpu.abi
adb shell dumpsys thermalservice | head -80
adb shell top -b -n 1 | head -30
```
Use values from several RKNHardering reports collected under identical conditions.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Pinning the CPU frequency or governor requires root, increases heat, and may damage the battery during prolonged testing. Do not leave performance mode enabled continuously.

### Rollback

Restore the default governor and thermal settings and reboot. An informational signal requires no bypass.

## Evidence level

**Low.** Verified from the 10 iterations, `CNTVCT_EL0`, and `INFORMATIONAL_KINDS`.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Arm generic timer documentation](https://developer.arm.com/documentation/102379/latest/).
- External primary documentation or official project: [Perfetto](https://perfetto.dev/docs/).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `backpressure`, `gso-ok`, `general-diagnostics`.

[Back to the Native signs reference](../)
