---
title: "`setsockopt()` did not accept `UDP_SEGMENT`"
permalink: /help/en/native/gso-failed/
---

# `setsockopt()` did not accept `UDP_SEGMENT`

> **ID:** `GSO_FAILED`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe creates a UDP socket and attempts `setsockopt(IPPROTO_UDP, UDP_SEGMENT, 1200)`. On failure, it emits `gso_failed` with the errno. The checker treats this as low-confidence informational data because lack of GSO is not considered a VPN indicator.

### Exact trigger condition

The kernel or libc returns an error while configuring `UDP_SEGMENT`.

## What the result means

It shows that UDP GSO is unavailable to this socket, kernel, or environment. This depends on kernel configuration and API support, not only on the VPN.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

The verdict logic does not distinguish `ENOPROTOOPT`, `EINVAL`, `EPERM`, or other causes. Android kernels and vendor backports vary. The physical-interface path is not tested.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not “fix” anything at first. Record a baseline on the same device without a VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Record the errno and kernel version. Do not change the VPN because a kernel feature is unavailable.

### With root

A root module can change this metric, but tuning for a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter a number of indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback path. Do not load an unknown kernel module merely for `UDP_SEGMENT`. Support requires a compatible kernel and network stack, not a Magisk property.

### How to verify the result

```bash
adb shell uname -a
adb shell zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_INET|CONFIG_UDP' | head -40
```
The exact errno is taken from the RKNHardering detail.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Replacing the kernel for GSO can cause a boot loop, module incompatibility, and data loss. This informational signal does not justify that risk.

### Rollback

Restore the stock boot/kernel image, remove the experimental module, and reboot.

## Evidence level

**Low.** Verified against the `UDP_SEGMENT=1200` failure branch; informational.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- External primary documentation or official project: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `gso-send-failed`, `gso-ok`, `normal-pmtu`.

[Back to the Native signs reference](../)
