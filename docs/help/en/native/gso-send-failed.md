---
title: "`UDP_SEGMENT` was accepted, but sending 4,800 bytes failed"
permalink: /help/en/native/gso-send-failed/
---

# `UDP_SEGMENT` was accepted, but sending 4,800 bytes failed

> **ID:** `GSO_SEND_FAILED`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

After successfully setting `UDP_SEGMENT=1200`, the probe sends a 4,800-byte datagram to `127.0.0.1:53`. If sendto returns -1, it emits `gso_send_failed|errno=N`. The checker displays the line as low-confidence informational data.

### Exact trigger condition

The GSO socket option was accepted, but sending the large buffer over loopback failed.

## What the result means

This diagnoses a specific send path. The failure may be related to offload support, socket buffers, policy, or a kernel bug; it does not prove the presence of a VPN.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

The check does not analyze the errno or actual segmentation. Loopback is not equivalent to a physical or tunnel device. No receiver is required, and delivery is not verified.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not “fix” anything at first. Record a baseline on the same device without a VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Repeat the test after a reboot with the firewall and VPN disabled, and record the errno. Do not lower the MTU by guesswork.

### With root

A root module can change this metric, but tuning for a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter a number of indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback path. Check kernel logs and vendor support. Do not replace only the sendto return value; that creates a false success and may hide a genuine application error.

### How to verify the result

```bash
adb shell dmesg 2>/dev/null | grep -Ei 'udp|gso|segmentation|skb' | tail -80
adb shell uname -r
```

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Kernel or network-sysctl experiments can degrade UDP/QUIC and DNS. Do not apply them globally on a primary device.

### Rollback

Restore sysctl, kernel, and module settings to the baseline, reboot, and repeat the DNS/QUIC tests.

## Evidence level

**Low.** Verified against the successful-setsockopt/failed-send branch; informational.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- External primary documentation or official project: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `gso-failed`, `gso-ok`, `udp-pmtu-fail`.

[Back to the Native signs reference](../)
