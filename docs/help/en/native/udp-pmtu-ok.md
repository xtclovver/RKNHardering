---
title: "Successfully Sent 1500 Bytes over UDP to 127.0.0.1:53"
permalink: /help/en/native/udp-pmtu-ok/
---

# Successfully Sent 1500 Bytes over UDP to 127.0.0.1:53

> **ID:** `UDP_PMTU_OK`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe creates a UDP socket and performs one `sendto()` call with a 1500-byte buffer to loopback DNS port 53. If the return value is greater than 0, it emits `udp_pmtu_ok`; no receiver or listener is required. The line is low-confidence informational data.

### Exact trigger condition

The kernel accepted a local 1500-byte UDP datagram on the send path.

## What the result means

Success shows only that the loopback send path accepted the datagram. It does not measure the external route PMTU, fragmentation, or delivery to a DNS service.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

The loopback MTU is normally far higher than the physical MTU. A successful UDP send does not confirm delivery. The PMTU label overstates the informational value.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not try to “fix” anything at first. Record a baseline on the same device without the VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between the two series is useful for analysis. A single MTU, timing, or GSO value is not evidence.

### With root

A root module can alter this indicator, but tuning it to a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter several indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback procedure. Do not block loopback UDP/53 merely to change the result: that creates `udp-pmtu-fail` and may disrupt local DNS.

### How to verify the result

```bash
adb shell ip link show lo
adb shell 'cat /sys/class/net/lo/mtu 2>/dev/null'
```
On a normal kernel, expect the send to succeed regardless of whether a listener exists.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Firewall or SELinux experiments involving loopback DNS may break name resolution for apps.

### Rollback

Remove the temporary loopback or firewall rule and restart netd, the VPN, or the device.

## Evidence level

**Low.** Verified from the fixed 1500-byte loopback send; informational.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- External primary documentation or official project: [ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `udp-pmtu-fail`, `normal-pmtu`, `backpressure`.

[Back to the Native signs reference](../)
