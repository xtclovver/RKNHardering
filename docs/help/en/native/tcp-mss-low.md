---
title: "Low TCP MSS on a Local Connection"
permalink: /help/en/native/tcp-mss-low/
---

# Low TCP MSS on a Local Connection

> **ID:** `TCP_MSS_LOW`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe attempts to connect to `127.0.0.1:443`. Only when a listener accepts the connection does it read `TCP_INFO` and emit `tcp_mss_low` if `tcpi_snd_mss > 0 && < 500`. The legacy policy treats this kind as high confidence. Without a local listener, the function exits silently.

### Exact trigger condition

A successful TCP connection to localhost:443 with a send MSS below 500.

## What the result means

In the current implementation, this is a rare and context-dependent signal. It depends more on the local listener and loopback stack than on the actual Internet PMTU.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The threshold of 500 is very low; a typical VPN MTU usually produces a much higher MSS. If port 443 is closed, the check does not run at all. Loopback `TCP_INFO` does not reflect the external tunnel path.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not try to “fix” anything at first. Record a baseline on the same device without the VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between the two series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Identify what is listening on localhost:443. If the listener is unnecessary, stop it; do not change the system MTU for this probe.

### With root

A root module can alter this indicator, but tuning it to a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter several indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback procedure. `TCP_INFO` can be substituted through a userspace or kernel hook, but upstream VPNHide does not claim coverage for this legacy loopback scenario; VPNHide Next claims `TCP_INFO` and MSS filtering.

### How to verify the result

```bash
adb shell ss -ltn 2>/dev/null | grep '127.0.0.1:443'
adb shell ip link show
```
An exact MSS measurement requires a test client running in the same app context.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Blindly lowering or raising the MTU can cause fragmentation, make some sites hang, and disrupt calls.

### Rollback

Restore the original MTU and MSS behavior, and stop only the test localhost listener.

## Evidence level

**High.** Verified from the connection target, `TCP_INFO`, and the `<500` threshold; the legacy kind is high confidence, but the probe is conditional.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `pmtu-mss-combined`, `normal-pmtu`, `loopback-port-conflict`.

[Back to the Native signs reference](../)
