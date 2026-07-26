---
title: "Sending a 1500-Byte UDP Datagram to Loopback Failed"
permalink: /help/en/native/udp-pmtu-fail/
---

# Sending a 1500-Byte UDP Datagram to Loopback Failed

> **ID:** `UDP_PMTU_FAIL`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

This is the alternative branch of the same probe: `sendto(127.0.0.1:53, 1500)` returned -1, and the detail contains the errno value. Unlike `udp-pmtu-ok`, this kind is not included in the informational set, so the current checker sets a medium-confidence `needsReview` finding.

### Exact trigger condition

Any `sendto()` error, regardless of errno.

## What the result means

The error is unusual on loopback but does not prove the presence of a VPN. Possible causes include an SELinux or firewall hook, a resource limit, an invalid socket state, a cancellation race, or a modified network stack.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The code does not classify errno values and does not set `IP_MTU_DISCOVER`. Therefore, `EMSGSIZE` cannot automatically be interpreted as a PMTU result, while `EACCES` and `ENOBUFS` have entirely different meanings.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Record the exact errno, reboot the device, and repeat the test without the VPN, firewall, or DNS-filtering app. Do not lower the MTU merely to make the error disappear.

### With root

Inspect `dmesg` and AVC messages, iptables/nftables, and socket-hook modules. Remove only a rule that demonstrably blocks loopback. Do not grant capabilities to the app.

### How to verify the result

```bash
adb logcat -d | grep -E 'avc: denied|udp_pmtu|sendto' | tail -80
adb shell iptables-save 2>/dev/null | grep -E 'lo|127[.]0[.]0[.]1|dport 53'
adb shell ip6tables-save 2>/dev/null | grep -E 'lo|::1|dport 53'
```
Use the RKNHardering detail for the errno value; a shell send uses a different UID.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Resetting all firewall rules is destructive: it may disable the VPN kill switch and system protections. Do not flush the ruleset globally.

### Rollback

Restore the saved rules or disable the responsible module through its manager; reboot and verify DNS resolution.

## Evidence level

**Medium.** Verified from the catch-all failure branch and the default medium-confidence evaluation.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [sendto(2)](https://man7.org/linux/man-pages/man2/sendto.2.html).
- External primary documentation or official project: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `udp-pmtu-ok`, `traceroute-denied`, `syscall-unavailable`.

[Back to the Native signs reference](../)
