---
title: "Loopback UDP Send with TTL=1 Returned EACCES"
permalink: /help/en/native/traceroute-denied/
---

# Loopback UDP Send with TTL=1 Returned EACCES

> **ID:** `TRACEROUTE_DENIED`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe creates a normal UDP socket, sets `IP_TTL=1` and a 100 ms send timeout, then sends 64 bytes to `127.0.0.1:33434`. The line appears only when `sendto()` returns -1 specifically with `EACCES`. It does not measure an ICMP reply, a hop, or an external traceroute.

### Exact trigger condition

`EACCES` from a local UDP `sendto()` after setting TTL to 1.

## What the result means

This indicates a policy or firewall denial on the specific socket path. It does not prove VPN encapsulation. The checker sets a medium-confidence review finding.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The name “traceroute” is approximate: the destination is loopback, no raw socket is used, and no hop discovery occurs. `EPERM`, `ENETUNREACH`, and other errno values are not reported at all.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Disable third-party local firewall, DNS, and VPN components for a control run and record whether `EACCES` disappears. Do not try to enable external traceroute; the check is local.

### With root

Inspect UID-specific iptables/nftables rules and AVC messages. Do not flush the ruleset; identify the exact rule applied to loopback UDP/33434 or TTL-marked traffic.

### How to verify the result

```bash
adb logcat -d | grep -E 'avc: denied|33434|traceroute' | tail -80
adb shell su -c 'iptables-save | grep -E "33434|owner|uid|lo"; ip6tables-save | grep -E "33434|owner|uid|lo"'
```
A shell packet may pass even when the app UID is blocked.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Flushing the firewall globally may expose traffic, disable a kill switch, and weaken security. Change only a confirmed UID-specific rule.

### Rollback

Restore the saved ruleset or module and restart the firewall and VPN. Verify DNS and the kill switch.

## Evidence level

**Medium.** Verified from the loopback destination, TTL=1, and the single `EACCES` branch; medium by default.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [ip(7) IP_TTL](https://man7.org/linux/man-pages/man7/ip.7.html).
- External primary documentation or official project: [sendto(2)](https://man7.org/linux/man-pages/man2/sendto.2.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `udp-pmtu-fail`, `syscall-unavailable`, `inet-diag-denied`.

[Back to the Native signs reference](../)
