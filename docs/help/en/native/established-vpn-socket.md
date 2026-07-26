---
title: "Established TCP connection to a typical VPN port"
permalink: /help/en/native/established-vpn-socket/
---

# Established TCP connection to a typical VPN port

> **ID:** `ESTABLISHED_VPN_SOCKET`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Medium

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

`detectEstablishedVpn()` reads `/proc/net/tcp` and selects state `01` (ESTABLISHED) with a remote port of 51820, 1194, 1195, 443, or 8443. It emits `established_vpn`; the legacy policy assigns a medium-confidence review finding.

### Exact trigger condition

An established IPv4 TCP socket using one of the five remote ports.

## What the result means

Ports 1194 and 1195 resemble OpenVPN, but 443 and 8443 are widely used by ordinary HTTPS, while WireGuard normally uses UDP on 51820. The signal is therefore intentionally not high confidence.

**How the line affects the report:** The line does not produce a final verdict on its own, but it sets `needsReview=true` and adds medium-confidence evidence.

## Limitations and possible false positives

The check does not associate the socket with a process or VPN app, does not read tcp6, and may be blocked by SELinux. Port-based classification produces many false positives.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Inspect the remote IP and connection owner before making changes. Stop an unnecessary VPN or API process, but do not block port 443. An external gateway moves the server socket off the phone.

### With root

Do not filter all of `/proc/net/tcp` or block port 443. Per-UID hiding requires a correct socket/proc policy, but it can easily create a mismatch with inet_diag. It is better to remove the actual local VPN socket.

### How to verify the result

```bash
adb shell cat /proc/net/tcp 2>&1 | head -80
adb shell ss -tn 2>/dev/null | grep -E ':(51820|1194|1195|443|8443) '
```
The app’s hexadecimal parser uses the remote port.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Blocking port 443 breaks most HTTPS traffic. Redact IP addresses before publishing a socket table.

### Rollback

Remove the specific firewall rule and restart the app or connection.

## Evidence level

**Medium.** Verified against the state check and `isVpnPort()`; medium-confidence review.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- External primary documentation or official project: [/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `tcp-vpn-port`, `inet-diag-denied`, `host-route`.

[Back to the Native signs reference](../)
