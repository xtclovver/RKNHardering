---
title: "Occupied TCP ports on 127.0.0.1"
permalink: /help/en/native/loopback-port-conflict/
---

# Occupied TCP ports on 127.0.0.1

> **ID:** `LOOPBACK_PORT_CONFLICT`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

For ports 51820, 1194, 443, and 8443, the probe creates a TCP socket with `SO_REUSEADDR` and binds it to `127.0.0.1`. Only `EADDRINUSE` emits `loopback_port_conflict`; the legacy policy classifies it as high confidence.

### Exact trigger condition

The selected localhost TCP port cannot be bound because the address is already in use.

## What the result means

It reveals a listener or conflicting bind, but not its owner. Ports 443 and 8443 may be used by a local web UI, development server, or security app, not necessarily a VPN.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

`SO_REUSEADDR` and Android socket semantics affect the result. The probe does not scan all ports, IPv6 `::1`, or UDP.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

First remove the actual artifact: stop an unnecessary listener, API port, local daemon, or VPN client; then force-stop the apps and repeat the test. If a VPN is required, an external gateway is usually cleaner than any local workaround. A second profile may restrict package visibility, but it does not guarantee that network objects are hidden and it creates its own user/profile signal. Identify the process and disable the unnecessary local API. Simply changing the port helps only against the fixed list and must not be treated as a complete solution.

### With root

Root can filter data for a specific UID, but adds its own detection surface. In VPNHide, the Apps and Ports roles target PackageManager and localhost respectively, while the native backend covers supported interface and route paths. For a nonstandard port, disable the control API before trying to mask it. Apply any iptables or nftables rules through a module with a clear rollback path, and test IPv4 and IPv6 loopback separately. VPNHide Ports is intended to restrict the target UID’s access to loopback, but an actual bind conflict may remain visible depending on the implementation. It is better not to run the listener.

### How to verify the result

```bash
adb shell ss -ltn 2>/dev/null | grep -E '127\.0\.0\.1:(51820|1194|443|8443)'
adb shell lsof -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(51820|1194|443|8443)'
```
`address already in use` means that the port is occupied.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Stopping an unknown system listener may break an app. A global loopback firewall breaks IPC and local APIs.

### Rollback

Restore the service or remove only the UID-specific rule that was added. Do not expose the port externally instead of binding it to localhost.

## Evidence level

**High.** Verified against the four ports, `AF_INET` loopback, and `EADDRINUSE`; the kind is high confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [bind(2)](https://man7.org/linux/man-pages/man2/bind.2.html).
- External primary documentation or official project: [VPNHide Ports](https://github.com/okhsunrog/vpnhide).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `tcp-vpn-port`, `udp-port-conflict-physical`, `tcp-mss-low`.

[Back to the Native signs reference](../)
