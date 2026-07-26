---
title: "Occupied VPN-Related UDP Ports on a Physical IPv4 Address"
permalink: /help/en/native/udp-port-conflict-physical/
---

# Occupied VPN-Related UDP Ports on a Physical IPv4 Address

> **ID:** `UDP_PORT_CONFLICT_PHYSICAL`
> **Category:** VPN artifacts and sockets
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The probe takes the first IPv4 address from `getifaddrs()`, excluding interface names containing `tun`, `wg`, `ppp`, `xfrm`, `utun`, or `lo`. It then enables `SO_REUSEADDR` and attempts to bind UDP sockets on that IP to ports 500, 4500, 1194, 1701, and 51820. Only `EADDRINUSE` adds a port to the result.

### Exact trigger condition

At least one of the five UDP ports is already occupied on the selected “physical” IPv4 address.

## What the result means

A conflicting bind exists on this local address, often corresponding to IKE/IPsec, OpenVPN, L2TP, or WireGuard. The checker treats the signal as high confidence but does not identify the port owner.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The first `getifaddrs()` records do not guarantee selection of the primary physical path; a container or OEM interface may be chosen incorrectly. These ports also have legitimate uses. `SO_REUSEADDR`/`SO_REUSEPORT` and bind semantics can produce different outcomes.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Address the actual artifact first: stop an unnecessary listener, API port, local daemon, or VPN client; then force-stop the apps and repeat the test. When a VPN is required, an external gateway is usually cleaner than any local bypass. A secondary profile may restrict package visibility but does not guarantee that network objects are hidden, and it creates its own user/profile signal. Stop only a VPN or server listener that you recognize. A client-side Android `VpnService` normally does not need to listen on these ports on the physical IP, so identify the owner first.

### With root

Root access can filter data for a particular UID but introduces its own detection surface. In VPNHide, the Apps and Ports roles cover PackageManager and localhost respectively, while the native backend handles supported interface and route paths. For a nonstandard port, disable the control API before attempting to mask it. Apply any iptables/nftables rules through a module with a clear rollback path, and test IPv4 and IPv6 loopback separately. Use `ss -ulpn` or `lsof` as root to identify the owner. Do not hide a port before confirming the process; moving the listener is cleaner than a kernel hook.

### How to verify the result

```bash
adb shell su -c 'ip -4 -br addr; ss -H -u -l -n -p | grep -E ":(500|4500|1194|1701|51820)( |$)"'
```
`connection/listener not shown` does not rule out a short-lived or namespace-specific bind; repeat the built-in check.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Stopping an IKE, IMS, or VPN process may interrupt mobile connectivity or an enterprise tunnel. A firewall does not release a bind and therefore may not remove this signal.

### Rollback

Restart the service or VPN you stopped, restore the previous port, and remove only the temporary UID-specific rule. A reboot normally releases test sockets.

## Evidence level

**High.** Verified from first-physical-IPv4 selection, the five-port list, and `EADDRINUSE`; high kind.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [bind(2)](https://man7.org/linux/man-pages/man2/bind.2.html).
- External primary documentation or official project: [udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `udp-vpn-port`, `loopback-port-conflict`, `established-vpn-socket`.

[Back to the Native signs reference](../)
