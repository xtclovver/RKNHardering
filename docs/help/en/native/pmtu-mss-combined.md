---
title: "TCP_INFO MSS on a Local 127.0.0.1:443 Connection"
permalink: /help/en/native/pmtu-mss-combined/
---

# TCP_INFO MSS on a Local 127.0.0.1:443 Connection

> **ID:** `PMTU_MSS_COMBINED`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** Low

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The function creates a TCP socket and attempts to connect to `127.0.0.1:443`. It reads `TCP_INFO` and reports `tcpi_snd_mss` and `tcpi_rcv_mss` only if a local listener accepts the connection. Despite the function name, it does not actually test UDP or PMTU.

### Exact trigger condition

A successful connection to localhost:443 followed by a successful `getsockopt(TCP_INFO)` call. The values are not compared with a threshold; the line is informational.

## What the result means

This is a baseline for the local TCP stack and listener, not a VPN indicator. If nothing is listening on port 443, the line is not emitted at all. Any MSS value is meaningful only in the context of the peer and route.

**How the line affects the report:** The line is informational or diagnostic. It is useful for comparing runs, but does not by itself prove the presence of a VPN or tampering.

## Limitations and possible false positives

Loopback does not measure Internet PMTU or the tunnel path. The listener may apply its own socket options. The word “combined” in the name is misleading; there are no thresholds or correlation.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

For a diagnostic signal, do not try to “fix” anything at first. Record a baseline on the same device without the VPN, then repeat the test with the VPN under the same network, temperature, and load conditions. Only a reproducible difference between the two series is useful for analysis. A single MTU, timing, or GSO value is not evidence. Do not start a listener merely to “pass” this check: the listener itself creates a port-conflict signal. Use a separate test server and a dedicated probe for network research.

### With root

A root module can alter this indicator, but tuning it to a particular number can easily disrupt TCP/UDP, DNS, calls, or power consumption. VPNHide Next claims to filter several indirect parameters, but those capabilities must be tested separately from basic interface hiding. Do not enable the maximum set of kernel hooks before obtaining a clean baseline and a working rollback procedure. Do not substitute `TCP_INFO` globally. When investigating MSS, capture packets and the route MTU in a test environment.

### How to verify the result

```bash
adb shell 'ss -H -ltn | grep -E "127[.]0[.]0[.]1:443|[*]:443" || echo no-local-443-listener'
```
When a listener is present, compare the details with a native `getsockopt(TCP_INFO)` test; `ss` may display a different MSS field.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Running a test service on port 443 can conflict with local APIs. Globally substituting MSS values can cause fragmentation or black-holed connections.

### Rollback

Stop only the test listener you created and remove its autostart entry. Restore the default socket and kernel parameters.

## Evidence level

**Low.** Verified from the loopback connection and the absence of thresholds; informational kind.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`VpnNativeDetectorChecker.kt` — deep VPN verdict and confidence](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [tcp(7) TCP_INFO](https://man7.org/linux/man-pages/man7/tcp.7.html).
- External primary documentation or official project: [Linux TCP_INFO uapi](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/tcp.h).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `tcp-mss-low`, `loopback-port-conflict`, `normal-pmtu`.

[Back to the Native signs reference](../)
