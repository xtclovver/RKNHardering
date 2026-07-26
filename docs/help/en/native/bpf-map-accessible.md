---
title: "Access to the netd BPF interface-index map"
permalink: /help/en/native/bpf-map-accessible/
---

# Access to the netd BPF interface-index map

> **ID:** `BPF_MAP_ACCESSIBLE`
> **Category:** Routes and network stack
> **Status in RKNHardering 2.10.0:** Active check
> **Role in the verdict:** High

This page describes the actual implementation in RKNHardering 2.10.0. It distinguishes what can be done without root, what requires root, and where a mitigation only reduces one signal without hiding the VPN as a whole.

## What is checked and why

The legacy probe attempts to open three paths read-only: `/sys/fs/bpf/map_netd_iface_index_name_map`, `/sys/fs/bpf/netd_shared/map_netd_iface_index_name_map`, and `/sys/fs/bpf/netd_iface_index_name_map`. A successful open emits `bpf_map_accessible`; the legacy policy classifies it as high confidence.

### Exact trigger condition

An ordinary app process can open one of the fixed BPF pin paths.

## What the result means

Access is normally restricted on stock Android. If available, the map may expose an ifindex-to-name mapping and bypass superficial hiding.

**How the line affects the report:** The line sets `detected=true` and is treated as a high-confidence local indicator.

## Limitations and possible false positives

The probe only tests whether the path can be opened; it does not read the map or confirm that a VPN entry exists. Path layouts vary across Android versions.

This line must be evaluated together with neighboring signals. A clean result from a single API does not simultaneously cover Java Binder, libc, raw netlink/syscalls, procfs/sysfs, local sockets, and server-side indicators.

## Recommendations for this vector

### Without root

Do not weaken SELinux or BPF filesystem permissions on a production ROM. If access is exposed by a custom ROM, the cleanest option is a stock enforcing build.

### With root

Apply the smallest policy fix: the target UID should not be able to read netd maps. Do not disable BPF or netd globally. VPNHide Next claims eBPF filtering, but this is a high-risk kernel-level experiment.

### How to verify the result

```bash
adb shell ls -l /sys/fs/bpf 2>/dev/null | head -80
adb shell 'for p in /sys/fs/bpf/map_netd_iface_index_name_map /sys/fs/bpf/netd_shared/map_netd_iface_index_name_map /sys/fs/bpf/netd_iface_index_name_map; do [ -r "$p" ] && echo readable:$p; done'
```
Shell access is not equivalent to access from the app UID.

After any change, force-stop both RKNHardering and the VPN client, start them again, and repeat the full scan. Zygisk, Xposed, and kernel modules usually require a reboot. Compare not only this line but also neighboring signals: a partial hook often creates inconsistencies between APIs.

## Required permissions and risks

The probe itself runs with ordinary app permissions and does not request root. The ADB commands below are for orientation only: `adb shell` runs under a different UID and may see either more or less than the app process. The decisive test is to run the check again after a force-stop.

### Risks

Changing netd BPF maps or policy can break traffic accounting, the firewall, and networking. Do not delete pinned maps.

### Rollback

Revert the sepolicy or module change and restart netd or the device; if the system is unstable, restore the boot image.

## Evidence level

**High.** Verified against the three paths; classified as legacy high confidence.

The status of a third-party solution does not automatically carry over to this device. A module developer’s claim is only the initial hypothesis; confirmation requires a reproducible RKNHardering result on the specific Android version, firmware, and kernel.

## Sources and last verification date

- Verified against project code: [`native_signs_probe.cpp` — native probe implementation](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- Verified against project code: [`NativeSignsChecker.kt` — main native/legacy verdict logic](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- Verified against project code: [`NativeSignalId.kt` — complete ID registry](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- Verified against project code: [`NativeSignalCatalog.kt` — category, slug, and line mapping](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- External primary documentation or official project: [Linux BPF docs](https://docs.kernel.org/bpf/index.html).
- External primary documentation or official project: [AOSP eBPF traffic monitoring](https://source.android.com/docs/core/datausage/ebpf-traffic-monitor).
- Implementation and links last checked: **July 19, 2026**.

Related signals: `deep-bpf-map-accessible`, `ifindexname-vpn`.

[Back to the Native signs reference](../)
