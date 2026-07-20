---
title: Local Android signals — Binder, TUN, routes, and localhost
permalink: /help/en/anti-detection/local-signals/
---

# Local Android signals — Binder, TUN, routes, and localhost

Local checks answer not “where did the packet go?” but “how does Android describe the network to this UID?” They remain visible even with direct egress and a plausible GeoIP result.

## Map of local channels

| Channel | Examples in RKNHardering | Why one hook is insufficient |
|---|---|---|
| Framework/Binder | `TRANSPORT_VPN`, `IS_VPN`, `VpnTransportInfo`, `NOT_VPN`, `LinkProperties`, callbacks | The data is produced by `system_server`; a native hook does not change it |
| libc/JNI | `NetworkInterface`, `getifaddrs`, `ioctl` | A Java `ConnectivityManager` hook does not affect libc or the kernel |
| netlink/kernel | `RTM_GETLINK`, `RTM_GETADDR`, routes, policy rules, qdisc | A raw syscall bypasses ordinary Zygisk/libc interposition |
| proc/sysfs | `/proc/net/*`, `/sys/class/net` | SELinux behavior depends on the ROM; access denial is not guaranteed on every device |
| PackageManager | VPN clients and `VpnService` declarations | Separate from tunnel activity |
| Local control plane | SOCKS/HTTP, Xray gRPC, Clash/sing-box REST | A password does not hide a listener; scanning can identify the protocol and port |
| dumpsys/system services | `vpn_management`, active `VpnService` instances | Ordinary applications are often restricted, but ROM and privilege change availability |

## Without root

### What you can do

Disable the system HTTP/SOCKS proxy and PAC if they are not required. Check `settings get global http_proxy`, Java properties, and the settings of the specific network. A system proxy is a separate direct signal and does nothing to conceal a VPN.

Disable unnecessary localhost listeners. Clash/mihomo/sing-box/Xray control APIs should either be disabled or inaccessible to the application. A strong secret protects commands, but RKNHardering additionally recognizes SOCKS5, HTTP CONNECT, and known REST/gRPC APIs.

Use Android package visibility to your advantage, but do not overestimate it. Beginning with Android 11, applications normally see a filtered package set; however, `QUERY_ALL_PACKAGES`, intent queries, a shared UID/installer, and OEM policies can expand that view. Official documentation: [Package visibility filtering](https://developer.android.com/training/package-visibility).

For a clean view across all local channels, move the VPN to an external gateway. This removes `VpnService`, the TUN interface, the VPN application, and the localhost daemon from the inspected Android device through one architectural change.

### What cannot generally be solved without root

An ordinary sandboxed APK cannot make the Android kernel return a filtered netlink dump to another UID. It cannot reliably rewrite another application’s Binder `NetworkCapabilities` response. It cannot hide an existing TUN interface from `getifaddrs` while keeping that interface operational for other applications.

A modified APK or “rootless Xposed” is not equivalent. Repackaging changes the application signature and integrity, while process injection is directly covered by `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, and beta direct-syscall/linker checks. For RKNHardering, this is usually worse than the original VPN signal.

### A secondary profile

A work profile can hide VPN applications installed in another profile and provide separate network settings, but Android still uses a shared kernel/network stack and RKNHardering can see userId/profile state. See the [profiles section](../profiles/) for details.

## With root

Complete local coverage requires two layers and, when necessary, a third:

1. **Framework layer:** the VPNHide module in Vector/LSPosed, scoped only to `System Framework`. It sanitizes Binder objects before they are serialized to the target process.
2. **Native layer:** exactly one of kmod, KPM, or Zygisk. Kernel variants are preferable because raw syscalls cannot bypass the filtering and the target process remains untouched.
3. **Ports/package layer:** `PackageManager` filtering and loopback blocking for the target UID.

Detailed installation is covered in [VPNHide and VPNHide Next](../root-vpnhide/).

### NetworkCapabilities and LinkProperties

Upstream VPNHide claims filtering of `NetworkCapabilities`, `NetworkInfo`, `LinkProperties`, the active network, network lists, and callbacks inside `system_server`. This is the correct interception point: RKNHardering receives an already sanitized Parcel rather than an Xposed bridge loaded into its own process.

Check the scope. Vector/LSPosed should include **only `System Framework`**, not RKNHardering. Adding the target application to scope creates a process-local hook surface and is not required by the VPNHide architecture.

### Interfaces, routes, and netlink

The kernel backend should cover at least:

- `ioctl(SIOCGIFFLAGS/SIOCGIFNAME/SIOCGIFCONF/...)`;
- `getifaddrs()` and `NetworkInterface`;
- netlink `RTM_GETLINK`, `RTM_GETADDR`, and route dumps;
- `/proc/net/route` and the IPv6 route where access is permitted;
- ifindex oracles and policy rules when supported by the selected backend.

Upstream VPNHide documents known gaps: raw syscalls bypass Zygisk, current kernel backends do not cover some `/proc/net/tcp*`/`if_inet6` paths, and KPM has separate parity limitations. Therefore, verify that a module is active by checking specific RKNHardering rows, not by trusting the manager status alone.

VPNHide Next claims broader modes covering sysfs/procfs, MTU/MSS/TCP_INFO, PMTU/GSO, BPF, qdisc, timing, and link-local signals. This is an external claim; compare the Minimum/Medium/Maximum modes on your firmware and keep a recovery path.

### Localhost and APIs

The best option is to disable the listener. If that is impossible, apply UID-based blocking. Upstream VPNHide provides a separate `portshide` component that generates rules for selected applications. VPNHide Next claims a kernel `security_socket_connect` hook instead of iptables.

Do not draw a conclusion from a single `connection refused`: it means the connection was rejected and may be the desired result. A `timeout` means the operation did not complete in time; scanners see it as a different behavior profile and it can itself become a timing signal. Verify how RKNHardering classifies the exact result.

### PackageManager

The Apps role in VPNHide filters enumeration, intent resolution, direct lookup, installer information, and UID mapping for selected observer UIDs. System UIDs and self-lookup must remain functional. After configuration, verify that the launcher and installer still work and that the VPN client can see itself.

## Verifying the result

Find the target package UID:

```bash
adb shell cmd package list packages -U | grep 'com.notcvnt.rknhardering'
```

Check the baseline state:

```bash
adb shell dumpsys connectivity
adb shell ip -details link
adb shell ip route show table all
adb shell ip rule
adb shell settings get global http_proxy
```

For upstream VPNHide, when the corresponding backend is installed, use read-only diagnostics only:

```bash
adb shell su -c 'cat /data/system/vpnhide_config.json'
adb shell su -c 'ls -la /data/adb/modules | grep -i vpnhide'
adb shell su -c 'cat /proc/vpnhide_ctl 2>/dev/null || cat /proc/vpnhide_targets 2>/dev/null'
adb logcat -d | grep -iE 'VpnHide|Vector|LSPosed'
```

The `/proc/vpnhide_*` path depends on the version or fork. `no such file or directory` means the path does not exist or the version uses another control interface; do not create the file manually.

After a change, force-stop the application and run it twice. Zygisk or port rules can require a process restart. Updating configuration is usually sufficient for a kernel or `system_server` layer, but installing a module always requires a reboot.

## Residual signals

Local cleanliness does not remove GeoIP, DNS, STUN, or server fingerprints. Kernel hiding does not automatically hide root. Package hiding does not change file signatures or process-local hooks. The inverse is also important: a clean root namespace does not conceal `TRANSPORT_VPN`.

[Back to the contents](../)
