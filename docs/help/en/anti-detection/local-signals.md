---
title: Local Android Signals — Binder, TUN, Routes, and Localhost
permalink: /help/en/anti-detection/local-signals/
---

# Local Android Signals — Binder, TUN, Routes, and Localhost

Local checks answer not “where did the packet go?” but “how does Android describe the network to this UID?” They remain visible even with direct egress and correct GeoIP.

## Map of Local Channels

| Channel | Examples in RKNHardering | Why one hook is insufficient |
|---|---|---|
| Framework/Binder | `TRANSPORT_VPN`, `IS_VPN`, `VpnTransportInfo`, `NOT_VPN`, `LinkProperties`, callbacks | The data is produced by `system_server`; a native hook does not change it |
| libc/JNI | `NetworkInterface`, `getifaddrs()`, ioctl | A Java hook on `ConnectivityManager` does not affect libc or the kernel |
| netlink/kernel | `RTM_GETLINK`, `RTM_GETADDR`, routes, policy rules, qdisc | A raw syscall bypasses ordinary Zygisk/libc interposition |
| proc/sysfs | `/proc/net/*`, `/sys/class/net` | SELinux behavior depends on the ROM; denial is not guaranteed on every device |
| PackageManager | VPN clients and `VpnService` declarations | Independent of tunnel activity |
| Local control plane | SOCKS/HTTP, Xray gRPC, Clash/sing-box REST | A password does not hide the listener; scanning can identify the protocol and port |
| dumpsys/system services | `vpn_management`, active `VpnService` instances | Ordinary apps are often restricted, but ROM and privilege level change availability |

## Without Root

### What Can Be Done

Disable the system HTTP/SOCKS proxy and PAC settings when they are not required. Check `settings get global http_proxy`, Java properties, and per-network settings. A system proxy is a separate direct detection and does nothing to hide a VPN.

Disable unnecessary localhost listeners. The control API in Clash/mihomo/sing-box/Xray should either be disabled or inaccessible to the app. A strong secret protects commands, but RKNHardering also recognizes SOCKS5, HTTP CONNECT, and known REST or gRPC APIs.

Use Android package visibility to your advantage, but do not overestimate it. Starting with Android 11, apps normally see a filtered package set, but `QUERY_ALL_PACKAGES`, intent queries, shared UIDs, installer relationships, and OEM policies may expand visibility. See the official [Package visibility filtering](https://developer.android.com/training/package-visibility) documentation.

When every local channel must appear clean, move the VPN to an external gateway. One architectural change removes `VpnService`, TUN, the VPN app, and the localhost daemon from the Android device under test.

### What Cannot Be Solved Generally Without Root

A sandboxed APK cannot make the Android kernel return a per-UID filtered netlink dump for another app without changing the system or kernel. It cannot reliably rewrite another app’s Binder `NetworkCapabilities` response. It also cannot hide an existing TUN interface from `getifaddrs()` while leaving that interface operational for other apps.

A modified APK or “rootless Xposed” is not equivalent. Repacking changes the app signature and integrity, while process injection falls directly under `HOOK_MARKERS`, `RWX_MEMORY_REGIONS`, `LIBRARY_INTEGRITY`, and beta direct-syscall or linker checks. For RKNHardering, this is usually worse than the original VPN signal.

### A Secondary Profile

A work profile may hide VPN apps installed in another profile and allow separate network settings, but Android still uses a shared kernel and network stack, and RKNHardering can see the user ID and profile state. See the [profiles section](../profiles/) for details.

## With Root

Complete local coverage needs two layers and, when necessary, a third:

1. **Framework layer:** the VPNHide module in Vector/LSPosed, scoped only to `System Framework`. It cleans Binder objects before they are serialized into the target process.
2. **Native layer:** exactly one of kmod, KPM, or Zygisk. Kernel variants are preferable because raw syscalls do not bypass their filtering and the target process remains untouched.
3. **Ports/package layer:** `PackageManager` filtering and loopback blocking for the target UID.

Detailed installation guidance is in [VPNHide and VPNHide Next](../root-vpnhide/).

### NetworkCapabilities and LinkProperties

Upstream VPNHide claims filtering for `NetworkCapabilities`, `NetworkInfo`, `LinkProperties`, the active network, the network list, and callbacks in `system_server`. This is the correct intervention point: RKNHardering receives an already-cleaned Parcel rather than loading an Xposed bridge into its own process.

Verify the scope. In Vector/LSPosed, select **only `System Framework`**, not RKNHardering. Adding the target app to scope creates a process-local hook surface and is not required by the VPNHide architecture.

### Interfaces, Routes, and Netlink

At minimum, the kernel backend must cover:

- `ioctl(SIOCGIFFLAGS/SIOCGIFNAME/SIOCGIFCONF/...)`;
- `getifaddrs()` and `NetworkInterface`;
- netlink `RTM_GETLINK`, `RTM_GETADDR`, and route dumps;
- `/proc/net/route` and the IPv6 route view where access is allowed;
- interface-index oracles and policy rules, when supported by the selected backend.

Upstream VPNHide documents known gaps: raw syscalls bypass Zygisk, current kernel backends do not cover some `/proc/net/tcp*` and `if_inet6` paths in the published matrix, and KPM has separate parity limitations. “The module is active” must therefore be verified through specific RKNHardering rows, not a manager status screen.

VPNHide Next claims a broader mode covering sysfs/procfs, MTU/MSS/TCP_INFO, PMTU/GSO, BPF, qdisc, timing, and link-local behavior. This is an external claim. Compare Minimum, Medium, and Maximum modes on the actual firmware and keep a recovery path available.

### Localhost and APIs

The best option is to disable the listener. When that is impossible, apply UID-specific blocking. Upstream VPNHide provides a separate `portshide` component that creates rules for selected apps. VPNHide Next claims a `security_socket_connect` kernel hook instead of iptables.

Do not draw a conclusion from one `connection refused` result: it means the connection was rejected and may be the intended outcome. `timeout` means the operation did not complete in time; for a scanner, that is a different behavior profile and can become a timing signal. Verify the classification shown by RKNHardering itself.

### PackageManager

VPNHide’s Apps role filters enumeration, intent resolution, direct lookup, installer information, and UID mapping for selected observer UIDs. System UIDs and self-lookup must continue to work. After configuration, verify that the launcher and installer still function and that the VPN client can see itself.

## Verifying the Result

Find the target package UID:

```bash
adb shell cmd package list packages -U | grep 'com.notcvnt.rknhardering'
```

Inspect the baseline state:

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

The `/proc/vpnhide_*` path depends on the version or fork. `no such file or directory` means the path is absent or that version uses another control interface; do not create the file manually.

After a change, force-stop the app and perform two runs. Zygisk and port rules may require a process restart. A kernel or `system_server` layer can often apply configuration updates without a full reboot, but a reboot is mandatory after installing the module.

## Residual Signals

A clean local view does not remove GeoIP, DNS, STUN, or server fingerprints. Kernel hiding does not automatically hide root. Package hiding does not change file signatures or process-local hooks. The reverse also matters: a clean root namespace does not hide `TRANSPORT_VPN`.

[Back to the anti-detection index](../)
