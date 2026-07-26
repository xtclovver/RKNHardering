---
title: RKNHardering Native Checks Reference
permalink: /help/en/native/
---

# RKNHardering Native Checks Reference

This reference explains **all 85 `NativeSignalId` entries in version 2.10.0**. It is not a collection of generic advice: every page is tied to a specific Kotlin or C++ condition, describes the line’s role in the final verdict, and separates actions that can be taken **without root** from those that **require root**.

Each signal page identifies the exact API, syscall, netlink request, file, property, or heuristic; its limitations; verification commands; risks; and rollback procedure. Historical IDs that have no producer in the current pipeline are marked explicitly, as is the `gso_ok` row, which C++ produces without a detail value and which the version 2.10.0 UI parser discards.

A practical matrix covering every local and server-side check is available in the [complete anti-detection guide](../anti-detection/matrix/). Start with the [threat model](../anti-detection/threat-model/) and [laboratory methodology](../anti-detection/lab/): otherwise, it is easy to remove one row while creating three new ones.

## How to interpret a signal’s role

- **High** — the row normally sets `detected=true`.
- **Medium** — the row sets `needsReview=true`; it warrants investigation but is not an independent final verdict.
- **Low** — telemetry or baseline data without a detection threshold.
- **Mixed** — one ID serves several branches with different effects.
- **Registry/compatibility** — the ID exists, but version 2.10.0 has no dedicated active producer or contains a parser gap.

The ADB commands on these pages are diagnostic aids. `adb shell` runs under a different UID and SELinux domain, so its output does not replace a repeated check inside RKNHardering. Perform root or kernel-level experiments first on a test device, with a copy of the boot image and a known way to disable the module from recovery.

## Interfaces

| Page | ID | Role | Status | What the article explains |
|---|---|---|---|---|
| [interface-enumeration](./interface-enumeration/) | `INTERFACE_ENUMERATION` | Mixed | Active check | Primary network-interface enumeration |
| [tuntap-type](./tuntap-type/) | `TUNTAP_TYPE` | High | Active check | ARPHRD_TUNNEL/TUN-TAP interface type regardless of name |
| [ipsec-interface](./ipsec-interface/) | `IPSEC_INTERFACE` | Low | Active check | IPsec/XFRM interfaces |
| [jvm-native-mismatch](./jvm-native-mismatch/) | `JVM_NATIVE_MISMATCH` | Mixed | Active check | Inconsistency between Java `NetworkInterface` and native `getifaddrs()` |
| [inet6-vpn-interface](./inet6-vpn-interface/) | `INET6_VPN_INTERFACE` | High | Active check | Legacy ioctl check for fixed VPN interfaces |
| [arp-vpn-interface](./arp-vpn-interface/) | `ARP_VPN_INTERFACE` | Registry/compatibility | ID retained for compatibility; no dedicated producer in 2.10.0 | Reserved legacy ARP-on-VPN-interface ID |
| [hidden-mac-neighbors](./hidden-mac-neighbors/) | `HIDDEN_MAC_NEIGHBORS` | High | Active check | ARP entries with a zero or broadcast MAC address |
| [sysfs-vpn-leak](./sysfs-vpn-leak/) | `SYSFS_VPN_LEAK` | High | Active check | VPN interface accessible through sysfs and proc/sys |
| [getifaddrs-vpn](./getifaddrs-vpn/) | `GETIFADDRS_VPN` | High | Active check | Fixed VPN names in `getifaddrs()` |
| [sysclassnet-vpn](./sysclassnet-vpn/) | `SYSCLASSNET_VPN` | High | Active check | Fixed VPN interfaces in `/sys/class/net` |
| [rtm-getlink-vpn](./rtm-getlink-vpn/) | `RTM_GETLINK_VPN` | High | Active check | VPN interface in netlink `RTM_GETLINK` |
| [proc-if-inet6-vpn](./proc-if-inet6-vpn/) | `PROC_IF_INET6_VPN` | High | Active check | VPN interface in `/proc/net/if_inet6` |
| [proc-net-dev-vpn](./proc-net-dev-vpn/) | `PROC_NET_DEV_VPN` | High | Active check | VPN interface counters in `/proc/net/dev` |
| [ifindexname-vpn](./ifindexname-vpn/) | `IFINDEXNAME_VPN` | High | Active check | VPN name returned by `if_indextoname()` |

## Routes and the Network Stack

| Page | ID | Role | Status | What the article explains |
|---|---|---|---|---|
| [route-table](./route-table/) | `ROUTE_TABLE` | Mixed | Active check | Main routing table and default route |
| [host-route](./host-route/) | `HOST_ROUTE` | Medium | Active check | Public /32 or /128 host route through a physical interface |
| [route-vpn-interface](./route-vpn-interface/) | `ROUTE_VPN_INTERFACE` | High | Active check | Legacy routes through fixed VPN interface names |
| [sysctl-forwarding](./sysctl-forwarding/) | `SYSCTL_FORWARDING` | Medium | Active check | IPv4 forwarding enabled |
| [sysctl-rp-filter](./sysctl-rp-filter/) | `SYSCTL_RP_FILTER` | Medium | Active check | Reverse-path filtering disabled globally |
| [vpn-policy-rules](./vpn-policy-rules/) | `VPN_POLICY_RULES` | High | Active check | Legacy nonstandard IPv4 routes on a VPN interface |
| [vpn-qdisc](./vpn-qdisc/) | `VPN_QDISC` | Medium | Active check | Legacy `tun0`/`wg0` traffic counters under the qdisc name |
| [tcp-mss-low](./tcp-mss-low/) | `TCP_MSS_LOW` | High | Active check | Low TCP MSS on a local connection |
| [bpf-map-accessible](./bpf-map-accessible/) | `BPF_MAP_ACCESSIBLE` | High | Active check | Access to netd’s BPF interface-index map |
| [proc-ipv6-route-vpn](./proc-ipv6-route-vpn/) | `PROC_IPV6_ROUTE_VPN` | High | Active check | VPN interface in `/proc/net/ipv6_route` |
| [vpn-policy-rules-netlink](./vpn-policy-rules-netlink/) | `VPN_POLICY_RULES_NETLINK` | High | Active check | Suspicious policy rules through `RTM_GETRULE` |
| [fib-trie-denied](./fib-trie-denied/) | `FIB_TRIE_DENIED` | Medium | Active check | Access to `/proc/net/fib_trie` denied or failed |
| [deep-vpn-qdisc](./deep-vpn-qdisc/) | `DEEP_VPN_QDISC` | Registry/compatibility | ID retained for compatibility; no dedicated producer in 2.10.0 | Reserved deep qdisc ID |
| [deep-bpf-map-accessible](./deep-bpf-map-accessible/) | `DEEP_BPF_MAP_ACCESSIBLE` | Registry/compatibility | ID retained for compatibility; no dedicated producer in 2.10.0 | Reserved deep BPF-map-accessibility ID |
| [route-count](./route-count/) | `ROUTE_COUNT` | Low | Active check | Informational route and interface count |
| [trim-oracle](./trim-oracle/) | `TRIM_ORACLE` | Medium | Active check | Interface-count mismatch between `if_indextoname()` and `RTM_GETLINK` |
| [pmtu-mss-combined](./pmtu-mss-combined/) | `PMTU_MSS_COMBINED` | Low | Active check | `TCP_INFO` MSS on a local 127.0.0.1:443 connection |
| [udp-pmtu-ok](./udp-pmtu-ok/) | `UDP_PMTU_OK` | Low | Active check | Successfully sent 1500 bytes over UDP to 127.0.0.1:53 |
| [udp-pmtu-fail](./udp-pmtu-fail/) | `UDP_PMTU_FAIL` | Medium | Active check | Sending a 1500-byte UDP datagram to loopback failed |
| [normal-pmtu](./normal-pmtu/) | `NORMAL_PMTU` | Low | Active check | MTU of the first non-tunnel interface |
| [timing-oracle](./timing-oracle/) | `TIMING_ORACLE` | Low | Active check | ARM64 socket/sendto timing through `CNTVCT_EL0` |
| [backpressure](./backpressure/) | `BACKPRESSURE` | Low | Active check | Loopback UDP flood: 50,000 packets of 1,400 bytes |
| [gso-failed](./gso-failed/) | `GSO_FAILED` | Low | Active check | `UDP_SEGMENT` rejected by `setsockopt()` |
| [gso-send-failed](./gso-send-failed/) | `GSO_SEND_FAILED` | Low | Active check | `UDP_SEGMENT` accepted, but sending 4,800 bytes failed |
| [gso-ok](./gso-ok/) | `GSO_OK` | Registry/compatibility | Native producer exists, but the current UI parser drops the row | UDP GSO accepted and loopback send succeeded |
| [hardware-timestamp](./hardware-timestamp/) | `HW_TIMESTAMP` | Low | Active check | `SIOCSHWTSTAMP` successfully configured on loopback |
| [traceroute-denied](./traceroute-denied/) | `TRACEROUTE_DENIED` | Medium | Active check | Loopback UDP send with TTL=1 returned `EACCES` |

## VPN Artifacts and Sockets

| Page | ID | Role | Status | What the article explains |
|---|---|---|---|---|
| [vpn-property](./vpn-property/) | `VPN_PROPERTY` | High | Active check | Legacy VPN/DNS system properties |
| [dns-property](./dns-property/) | `DNS_PROPERTY` | Registry/compatibility | ID retained for compatibility; no dedicated producer in 2.10.0 | Reserved `dns_prop` ID |
| [vpn-file](./vpn-file/) | `VPN_FILE` | Registry/compatibility | ID retained for compatibility; no dedicated producer in 2.10.0 | Reserved general VPN-file ID |
| [tcp-vpn-port](./tcp-vpn-port/) | `TCP_VPN_PORT` | Registry/compatibility | ID retained for compatibility; no dedicated producer in 2.10.0 | Reserved legacy TCP VPN-port ID |
| [udp-vpn-port](./udp-vpn-port/) | `UDP_VPN_PORT` | Registry/compatibility | ID retained for compatibility; no dedicated producer in 2.10.0 | Reserved legacy UDP VPN-port ID |
| [established-vpn-socket](./established-vpn-socket/) | `ESTABLISHED_VPN_SOCKET` | Medium | Active check | Established TCP connection on a typical VPN port |
| [so-bindtodevice](./so-bindtodevice/) | `SO_BINDTODEVICE` | Medium | Active check | Legacy socket identity under the historical `SO_BINDTODEVICE` name |
| [loopback-port-conflict](./loopback-port-conflict/) | `LOOPBACK_PORT_CONFLICT` | High | Active check | Occupied TCP ports on 127.0.0.1 |
| [ip-recverr](./ip-recverr/) | `IP_RECVERR` | Registry/compatibility | ID retained for compatibility; no dedicated producer in 2.10.0 | Reserved positive `IP_RECVERR` ID |
| [inet-diag-denied](./inet-diag-denied/) | `INET_DIAG_DENIED` | Medium | Active check | `NETLINK_SOCK_DIAG` unavailable to the app |
| [bindtodevice-leak](./bindtodevice-leak/) | `BINDTODEVICE_LEAK` | High | Active check | `SO_BINDTODEVICE` confirms that a VPN interface exists |
| [getsockname-leak](./getsockname-leak/) | `GETSOCKNAME_LEAK` | High | Active check | An unbound UDP socket immediately received a private IPv4 address |
| [udp-port-conflict-physical](./udp-port-conflict-physical/) | `UDP_PORT_CONFLICT_PHYSICAL` | High | Active check | Occupied VPN-related UDP ports on a physical IPv4 address |

## Process Hooks and Integrity

| Page | ID | Role | Status | What the article explains |
|---|---|---|---|---|
| [hook-markers](./hook-markers/) | `HOOK_MARKERS` | Medium | Active check | Named injection markers in `/proc/self/maps` |
| [rwx-memory-regions](./rwx-memory-regions/) | `RWX_MEMORY_REGIONS` | Low | Active check | Large RWX memory regions |
| [library-integrity](./library-integrity/) | `LIBRARY_INTEGRITY` | Medium | Active check | Origin of key libc symbols |
| [vpnhide](./vpnhide/) | `VPNHIDE` | Mixed | Active check | VPNHide artifacts and regression oracles |
| [lsposed](./lsposed/) | `LSPOSED` | Medium | Active check | File artifacts from an LSPosed/Vector-like stack |
| [hook-property](./hook-property/) | `HOOK_PROPERTY` | High | Active check | LSPosed/Magisk/Zygote-hook system properties |

## Root and System State

| Page | ID | Role | Status | What the article explains |
|---|---|---|---|---|
| [root-indicators](./root-indicators/) | `ROOT_INDICATORS` | Structural | Active check | Native root-indicator summary |
| [root-su-binary](./root-su-binary/) | `ROOT_SU_BINARY` | Medium | Active check | `su` file in known paths |
| [root-property](./root-property/) | `ROOT_PROPERTY` | Medium | Active check | Suspicious root/debug system properties |
| [root-management](./root-management/) | `ROOT_MANAGEMENT` | Medium | Active check | Root-manager directories and files |
| [root-system-rw](./root-system-rw/) | `ROOT_SYSTEM_RW` | Medium | Active check | Write access to `/system` |
| [root-suspicious-mount](./root-suspicious-mount/) | `ROOT_SUSPICIOUS_MOUNT` | Medium | Active check | Mount rows containing Magisk/core-only and root markers |
| [root-overlay-mount](./root-overlay-mount/) | `ROOT_OVERLAY_MOUNT` | Medium | Active check | Overlay mount over `/system` or `/vendor` |
| [root-selinux](./root-selinux/) | `ROOT_SELINUX` | Medium | Active check | SELinux permissive mode or an inaccessible enforce file |
| [root-uid](./root-uid/) | `ROOT_UID` | Medium | Active check | Process UID/EUID/GID equals 0 |
| [root-magisk-property](./root-magisk-property/) | `ROOT_MAGISK_PROPERTY` | Medium | Active check | Magisk-specific system properties |

## Emulation, Profiles, and Isolation

| Page | ID | Role | Status | What the article explains |
|---|---|---|---|---|
| [emulator-indicators](./emulator-indicators/) | `EMULATOR_INDICATORS` | Structural | Active check | Emulator-indicator summary |
| [emulator-qemu-property](./emulator-qemu-property/) | `EMULATOR_QEMU_PROPERTY` | Medium | Active check | QEMU system properties |
| [emulator-qemu-pipe](./emulator-qemu-pipe/) | `EMULATOR_QEMU_PIPE` | Medium | Active check | QEMU/Genymotion devices and sockets |
| [emulator-goldfish](./emulator-goldfish/) | `EMULATOR_GOLDFISH` | Medium | Active check | Goldfish/Ranchu in hardware and board properties |
| [emulator-qemu-driver](./emulator-qemu-driver/) | `EMULATOR_QEMU_DRIVER` | Medium | Active check | Goldfish in `/proc/tty/drivers` |
| [emulator-bluestacks](./emulator-bluestacks/) | `EMULATOR_BLUESTACKS` | Medium | Active check | BlueStacks files |
| [emulator-build-profile](./emulator-build-profile/) | `EMULATOR_BUILD` | Medium | Active check | `Build.FINGERPRINT`/`MODEL`/`HARDWARE`/`PRODUCT` heuristics |
| [isolation-profile](./isolation-profile/) | `ISOLATION_PROFILE` | Structural | Active check | Android user/profile-isolation summary |
| [isolation-clone](./isolation-clone/) | `ISOLATION_CLONE` | Medium | Active check | OEM clone/dual-app user ID |
| [isolation-secondary-user](./isolation-secondary-user/) | `ISOLATION_SECONDARY_USER` | Medium | Active check | Execution outside the primary user |
| [isolation-work-profile](./isolation-work-profile/) | `ISOLATION_WORK_PROFILE` | Medium | Active check | RKNHardering is a profile owner |

## Service-Level Signals

| Page | ID | Role | Status | What the article explains |
|---|---|---|---|---|
| [native-library](./native-library/) | `NATIVE_LIBRARY` | Availability | Active check | Loading the native checks library |
| [syscall-unavailable](./syscall-unavailable/) | `SYSCALL_UNAVAILABLE` | Availability | Active check | Native syscall/socket probe unavailable |
| [general-diagnostics](./general-diagnostics/) | `GENERAL_DIAGNOSTICS` | Structural | Active check | Deep native detector returned no rows |
| [unknown-signals](./unknown-signals/) | `UNKNOWN` | Structural | Active check | Unknown or unmapped native kind |

## Official Download Sources for Root Components

- [VPNHide releases](https://github.com/okhsunrog/vpnhide/releases/latest) and its [coverage map](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- [VPNHide Next releases](https://github.com/soranerai/vpnhide_next/releases/latest), an experimental fork with more aggressive kernel hooks.
- [Vector releases](https://github.com/JingMatrix/Vector/releases/latest) for the framework/Xposed layer.
- [Magisk releases](https://github.com/topjohnwu/Magisk/releases/latest), [KernelSU Next releases](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest), and [APatch releases](https://github.com/bmax121/APatch/releases/latest).

Download APK and ZIP files only from an official repository or release page, verify signatures or hashes, do not run unknown installer scripts as root, and do not install multiple native backends that intercept the same kernel functions.

[Back to the language index](../)
