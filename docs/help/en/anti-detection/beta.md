---
title: Beta Checks — Conditions, Quorum, and Countermeasures
permalink: /help/en/anti-detection/beta/
---

# Beta Checks — Conditions, Quorum, and Countermeasures

Beta mode in RKNHardering must be enabled explicitly. It does not turn every denial or unusual row into `DETECTED`: `PERMISSION_DENIED`, `UNSUPPORTED`, races, malformed or truncated results, and network-epoch changes are suppressed or downgraded. A positive observation must match the registered source, domain, and independence group.

Only two checks can become standalone hard signals: **`beta.vpn_binder`** with `BINDER_SERVICE` authority and **`beta.tun_fd`** with `KERNEL_QUERY` authority. Both require at least two successful samples, the same classification, and a stable epoch. Other beta checks produce review findings or participate in a quorum of independent groups.

## Without Root

The main strategies remain the same: an external gateway removes the local VPN; the owner user removes profile context; disabling the proxy or control plane removes local sockets; and an original APK outside a virtual container removes sandbox and hook inconsistencies. Do not try to “fix” a permission denial by granting Shizuku or root. That expands the probe’s access and may expose more genuine signals.

## With Root

The beta layer is particularly effective at detecting partial hooks. The framework must filter Binder consistently, the kernel backend must cover raw netlink, socket, and TUN-FD paths, and the target process should remain free of Xposed or Zygisk injection. Global root or Shizuku probes run only when explicitly selected. They can be useful during controlled validation of your own protection, but the app should not retain unnecessary privileges permanently.

## Complete Beta-ID Table

| Beta ID | Observation | Domain / independent group | Without root | With root | What remains |
|---|---|---|---|---|---|
| `beta.vpn_binder` | Binder request to the Android VPN service or state. **Hard authority after a stable repeat.** | `VPN_OR_PROXY` / `android_vpn_service` | Use an external gateway. | Filter in `system_server`; keep the target outside Xposed scope. | Binder and native models must agree. |
| `beta.user_profile` | Current user/profile through Android user APIs. | `ISOLATED_PROFILE` / `android_user_manager` | Use the owner user. | Target the correct UID only; do not break `UserManager`. | A truthful profile signal remains. |
| `beta.foreground_user` | Foreground user and consistency with the process context. | `ISOLATED_PROFILE` / `android_user_manager` | Use the owner user. | Target the correct UID only; do not break `UserManager`. | A truthful profile signal remains. |
| `beta.connectivity_binder` | Connectivity Binder responses compared with the public model. | `NETWORK_PATH_DIVERGENCE` / `android_connectivity` | Use an external gateway. | Filter in `system_server`; keep the target outside Xposed scope. | Binder and native models must agree. |
| `beta.netd_netid` | netd/network ID of the active path. | `NETWORK_PATH_DIVERGENCE` / `netd` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.socket_identity` | Socket mark, netId, and identity. | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.inet_diag_cookie` | INET_DIAG cookie and socket identity. | `NETWORK_PATH_DIVERGENCE` / `socket_diag` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.route_lookup` | Single route lookup to a control destination. | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.policy_rules` | Policy-routing rules for a UID or netId. | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.rtnl_address` | IPv4/IPv6 RTNL address dump. | `NETWORK_PATH_DIVERGENCE` / `kernel_link` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.extended_rtnetlink` | Extended rtnetlink/netd routing context. | `NETWORK_PATH_DIVERGENCE` / `kernel_routing` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.interface_driver` | Driver, kind, and details of a network interface. | `VPN_OR_PROXY` / `kernel_link` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.interface_traffic` | Interface counters and the actual egress. | `NETWORK_PATH_DIVERGENCE` / `active_egress` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.wireguard_genl` | WireGuard generic-netlink state. | `VPN_OR_PROXY` / `kernel_vpn` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.ovpn_genl` | OpenVPN DCO/generic-netlink state. | `VPN_OR_PROXY` / `kernel_vpn` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.xfrm` | XFRM/IPsec states and policies. | `VPN_OR_PROXY` / `kernel_ipsec` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.unix_diag` | Unix-domain sockets of the local control plane. | `VPN_OR_PROXY` / `local_control_plane` | Disable the proxy or control daemon. | Apply a UID or namespace block. | The listener or Unix socket may remain visible. |
| `beta.unix_peer_identity` | Peer credentials and identity of a Unix socket. | `VPN_OR_PROXY` / `local_control_plane` | Disable the proxy or control daemon. | Apply a UID or namespace block. | The listener or Unix socket may remain visible. |
| `beta.tun_fd` | Kernel query of a TUN file descriptor. **Hard authority after a stable repeat.** | `VPN_OR_PROXY` / `process_fd` | Remove the local `VpnService` by using an external gateway. | Use kernel filtering; a userspace hook is insufficient. | Hard only after at least two stable matching samples. |
| `beta.bpf_netd` | BPF/netd maps and traffic policy. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.cgroup_bpf` | Cgroup BPF attachment and policy. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.netfilter_path` | Netfilter path or redirect state. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.original_destination` | Original destination after a transparent redirect. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.direct_syscall_consistency` | Comparison of libc APIs with direct syscalls. | `HOOK_OR_TAMPERING` / `hook_consistency` | Avoid process injection. | Use a kernel backend and keep the target outside Zygisk/Xposed. | An alternate path exposes a partial hook. |
| `beta.io_uring_consistency` | Alternate io_uring path compared with a hooked API. | `HOOK_OR_TAMPERING` / `alternate_syscall_path` | Avoid process injection. | Use a kernel backend and keep the target outside Zygisk/Xposed. | An alternate path exposes a partial hook. |
| `beta.fd_identity` | Type and identity of process file descriptors. | `HOOK_OR_TAMPERING` / `process_fd` | Avoid process injection. | Use a kernel backend and keep the target outside Zygisk/Xposed. | An alternate path exposes a partial hook. |
| `beta.sandbox_identity.process` | Process identity of a virtual container. | `APP_VIRTUALIZATION` / `process_identity` | Run the original APK in the normal sandbox. | Do not use a virtual container or repacked APK. | Root does not turn a container into a normal profile. |
| `beta.sandbox_identity.filesystem` | Filesystem layout and sandbox identity. | `APP_VIRTUALIZATION` / `filesystem_identity` | Run the original APK in the normal sandbox. | Do not use a virtual container or repacked APK. | Root does not turn a container into a normal profile. |
| `beta.sandbox_identity.namespace` | Namespace identity of the sandbox or virtualization layer. | `APP_VIRTUALIZATION` / `namespace_identity` | Run the original APK in the normal sandbox. | Do not use a virtual container or repacked APK. | Root does not turn a container into a normal profile. |
| `beta.fscrypt_identity` | fscrypt and user-storage identity. | `APP_VIRTUALIZATION` / `filesystem_identity` | Run the original APK in the normal sandbox. | Do not use a virtual container or repacked APK. | Root does not turn a container into a normal profile. |
| `beta.linker_integrity` | Linker/loader integrity and hooks. | `HOOK_OR_TAMPERING` / `loader_integrity` | Avoid process injection. | Use a kernel backend and keep the target outside Zygisk/Xposed. | An alternate path exposes a partial hook. |
| `beta.dns_netid` | DNS resolver netId and path. | `NETWORK_PATH_DIVERGENCE` / `dns_path` | Align the real route, DNS, and TLS path; use an external gateway. | Root does not replace the server-side path; eliminate MITM. | Network epoch and noise matter; server context alone is not always hard evidence. |
| `beta.native_dns_resolver` | Native resolver compared with framework DNS. | `NETWORK_PATH_DIVERGENCE` / `dns_path` | Align the real route, DNS, and TLS path; use an external gateway. | Root does not replace the server-side path; eliminate MITM. | Network epoch and noise matter; server context alone is not always hard evidence. |
| `beta.proxy_selector` | Java `ProxySelector` and system-proxy consistency. | `VPN_OR_PROXY` / `android_proxy` | Disable the proxy or control daemon. | Apply a UID or namespace block. | The listener or Unix socket may remain visible. |
| `beta.transport_matrix` | HTTP/DNS/UDP matrix of canary endpoints. | `NETWORK_PATH_DIVERGENCE` / `active_egress` | Align the real route, DNS, and TLS path; use an external gateway. | Root does not replace the server-side path; eliminate MITM. | Network epoch and noise matter; server context alone is not always hard evidence. |
| `beta.tls_interception` | TLS interception and certificate path. | `VPN_OR_PROXY` / `tls_path` | Align the real route, DNS, and TLS path; use an external gateway. | Root does not replace the server-side path; eliminate MITM. | Network epoch and noise matter; server context alone is not always hard evidence. |
| `beta.pktinfo` | `IP_PKTINFO`/IPv6 pktinfo for inbound and outbound paths. | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.netlink_transitions` | Time sequence of netlink network events. | `NETWORK_PATH_DIVERGENCE` / `network_timeline` | Use an external gateway or remove the local VPN. | Kernel-level filtering for the specific channel; VPNHide Next advanced mode is experimental. | Denial is often neutral; kernel and ROM behavior differs. |
| `beta.traceroute` | Traceroute and path observation. | `SYSTEM_NETWORK_CONTEXT` / `path_observation` | Align the real route, DNS, and TLS path; use an external gateway. | Root does not replace the server-side path; eliminate MITM. | Network epoch and noise matter; server context alone is not always hard evidence. |
| `beta.server_fingerprint` | Remote fingerprint of the observed channel. | `SYSTEM_NETWORK_CONTEXT` / `server_observation` | Align the real route, DNS, and TLS path; use an external gateway. | Root does not replace the server-side path; eliminate MITM. | Network epoch and noise matter; server context alone is not always hard evidence. |
| `beta.root_emulator` | Aggregate beta assessment of root, emulator, and device integrity. | `DEVICE_INTEGRITY` / `device_integrity` | Use a physical stock device without root. | Minimize the root surface; do not partially spoof an emulator. | Review or quorum remains possible. |

## How to Interpret the Quorum

Project-verified: beta network evidence becomes `DETECTED` when there are at least two independent network groups, or one beta group plus an independent stable network source. Isolation combined with a network signal may also produce detection. Tampering and app virtualization require two independent groups. `SYSTEM_NETWORK_CONTEXT`, which includes traceroute and server fingerprinting, cannot form a hard quorum by itself.

The correct objective is therefore not to “silence every beta row,” but to remove independent corroboration. A clean Binder result does not help when `tun_fd` and route lookup remain dirty; a clean route dump combined with a direct-syscall mismatch reveals a partial userspace hook.

## Verification

Collect two consecutive samples without switching networks, then repeat after a force-stop. If the result changes on every run, address the race or network-epoch instability before installing another hiding module.

Use privileged probes only in a separate laboratory run. Do not make Shizuku or root a permanent dependency of a normal user test: under beta policy, lack of privilege is treated as an availability limitation rather than proof that the system is clean.

[Back to the anti-detection index](../)
