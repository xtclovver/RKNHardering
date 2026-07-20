---
title: β checks — conditions, quorum, and countermeasures
permalink: /help/en/anti-detection/beta/
---

# β checks — conditions, quorum, and countermeasures

β mode in RKNHardering is enabled explicitly. It does not turn every denial or unusual string into `DETECTED`: `PERMISSION_DENIED`, `UNSUPPORTED`, races, malformed/truncated output, and a change of network epoch are suppressed or downgraded. A positive observation must match the source/domain/independence-group registry.

Only two checks can become standalone hard signals: **`beta.vpn_binder`** with authority `BINDER_SERVICE` and **`beta.tun_fd`** with authority `KERNEL_QUERY`. Both require at least two successful samples, the same classification, and a stable epoch. The remaining β checks produce review findings or participate in a quorum of independent groups.

## Without root

The main strategies are the same: an external gateway removes the local VPN; the owner user removes profile context; a disabled proxy/control plane removes local sockets; and the original APK outside a virtual container removes sandbox/hook contradictions. Do not try to “fix” permission denial by granting Shizuku/root access: that expands what the check can inspect and may expose more real signals.

## With root

The β layer is especially good at detecting partial hooks. The framework layer must sanitize Binder consistently, the kernel backend must cover raw netlink/socket/TUN FD paths, and the target process should remain outside Xposed/Zygisk injection. Global root/Shizuku probes run only when explicitly selected. When testing your own protection, enabling them deliberately is useful, but the application should not receive permanent excessive privileges.

## Complete β-ID table

| β-ID | What it observes | Domain / independence group | Without root | With root | What remains |
|---|---|---|---|---|---|
| `beta.vpn_binder` | Binder query to the Android VPN service/state. **Hard authority after a stable repeat.** | `VPN_OR_PROXY` / `android_vpn_service` | External gateway. | System-server framework filtering; keep the target outside Xposed scope. | Binder and native models must agree. |
| `beta.user_profile` | Current user/profile through Android user APIs. | `ISOLATED_PROFILE` / `android_user_manager` | Owner user. | Only correct UID targeting; do not break UserManager. | The truthful profile signal remains. |
| `beta.foreground_user` | Foreground user and whether it matches the process context. | `ISOLATED_PROFILE` / `android_user_manager` | Owner user. | Only correct UID targeting; do not break UserManager. | The truthful profile signal remains. |
| `beta.connectivity_binder` | Connectivity Binder responses compared with the public model. | `NETWORK_PATH_DIVERGENCE` / `android_connectivity` | External gateway. | System-server framework filtering; keep the target outside Xposed scope. | Binder and native models must agree. |
| `beta.netd_netid` | netd/network ID of the active path. | `NETWORK_PATH_DIVERGENCE` / `netd` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.socket_identity` | Socket mark/netId/identity. | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.inet_diag_cookie` | INET_DIAG cookie and socket identity. | `NETWORK_PATH_DIVERGENCE` / `socket_diag` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.route_lookup` | Single route lookup to a control target. | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.policy_rules` | Policy-routing rules for the UID/netId. | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.rtnl_address` | RTNL IPv4/IPv6 address dump. | `NETWORK_PATH_DIVERGENCE` / `kernel_link` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.extended_rtnetlink` | Extended rtnetlink/netd routing context. | `NETWORK_PATH_DIVERGENCE` / `kernel_routing` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.interface_driver` | Network-interface driver/kind/details. | `VPN_OR_PROXY` / `kernel_link` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.interface_traffic` | Interface counters and actual egress. | `NETWORK_PATH_DIVERGENCE` / `active_egress` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.wireguard_genl` | WireGuard generic-netlink state. | `VPN_OR_PROXY` / `kernel_vpn` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.ovpn_genl` | OpenVPN DCO/generic-netlink state. | `VPN_OR_PROXY` / `kernel_vpn` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.xfrm` | XFRM/IPsec states and policies. | `VPN_OR_PROXY` / `kernel_ipsec` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.unix_diag` | Unix-domain sockets of the local control plane. | `VPN_OR_PROXY` / `local_control_plane` | Disable the proxy/control daemon. | UID/namespace block. | A listener/Unix socket may remain visible. |
| `beta.unix_peer_identity` | Unix-socket peer credentials/identity. | `VPN_OR_PROXY` / `local_control_plane` | Disable the proxy/control daemon. | UID/namespace block. | A listener/Unix socket may remain visible. |
| `beta.tun_fd` | Kernel query for a TUN file descriptor. **Hard authority after a stable repeat.** | `VPN_OR_PROXY` / `process_fd` | Remove the local VpnService by using an external gateway. | Kernel filtering; a userspace hook is insufficient. | Hard only after ≥2 stable matching samples. |
| `beta.bpf_netd` | BPF/netd maps and traffic policy. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.cgroup_bpf` | Cgroup BPF attachment/policy. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.netfilter_path` | Netfilter path/redirect state. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.original_destination` | Original destination after transparent redirection. | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.direct_syscall_consistency` | Comparison of libc APIs with direct syscalls. | `HOOK_OR_TAMPERING` / `hook_consistency` | No process injection. | Kernel backend; keep the target outside Zygisk/Xposed. | An alternative path exposes a partial hook. |
| `beta.io_uring_consistency` | Alternative io_uring path compared with a hooked API. | `HOOK_OR_TAMPERING` / `alternate_syscall_path` | No process injection. | Kernel backend; keep the target outside Zygisk/Xposed. | An alternative path exposes a partial hook. |
| `beta.fd_identity` | Type/identity of process file descriptors. | `HOOK_OR_TAMPERING` / `process_fd` | No process injection. | Kernel backend; keep the target outside Zygisk/Xposed. | An alternative path exposes a partial hook. |
| `beta.sandbox_identity.process` | Process identity of a virtual container. | `APP_VIRTUALIZATION` / `process_identity` | Original APK in a normal sandbox. | Do not use a virtual container/repack. | Root does not turn a container into a normal profile. |
| `beta.sandbox_identity.filesystem` | Filesystem layout/identity of the sandbox. | `APP_VIRTUALIZATION` / `filesystem_identity` | Original APK in a normal sandbox. | Do not use a virtual container/repack. | Root does not turn a container into a normal profile. |
| `beta.sandbox_identity.namespace` | Namespace identity of the sandbox/virtualization layer. | `APP_VIRTUALIZATION` / `namespace_identity` | Original APK in a normal sandbox. | Do not use a virtual container/repack. | Root does not turn a container into a normal profile. |
| `beta.fscrypt_identity` | fscrypt/user-storage identity. | `APP_VIRTUALIZATION` / `filesystem_identity` | Original APK in a normal sandbox. | Do not use a virtual container/repack. | Root does not turn a container into a normal profile. |
| `beta.linker_integrity` | Linker/loader integrity and hooks. | `HOOK_OR_TAMPERING` / `loader_integrity` | No process injection. | Kernel backend; keep the target outside Zygisk/Xposed. | An alternative path exposes a partial hook. |
| `beta.dns_netid` | DNS resolver netId/path. | `NETWORK_PATH_DIVERGENCE` / `dns_path` | Make the real route/DNS/TLS consistent; use an external gateway. | Root does not alter the server-side path; exclude MITM. | Network epoch and noise; server context alone is not always hard. |
| `beta.native_dns_resolver` | Native resolver compared with framework DNS. | `NETWORK_PATH_DIVERGENCE` / `dns_path` | Make the real route/DNS/TLS consistent; use an external gateway. | Root does not alter the server-side path; exclude MITM. | Network epoch and noise; server context alone is not always hard. |
| `beta.proxy_selector` | Java ProxySelector/system-proxy consistency. | `VPN_OR_PROXY` / `android_proxy` | Disable the proxy/control daemon. | UID/namespace block. | A listener/Unix socket may remain visible. |
| `beta.transport_matrix` | HTTP/DNS/UDP matrix of canary endpoints. | `NETWORK_PATH_DIVERGENCE` / `active_egress` | Make the real route/DNS/TLS consistent; use an external gateway. | Root does not alter the server-side path; exclude MITM. | Network epoch and noise; server context alone is not always hard. |
| `beta.tls_interception` | TLS interception/certificate path. | `VPN_OR_PROXY` / `tls_path` | Make the real route/DNS/TLS consistent; use an external gateway. | Root does not alter the server-side path; exclude MITM. | Network epoch and noise; server context alone is not always hard. |
| `beta.pktinfo` | IP_PKTINFO/IPv6 pktinfo for inbound/outbound paths. | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.netlink_transitions` | Temporal sequence of netlink network events. | `NETWORK_PATH_DIVERGENCE` / `network_timeline` | External gateway or no local VPN. | Kernel-level filtering for the specific channel; Next advanced is experimental. | Denial is often neutral; kernel/ROM parity differs. |
| `beta.traceroute` | Traceroute/path observation. | `SYSTEM_NETWORK_CONTEXT` / `path_observation` | Make the real route/DNS/TLS consistent; use an external gateway. | Root does not alter the server-side path; exclude MITM. | Network epoch and noise; server context alone is not always hard. |
| `beta.server_fingerprint` | Remote fingerprint of the observed channel. | `SYSTEM_NETWORK_CONTEXT` / `server_observation` | Make the real route/DNS/TLS consistent; use an external gateway. | Root does not alter the server-side path; exclude MITM. | Network epoch and noise; server context alone is not always hard. |
| `beta.root_emulator` | Combined β assessment of root/emulator/device integrity. | `DEVICE_INTEGRITY` / `device_integrity` | Physical stock device without root. | Minimize the root surface; do not partially spoof an emulator. | Review/quorum remains possible. |


## How to read the quorum

Verified by the project: β network evidence becomes `DETECTED` when there are at least two independent network groups, or one β group plus an independent stable network source. Isolation plus a network signal can also produce detected. Tamper/app-virtualization findings require two independent groups. `SYSTEM_NETWORK_CONTEXT`, which contains traceroute/server fingerprint, is excluded from a hard quorum on its own.

Therefore, the correct objective is not to “silence every β row”, but to remove independence between pieces of evidence. For example, clean Binder output does not help while `tun_fd` and route lookup remain dirty; a clean route dump combined with a direct-syscall mismatch reveals a partial userspace hook.

## Verification

Run two consecutive samples without switching networks. Then repeat after a force-stop. If the result changes on every run, fix the race/network epoch first rather than installing another hiding module.

Use the privileged probe in a separate laboratory run. Do not make Shizuku/root a permanent dependency of an ordinary user test: in β policy, lack of privilege is treated as an availability/limitation condition, not as proof of a clean state.

[Back to the table of contents](../)
