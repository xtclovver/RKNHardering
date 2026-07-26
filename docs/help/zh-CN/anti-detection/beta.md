---
title: Beta 检查——条件、法定人数与应对措施
permalink: /help/zh-CN/anti-detection/beta/
---

# Beta 检查——条件、法定人数与应对措施

RKNHardering 的 beta 模式必须显式启用。它不会把每一次拒绝访问或异常条目都转成 `DETECTED`：`PERMISSION_DENIED`、`UNSUPPORTED`、竞态、格式错误或截断的结果，以及网络 epoch 变化都会被抑制或降级。阳性观测必须与已注册的来源、证据域和独立分组相匹配。

只有两项检查可以成为独立硬信号：具有 `BINDER_SERVICE` 判定权的 **`beta.vpn_binder`**，以及具有 `KERNEL_QUERY` 判定权的 **`beta.tun_fd`**。两者都要求至少两个成功样本、相同分类和稳定 epoch。其他 beta 检查只会产生待复核发现，或参与多个独立分组组成的法定人数。

## 无 root

主要策略仍然不变：外部网关会移除本地 VPN；所有者用户会消除资料上下文；禁用代理或控制面会移除本地套接字；在正常沙箱中运行原始 APK 会消除沙箱与 Hook 不一致。不要通过授予 Shizuku 或 root 来“修复”权限拒绝。这样只会扩大探测器的访问范围，并可能暴露更多真实信号。

## 有 root

Beta 层特别擅长发现只覆盖一部分路径的 Hook。框架必须一致地过滤 Binder，内核后端必须覆盖原始 netlink、套接字和 TUN-FD 路径，而目标进程应保持不接受 Xposed 或 Zygisk 注入。全局 root 或 Shizuku 探测只会在显式选择后运行。它们可以用于受控环境中验证你自己的防护，但应用不应永久保留不必要的高权限。

## 完整 Beta ID 表

| Beta ID | 观测内容 | 证据域/独立分组 | 无 root | 有 root | 仍然存在的内容 |
|---|---|---|---|---|---|
| `beta.vpn_binder` | 向 Android VPN 服务或状态发起 Binder 查询。 **稳定重复后具有独立硬判定权。** | `VPN_OR_PROXY` / `android_vpn_service` | 使用外部网关。 | 在 `system_server` 中应用框架过滤，并把目标排除在 Xposed 作用域之外。 | Binder 与原生模型必须一致。 |
| `beta.user_profile` | 通过 Android 用户 API 获取当前用户或用户资料。 | `ISOLATED_PROFILE` / `android_user_manager` | 在所有者用户下运行。 | 只针对正确 UID；不要破坏 `UserManager`。 | 真实的用户资料信号仍会保留。 |
| `beta.foreground_user` | 前台用户及其与进程上下文的一致性。 | `ISOLATED_PROFILE` / `android_user_manager` | 在所有者用户下运行。 | 只针对正确 UID；不要破坏 `UserManager`。 | 真实的用户资料信号仍会保留。 |
| `beta.connectivity_binder` | 把 Connectivity Binder 响应与公共模型比较。 | `NETWORK_PATH_DIVERGENCE` / `android_connectivity` | 使用外部网关。 | 在 `system_server` 中应用框架过滤，并把目标排除在 Xposed 作用域之外。 | Binder 与原生模型必须一致。 |
| `beta.netd_netid` | 活动路径的 netd 或网络 ID。 | `NETWORK_PATH_DIVERGENCE` / `netd` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.socket_identity` | 套接字 mark、网络 ID 与身份。 | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.inet_diag_cookie` | INET_DIAG cookie 与套接字身份。 | `NETWORK_PATH_DIVERGENCE` / `socket_diag` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.route_lookup` | 对控制目标执行一次路由查询。 | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.policy_rules` | 针对 UID 或网络 ID 的策略路由规则。 | `NETWORK_PATH_DIVERGENCE` / `kernel_route` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.rtnl_address` | IPv4 与 IPv6 RTNL 地址转储。 | `NETWORK_PATH_DIVERGENCE` / `kernel_link` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.extended_rtnetlink` | 扩展 rtnetlink 与 netd 路由上下文。 | `NETWORK_PATH_DIVERGENCE` / `kernel_routing` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.interface_driver` | 网络接口驱动、kind 与详细属性。 | `VPN_OR_PROXY` / `kernel_link` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.interface_traffic` | 接口计数器与真实出口。 | `NETWORK_PATH_DIVERGENCE` / `active_egress` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.wireguard_genl` | WireGuard generic-netlink 状态。 | `VPN_OR_PROXY` / `kernel_vpn` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.ovpn_genl` | OpenVPN DCO 或 generic-netlink 状态。 | `VPN_OR_PROXY` / `kernel_vpn` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.xfrm` | XFRM/IPsec 状态与策略。 | `VPN_OR_PROXY` / `kernel_ipsec` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.unix_diag` | 本地控制面的 Unix 域套接字。 | `VPN_OR_PROXY` / `local_control_plane` | 关闭代理或控制守护进程。 | 按 UID 或命名空间阻断。 | 监听器或 Unix 套接字仍可能可见。 |
| `beta.unix_peer_identity` | Unix 套接字上的对端凭据与身份。 | `VPN_OR_PROXY` / `local_control_plane` | 关闭代理或控制守护进程。 | 按 UID 或命名空间阻断。 | 监听器或 Unix 套接字仍可能可见。 |
| `beta.tun_fd` | 对 TUN 文件描述符执行内核查询。 **稳定重复后具有独立硬判定权。** | `VPN_OR_PROXY` / `process_fd` | 使用外部网关移除本地 `VpnService`。 | 在内核中过滤；用户态 Hook 不够。 | 只有至少两次稳定且一致的样本后，才能视为硬证据。 |
| `beta.bpf_netd` | BPF/netd 映射与流量策略。 | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.cgroup_bpf` | Cgroup BPF 挂载与策略。 | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.netfilter_path` | Netfilter 路径或重定向状态。 | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.original_destination` | 透明重定向后的原始目标。 | `NETWORK_PATH_DIVERGENCE` / `packet_policy` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.direct_syscall_consistency` | 比较 libc API 与直接系统调用。 | `HOOK_OR_TAMPERING` / `hook_consistency` | 避免进程注入。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `beta.io_uring_consistency` | 把替代 io_uring 路径与可能被 Hook 的 API 比较。 | `HOOK_OR_TAMPERING` / `alternate_syscall_path` | 避免进程注入。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `beta.fd_identity` | 进程文件描述符的类型与身份。 | `HOOK_OR_TAMPERING` / `process_fd` | 避免进程注入。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `beta.sandbox_identity.process` | 虚拟容器中的进程身份。 | `APP_VIRTUALIZATION` / `process_identity` | 在普通沙箱中使用原始 APK。 | 不要使用虚拟容器或重新打包的 APK。 | Root 无法把容器变成普通用户资料。 |
| `beta.sandbox_identity.filesystem` | 沙箱文件系统布局与身份。 | `APP_VIRTUALIZATION` / `filesystem_identity` | 在普通沙箱中使用原始 APK。 | 不要使用虚拟容器或重新打包的 APK。 | Root 无法把容器变成普通用户资料。 |
| `beta.sandbox_identity.namespace` | 沙箱或虚拟化命名空间身份。 | `APP_VIRTUALIZATION` / `namespace_identity` | 在普通沙箱中使用原始 APK。 | 不要使用虚拟容器或重新打包的 APK。 | Root 无法把容器变成普通用户资料。 |
| `beta.fscrypt_identity` | fscrypt 与用户存储身份。 | `APP_VIRTUALIZATION` / `filesystem_identity` | 在普通沙箱中使用原始 APK。 | 不要使用虚拟容器或重新打包的 APK。 | Root 无法把容器变成普通用户资料。 |
| `beta.linker_integrity` | Linker/loader 完整性与 Hook。 | `HOOK_OR_TAMPERING` / `loader_integrity` | 避免进程注入。 | 使用内核后端，并把目标排除在 Zygisk/Xposed 之外。 | 替代路径会暴露局部 Hook。 |
| `beta.dns_netid` | DNS 解析器网络 ID 与路径。 | `NETWORK_PATH_DIVERGENCE` / `dns_path` | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.native_dns_resolver` | 原生解析器与框架 DNS 的对比。 | `NETWORK_PATH_DIVERGENCE` / `dns_path` | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.proxy_selector` | Java `ProxySelector` 与系统代理一致性。 | `VPN_OR_PROXY` / `android_proxy` | 关闭代理或控制守护进程。 | 按 UID 或命名空间阻断。 | 监听器或 Unix 套接字仍可能可见。 |
| `beta.transport_matrix` | 针对 canary 端点的 HTTP、DNS 与 UDP 矩阵。 | `NETWORK_PATH_DIVERGENCE` / `active_egress` | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.tls_interception` | TLS 拦截与证书路径。 | `VPN_OR_PROXY` / `tls_path` | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.pktinfo` | 入站或出站路径的 `IP_PKTINFO`/IPv6 packet info。 | `NETWORK_PATH_DIVERGENCE` / `kernel_socket` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.netlink_transitions` | netlink 网络事件的时间顺序。 | `NETWORK_PATH_DIVERGENCE` / `network_timeline` | 使用外部网关，或移除本地 VPN。 | 针对精确通道应用内核级过滤；VPNHide Next 的高级覆盖仍属实验性。 | 拒绝访问通常属于中性结果，且内核/ROM 一致性会变化。 |
| `beta.traceroute` | Traceroute 与路径观察。 | `SYSTEM_NETWORK_CONTEXT` / `path_observation` | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.server_fingerprint` | 远端观察路径的指纹。 | `SYSTEM_NETWORK_CONTEXT` / `server_observation` | 让真实路由、DNS 与 TLS 路径一致，或使用外部网关。 | Root 无法改变服务端路径；把目标排除在 MITM 之外。 | 网络 epoch 变化与噪声会影响结果；仅有服务端上下文并不总是硬证据。 |
| `beta.root_emulator` | 对 root、模拟器与设备完整性的 β 聚合评估。 | `DEVICE_INTEGRITY` / `device_integrity` | 使用无 root 的原厂物理设备。 | 尽量缩小 root 表面，不要局部伪装模拟器。 | 仍可能进入待复核状态或形成 quorum。 |

## 如何理解法定人数

**本项目已核验：**当 beta 网络证据来自至少两个独立网络分组，或来自一个 beta 分组加一个独立的稳定网络来源时，结果会变为 `DETECTED`。隔离信号与网络信号组合也可能产生检测。篡改和应用虚拟化要求两个独立分组。包含 traceroute 与服务端指纹的 `SYSTEM_NETWORK_CONTEXT` 无法单独形成硬法定人数。

因此，正确目标不是“让每一行 beta 检查都沉默”，而是消除相互独立的佐证。Binder 结果干净并没有帮助，如果 `tun_fd` 和路由查询仍然异常；同样，干净的路由 dump 与直接系统调用不一致组合，会暴露局部用户态 Hook。

## 验证

在不切换网络的情况下采集两个连续样本，然后强制停止应用并再次运行。如果每次结果都变化，应先解决竞态或网络 epoch 不稳定，再安装其他隐藏模块。

高权限探测只能放在单独的实验室运行中。不要让 Shizuku 或 root 成为普通用户测试的永久依赖：在 beta 策略中，缺少权限只被视为可用性限制，而不是系统干净的证明。

[返回反检测指南首页](../)
