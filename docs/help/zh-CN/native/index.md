---
title: RKNHardering 原生检查参考
permalink: /help/zh-CN/native/
---

# RKNHardering 原生检查参考

本参考文档说明 **2.10.0 版中的全部 85 个 `NativeSignalId` 条目**。它不是一组泛泛建议：每个页面都对应具体的 Kotlin 或 C++ 条件，说明该输出行在最终判定中的作用，并明确区分**无需 root**即可采取的措施与**必须使用 root**的措施。

每个信号页面都会标出精确的 API、系统调用、netlink 请求、文件、属性或启发式条件，并说明限制、验证命令、风险与回滚步骤。当前流水线中没有生成器的历史 ID 会被明确标记；`gso_ok` 也会单独说明——C++ 会生成这一行，但不包含 detail 值，因此 2.10.0 的 UI 解析器会将其丢弃。

覆盖全部本地与服务端检查的实用矩阵见[完整反检测指南](../anti-detection/matrix/)。建议先阅读[威胁模型](../anti-detection/threat-model/)和[实验室方法](../anti-detection/lab/)；否则很容易在消除一条输出的同时又制造三条新信号。

## 如何理解信号的作用

- **高**——该行通常会设置 `detected=true`。
- **中**——该行会设置 `needsReview=true`；需要调查，但不能单独作为最终判定。
- **低**——没有检测阈值的遥测或基线数据。
- **混合**——同一 ID 服务于多个分支，而各分支的影响不同。
- **目录项/兼容性**——ID 仍然存在，但 2.10.0 没有专用的活动生成器，或存在解析器缺口。

这些页面中的 ADB 命令只用于辅助诊断。`adb shell` 运行在不同的 UID 与 SELinux 域中，因此其输出不能替代在 RKNHardering 内重新执行检查。所有 root 或内核级实验都应先在测试设备上进行，并提前保存 boot 镜像，确认可以从 recovery 禁用模块。

## 网络接口

| 页面 | ID | 作用 | 状态 | 页面说明 |
|---|---|---|---|---|
| [interface-enumeration](./interface-enumeration/) | `INTERFACE_ENUMERATION` | 混合 | 已启用 | 主要网络接口枚举 |
| [tuntap-type](./tuntap-type/) | `TUNTAP_TYPE` | 高 | 已启用 | 不依赖名称的 ARPHRD_TUNNEL/TUN-TAP 接口类型检查 |
| [ipsec-interface](./ipsec-interface/) | `IPSEC_INTERFACE` | 低 | 已启用 | IPsec/XFRM 接口 |
| [jvm-native-mismatch](./jvm-native-mismatch/) | `JVM_NATIVE_MISMATCH` | 混合 | 已启用 | Java `NetworkInterface` 与原生 `getifaddrs()` 之间的不一致 |
| [inet6-vpn-interface](./inet6-vpn-interface/) | `INET6_VPN_INTERFACE` | 高 | 已启用 | 针对固定 VPN 接口的旧版 ioctl 检查 |
| [arp-vpn-interface](./arp-vpn-interface/) | `ARP_VPN_INTERFACE` | 目录项/兼容性 | 为兼容性保留；2.10.0 无专用生成器 | 保留的旧版 VPN 接口 ARP ID |
| [hidden-mac-neighbors](./hidden-mac-neighbors/) | `HIDDEN_MAC_NEIGHBORS` | 高 | 已启用 | MAC 地址为全零或广播地址的 ARP 条目 |
| [sysfs-vpn-leak](./sysfs-vpn-leak/) | `SYSFS_VPN_LEAK` | 高 | 已启用 | 可通过 sysfs 与 proc/sys 访问的 VPN 接口 |
| [getifaddrs-vpn](./getifaddrs-vpn/) | `GETIFADDRS_VPN` | 高 | 已启用 | `getifaddrs()` 中的固定 VPN 名称 |
| [sysclassnet-vpn](./sysclassnet-vpn/) | `SYSCLASSNET_VPN` | 高 | 已启用 | `/sys/class/net` 中的固定 VPN 接口 |
| [rtm-getlink-vpn](./rtm-getlink-vpn/) | `RTM_GETLINK_VPN` | 高 | 已启用 | netlink `RTM_GETLINK` 中的 VPN 接口 |
| [proc-if-inet6-vpn](./proc-if-inet6-vpn/) | `PROC_IF_INET6_VPN` | 高 | 已启用 | `/proc/net/if_inet6` 中的 VPN 接口 |
| [proc-net-dev-vpn](./proc-net-dev-vpn/) | `PROC_NET_DEV_VPN` | 高 | 已启用 | `/proc/net/dev` 中的 VPN 接口计数器 |
| [ifindexname-vpn](./ifindexname-vpn/) | `IFINDEXNAME_VPN` | 高 | 已启用 | `if_indextoname()` 返回的 VPN 名称 |

## 路由与网络栈

| 页面 | ID | 作用 | 状态 | 页面说明 |
|---|---|---|---|---|
| [route-table](./route-table/) | `ROUTE_TABLE` | 混合 | 已启用 | 主路由表与默认路由 |
| [host-route](./host-route/) | `HOST_ROUTE` | 中 | 已启用 | 经物理接口的公网 /32 或 /128 主机路由 |
| [route-vpn-interface](./route-vpn-interface/) | `ROUTE_VPN_INTERFACE` | 高 | 已启用 | 经固定 VPN 接口名称的旧版路由 |
| [sysctl-forwarding](./sysctl-forwarding/) | `SYSCTL_FORWARDING` | 中 | 已启用 | 已启用 IPv4 转发 |
| [sysctl-rp-filter](./sysctl-rp-filter/) | `SYSCTL_RP_FILTER` | 中 | 已启用 | 已全局禁用反向路径过滤 |
| [vpn-policy-rules](./vpn-policy-rules/) | `VPN_POLICY_RULES` | 高 | 已启用 | VPN 接口上的旧版非标准 IPv4 路由 |
| [vpn-qdisc](./vpn-qdisc/) | `VPN_QDISC` | 中 | 已启用 | 历史 qdisc 名称下的 `tun0`/`wg0` 流量计数器 |
| [tcp-mss-low](./tcp-mss-low/) | `TCP_MSS_LOW` | 高 | 已启用 | 本地连接上的低 TCP MSS |
| [bpf-map-accessible](./bpf-map-accessible/) | `BPF_MAP_ACCESSIBLE` | 高 | 已启用 | 可访问 netd 的 BPF 接口索引映射 |
| [proc-ipv6-route-vpn](./proc-ipv6-route-vpn/) | `PROC_IPV6_ROUTE_VPN` | 高 | 已启用 | `/proc/net/ipv6_route` 中的 VPN 接口 |
| [vpn-policy-rules-netlink](./vpn-policy-rules-netlink/) | `VPN_POLICY_RULES_NETLINK` | 高 | 已启用 | 通过 `RTM_GETRULE` 发现的可疑策略规则 |
| [fib-trie-denied](./fib-trie-denied/) | `FIB_TRIE_DENIED` | 中 | 已启用 | 访问 `/proc/net/fib_trie` 被拒绝或失败 |
| [deep-vpn-qdisc](./deep-vpn-qdisc/) | `DEEP_VPN_QDISC` | 目录项/兼容性 | 为兼容性保留；2.10.0 无专用生成器 | 保留的深度 qdisc ID |
| [deep-bpf-map-accessible](./deep-bpf-map-accessible/) | `DEEP_BPF_MAP_ACCESSIBLE` | 目录项/兼容性 | 为兼容性保留；2.10.0 无专用生成器 | 保留的深度 BPF 映射可访问性 ID |
| [route-count](./route-count/) | `ROUTE_COUNT` | 低 | 已启用 | 信息性的路由与接口数量 |
| [trim-oracle](./trim-oracle/) | `TRIM_ORACLE` | 中 | 已启用 | `if_indextoname()` 与 `RTM_GETLINK` 的接口数量不一致 |
| [pmtu-mss-combined](./pmtu-mss-combined/) | `PMTU_MSS_COMBINED` | 低 | 已启用 | 本地 127.0.0.1:443 连接的 `TCP_INFO` MSS |
| [udp-pmtu-ok](./udp-pmtu-ok/) | `UDP_PMTU_OK` | 低 | 已启用 | 成功向 127.0.0.1:53 发送 1500 字节 UDP 数据 |
| [udp-pmtu-fail](./udp-pmtu-fail/) | `UDP_PMTU_FAIL` | 中 | 已启用 | 向回环地址发送 1500 字节 UDP 数据报失败 |
| [normal-pmtu](./normal-pmtu/) | `NORMAL_PMTU` | 低 | 已启用 | 首个非隧道接口的 MTU |
| [timing-oracle](./timing-oracle/) | `TIMING_ORACLE` | 低 | 已启用 | 通过 `CNTVCT_EL0` 测量 ARM64 socket/sendto 时序 |
| [backpressure](./backpressure/) | `BACKPRESSURE` | 低 | 已启用 | 回环 UDP 洪泛：50,000 个 1,400 字节数据包 |
| [gso-failed](./gso-failed/) | `GSO_FAILED` | 低 | 已启用 | `setsockopt()` 拒绝 `UDP_SEGMENT` |
| [gso-send-failed](./gso-send-failed/) | `GSO_SEND_FAILED` | 低 | 已启用 | `UDP_SEGMENT` 已接受，但发送 4,800 字节失败 |
| [gso-ok](./gso-ok/) | `GSO_OK` | 目录项/兼容性 | 原生生成器存在，但当前 UI 解析器丢弃该行 | UDP GSO 被接受，且回环发送成功 |
| [hardware-timestamp](./hardware-timestamp/) | `HW_TIMESTAMP` | 低 | 已启用 | 在回环接口上成功配置 `SIOCSHWTSTAMP` |
| [traceroute-denied](./traceroute-denied/) | `TRACEROUTE_DENIED` | 中 | 已启用 | TTL=1 的回环 UDP 发送返回 `EACCES` |

## VPN 痕迹与套接字

| 页面 | ID | 作用 | 状态 | 页面说明 |
|---|---|---|---|---|
| [vpn-property](./vpn-property/) | `VPN_PROPERTY` | 高 | 已启用 | 旧版 VPN/DNS 系统属性 |
| [dns-property](./dns-property/) | `DNS_PROPERTY` | 目录项/兼容性 | 为兼容性保留；2.10.0 无专用生成器 | 保留的 `dns_prop` ID |
| [vpn-file](./vpn-file/) | `VPN_FILE` | 目录项/兼容性 | 为兼容性保留；2.10.0 无专用生成器 | 保留的通用 VPN 文件 ID |
| [tcp-vpn-port](./tcp-vpn-port/) | `TCP_VPN_PORT` | 目录项/兼容性 | 为兼容性保留；2.10.0 无专用生成器 | 保留的旧版 TCP VPN 端口 ID |
| [udp-vpn-port](./udp-vpn-port/) | `UDP_VPN_PORT` | 目录项/兼容性 | 为兼容性保留；2.10.0 无专用生成器 | 保留的旧版 UDP VPN 端口 ID |
| [established-vpn-socket](./established-vpn-socket/) | `ESTABLISHED_VPN_SOCKET` | 中 | 已启用 | 常见 VPN 端口上的已建立 TCP 连接 |
| [so-bindtodevice](./so-bindtodevice/) | `SO_BINDTODEVICE` | 中 | 已启用 | 历史 `SO_BINDTODEVICE` 名称下的旧版套接字身份检查 |
| [loopback-port-conflict](./loopback-port-conflict/) | `LOOPBACK_PORT_CONFLICT` | 高 | 已启用 | 127.0.0.1 上被占用的 TCP 端口 |
| [ip-recverr](./ip-recverr/) | `IP_RECVERR` | 目录项/兼容性 | 为兼容性保留；2.10.0 无专用生成器 | 保留的阳性 `IP_RECVERR` ID |
| [inet-diag-denied](./inet-diag-denied/) | `INET_DIAG_DENIED` | 中 | 已启用 | 应用无法使用 `NETLINK_SOCK_DIAG` |
| [bindtodevice-leak](./bindtodevice-leak/) | `BINDTODEVICE_LEAK` | 高 | 已启用 | `SO_BINDTODEVICE` 确认 VPN 接口真实存在 |
| [getsockname-leak](./getsockname-leak/) | `GETSOCKNAME_LEAK` | 高 | 已启用 | 未绑定 UDP 套接字立即获得私有 IPv4 地址 |
| [udp-port-conflict-physical](./udp-port-conflict-physical/) | `UDP_PORT_CONFLICT_PHYSICAL` | 高 | 已启用 | 物理 IPv4 地址上的 VPN 相关 UDP 端口被占用 |

## 进程 Hook 与完整性

| 页面 | ID | 作用 | 状态 | 页面说明 |
|---|---|---|---|---|
| [hook-markers](./hook-markers/) | `HOOK_MARKERS` | 中 | 已启用 | `/proc/self/maps` 中具名的注入标记 |
| [rwx-memory-regions](./rwx-memory-regions/) | `RWX_MEMORY_REGIONS` | 低 | 已启用 | 大型 RWX 内存区域 |
| [library-integrity](./library-integrity/) | `LIBRARY_INTEGRITY` | 中 | 已启用 | 关键 libc 符号的来源 |
| [vpnhide](./vpnhide/) | `VPNHIDE` | 混合 | 已启用 | VPNHide 痕迹与回归 Oracle |
| [lsposed](./lsposed/) | `LSPOSED` | 中 | 已启用 | LSPosed/Vector 类框架的文件痕迹 |
| [hook-property](./hook-property/) | `HOOK_PROPERTY` | 高 | 已启用 | LSPosed/Magisk/Zygote Hook 系统属性 |

## Root 与系统状态

| 页面 | ID | 作用 | 状态 | 页面说明 |
|---|---|---|---|---|
| [root-indicators](./root-indicators/) | `ROOT_INDICATORS` | 结构性 | 已启用 | 原生 root 指标汇总 |
| [root-su-binary](./root-su-binary/) | `ROOT_SU_BINARY` | 中 | 已启用 | 已知路径中的 `su` 文件 |
| [root-property](./root-property/) | `ROOT_PROPERTY` | 中 | 已启用 | 可疑 root/调试系统属性 |
| [root-management](./root-management/) | `ROOT_MANAGEMENT` | 中 | 已启用 | Root 管理器目录与文件 |
| [root-system-rw](./root-system-rw/) | `ROOT_SYSTEM_RW` | 中 | 已启用 | 对 `/system` 具有写权限 |
| [root-suspicious-mount](./root-suspicious-mount/) | `ROOT_SUSPICIOUS_MOUNT` | 中 | 已启用 | 包含 Magisk/core-only 与 root 标记的挂载行 |
| [root-overlay-mount](./root-overlay-mount/) | `ROOT_OVERLAY_MOUNT` | 中 | 已启用 | 覆盖 `/system` 或 `/vendor` 的 overlay 挂载 |
| [root-selinux](./root-selinux/) | `ROOT_SELINUX` | 中 | 已启用 | SELinux permissive 模式或 enforce 文件不可访问 |
| [root-uid](./root-uid/) | `ROOT_UID` | 中 | 已启用 | 进程 UID/EUID/GID 等于 0 |
| [root-magisk-property](./root-magisk-property/) | `ROOT_MAGISK_PROPERTY` | 中 | 已启用 | Magisk 专用系统属性 |

## 模拟器、用户资料与隔离

| 页面 | ID | 作用 | 状态 | 页面说明 |
|---|---|---|---|---|
| [emulator-indicators](./emulator-indicators/) | `EMULATOR_INDICATORS` | 结构性 | 已启用 | 模拟器指标汇总 |
| [emulator-qemu-property](./emulator-qemu-property/) | `EMULATOR_QEMU_PROPERTY` | 中 | 已启用 | QEMU 系统属性 |
| [emulator-qemu-pipe](./emulator-qemu-pipe/) | `EMULATOR_QEMU_PIPE` | 中 | 已启用 | QEMU/Genymotion 设备与套接字 |
| [emulator-goldfish](./emulator-goldfish/) | `EMULATOR_GOLDFISH` | 中 | 已启用 | hardware 与 board 属性中的 Goldfish/Ranchu |
| [emulator-qemu-driver](./emulator-qemu-driver/) | `EMULATOR_QEMU_DRIVER` | 中 | 已启用 | `/proc/tty/drivers` 中的 Goldfish |
| [emulator-bluestacks](./emulator-bluestacks/) | `EMULATOR_BLUESTACKS` | 中 | 已启用 | BlueStacks 文件痕迹 |
| [emulator-build-profile](./emulator-build-profile/) | `EMULATOR_BUILD` | 中 | 已启用 | `Build.FINGERPRINT`/`MODEL`/`HARDWARE`/`PRODUCT` 启发式检查 |
| [isolation-profile](./isolation-profile/) | `ISOLATION_PROFILE` | 结构性 | 已启用 | Android 用户/资料隔离汇总 |
| [isolation-clone](./isolation-clone/) | `ISOLATION_CLONE` | 中 | 已启用 | OEM 克隆/双开用户 ID |
| [isolation-secondary-user](./isolation-secondary-user/) | `ISOLATION_SECONDARY_USER` | 中 | 已启用 | 运行在主用户之外 |
| [isolation-work-profile](./isolation-work-profile/) | `ISOLATION_WORK_PROFILE` | 中 | 已启用 | RKNHardering 本身是 profile owner |

## 服务级信号

| 页面 | ID | 作用 | 状态 | 页面说明 |
|---|---|---|---|---|
| [native-library](./native-library/) | `NATIVE_LIBRARY` | 可用性 | 已启用 | 加载原生检查库 |
| [syscall-unavailable](./syscall-unavailable/) | `SYSCALL_UNAVAILABLE` | 可用性 | 已启用 | 原生系统调用/套接字探针不可用 |
| [general-diagnostics](./general-diagnostics/) | `GENERAL_DIAGNOSTICS` | 结构性 | 已启用 | 深度原生检测器没有返回任何行 |
| [unknown-signals](./unknown-signals/) | `UNKNOWN` | 结构性 | 已启用 | 未知或未映射的原生 kind |

## Root 组件的官方下载来源

- [VPNHide 发布页](https://github.com/okhsunrog/vpnhide/releases/latest)及其[覆盖范围表](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)。
- [VPNHide Next 发布页](https://github.com/soranerai/vpnhide_next/releases/latest)：带有更激进内核 Hook 的实验性分支。
- 用于框架/Xposed 层的 [Vector 发布页](https://github.com/JingMatrix/Vector/releases/latest)。
- [Magisk 发布页](https://github.com/topjohnwu/Magisk/releases/latest)、[KernelSU Next 发布页](https://github.com/KernelSU-Next/KernelSU-Next/releases/latest)和 [APatch 发布页](https://github.com/bmax121/APatch/releases/latest)。

APK 和 ZIP 只能从官方仓库或发布页下载。请验证签名或哈希，不要以 root 运行来源不明的安装脚本，也不要同时安装会拦截相同内核函数的多个原生后端。

[返回语言索引](../)
