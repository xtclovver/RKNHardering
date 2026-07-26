---
title: "`/proc/net/ipv6_route` 中的 VPN 接口"
permalink: /help/zh-CN/native/proc-ipv6-route-vpn/
---

# `/proc/net/ipv6_route` 中的 VPN 接口

> **ID：** `PROC_IPV6_ROUTE_VPN`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针先读取 `/proc/net/ipv6_route`，再读取 `/proc/self/net/ipv6_route`。每行被拆分为十个字段，第十个字段视为接口名称；`tun0`、`tun1`、`utun0`、`wg0`、`ppp0` 和 `xfrm0` 的匹配会增加计数。

### 精确触发条件

至少有一条 IPv6 路由记录使用固定 VPN 接口名称。

## 结果含义

IPv6 路由表直接引用了 VPN 风格接口。禁用 IPv4 并不能关闭这一路径。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

procfs 格式与内核相关，也可能被 SELinux 阻止。探针只报告数量，不报告目标、前缀或路由表，因此分析需要原始快照；非标准接口名称不会被发现。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无 root 权限时，应调整路由设计，而不是试图改变路由表的显示方式。若需要一台本地状态干净的手机，请使用外部网关。若 VPN 仍通过 `VpnService` 运行，可配置分流，让被测试应用实际经由预期的物理网络出口；但这不能视为隐藏本地路由，因为接口和策略规则仍可能可见。不要在运行中的设备上用 `ip route` 删除路由；Android 与 VPN 服务会重新创建它们，并可能造成连接中断。 在资料中禁用 IPv6 会减少暴露面，但也可能让 IPv6 流量绕过 VPN，或完全失去 IPv6 连接。请先在独立网络上验证。

### 有 root 权限

在已 root 设备上，后端必须过滤真实数据源，而不能只处理 libc。上游 VPNHide 的内核后端用于覆盖 `ioctl`、netlink 及部分路由/procfs 向量；Zygisk 仍只是有条件的回退方案。不要同时安装 kmod 与 KPM，因为它们可能拦截同一批内核函数。VPNHide Next 声称还覆盖更广的 PMTU/MSS/qdisc/BPF，但这是外部声明，必须在具体内核上重新验证。 过滤器必须一致覆盖 procfs 和 IPv6 `RTM_GETROUTE`。只替换 `/proc/net/ipv6_route` 会让 netlink 转储继续暴露。

### 如何验证结果

```bash
adb shell 'cat /proc/net/ipv6_route 2>/dev/null || cat /proc/self/net/ipv6_route 2>/dev/null'
adb shell ip -6 route show table all
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

手工删除 IPv6 路由可能破坏 DNS 或 NAT64，而且 VPN 重建后不会持续生效。有缺陷的内核 seq-file Hook 可能损坏 procfs 读取。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**高。**已根据两个 proc 路径、字段 `[9]` 和六个固定名称核验；该 `kind` 为高置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[/proc/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- 外部第一方文档或官方项目：[rtnetlink routes](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- 外部第一方文档或官方项目：[VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `route-table`, `rtm-getlink-vpn`, `proc-if-inet6-vpn`.

[返回原生检查参考](../)
