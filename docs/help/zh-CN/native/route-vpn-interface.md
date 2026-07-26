---
title: "经固定 VPN 接口名称的旧版路由"
permalink: /help/zh-CN/native/route-vpn-interface/
---

# 经固定 VPN 接口名称的旧版路由

> **ID：** `ROUTE_VPN_INTERFACE`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectVpnRoutes()` 读取 `/proc/net/route`，统计接口为 `tun0`、`tun1`、`utun0`、`ppp0`、`wg0` 和 `wg1` 的记录；计数大于 0 时生成 `route_vpn_iface|vpn_routes=N`。这是旧版高置信度信号。

### 精确触发条件

`/proc/net/route` 中至少有一行使用固定 VPN 接口名称。

## 结果含义

这是直接的 IPv4 procfs 泄漏；无论该路由是否为默认路由，都会触发。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

较新的 Android 版本通常由 SELinux 阻止普通应用读取 procfs；此时没有该行并不表示系统干净。IPv6 和 netlink 由其他信号覆盖。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无 root 权限时，应调整路由设计，而不是试图改变路由表的显示方式。若需要一台本地状态干净的手机，请使用外部网关。若 VPN 仍通过 `VpnService` 运行，可配置分流，让被测试应用实际经由预期的物理网络出口；但这不能视为隐藏本地路由，因为接口和策略规则仍可能可见。不要在运行中的设备上用 `ip route` 删除路由；Android 与 VPN 服务会重新创建它们，并可能造成连接中断。

### 有 root 权限

在已 root 设备上，后端必须过滤真实数据源，而不能只处理 libc。上游 VPNHide 的内核后端用于覆盖 `ioctl`、netlink 及部分路由/procfs 向量；Zygisk 仍只是有条件的回退方案。不要同时安装 kmod 与 KPM，因为它们可能拦截同一批内核函数。VPNHide Next 声称还覆盖更广的 PMTU/MSS/qdisc/BPF，但这是外部声明，必须在具体内核上重新验证。 上游 VPNHide 明确记录了 `/proc/net/route` 过滤；当 ROM 的 SELinux 允许读取时，内核后端必须覆盖原始 open/read 访问。

### 如何验证结果

```bash
adb shell cat /proc/net/route 2>&1 | head -80
```
`permission denied` 表示 shell 无法访问该路径；应用可能得到不同结果。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

procfs 不能像普通文件一样编辑。删除路由会中断网络连接。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**高。**已根据 `/proc/net/route` 解析器和固定名称列表核验；该 `kind` 为高置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- 外部第一方文档或官方项目：[VPNHide proc route coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `route-table`, `proc-ipv6-route-vpn`, `vpn-policy-rules`.

[返回原生检查参考](../)
