---
title: "主路由表与默认路由"
permalink: /help/zh-CN/native/route-table/
---

# 主路由表与默认路由

> **ID：** `ROUTE_TABLE`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 混合

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

原生探针采集 IPv4 和 IPv6 路由及 netlink 元数据。`evaluateRoutes()` 识别默认路由，并按规范化接口与地址族去重。VPN 风格接口上的默认路由被赋予高置信度；未知非标准接口上的默认路由被赋予中等置信度，但当前检查器同样会设置 `detected=true`。匹配 `wlan*`、`rmnet*`、`eth*`、`lo`、`ccmni*`、`ccemni*`、`seth*` 和 `dummy*` 的标准接口仅作为信息报告。

### 精确触发条件

默认路由指向 VPN 模式接口，或指向标准名称允许列表之外的接口时触发。没有默认路由只属于信息性结果。

## 结果含义

VPN 默认路由是强本地信号。非常规接口需要进一步调查，因为 OEM 网络栈、网络共享、CLAT 或企业网络栈都可能使用非标准名称。

**该行如何影响报告：**同一 ID 既用于信息性汇总，也用于可疑输出；最终影响取决于具体详情和所走的检查分支。

## 限制与可能的误报

Android 策略路由远比单一主表复杂；特定 UID 的实际路由可能通过 fwmark 与 `ip rule` 选择。因此干净的默认路由不能排除 VPN，网络切换期间路由转储也可能短暂不稳定。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

无 root 权限时，应调整路由设计，而不是试图改变路由表的显示方式。若需要一台本地状态干净的手机，请使用外部网关。若 VPN 仍通过 `VpnService` 运行，可配置分流，让被测试应用实际经由预期的物理网络出口；但这不能视为隐藏本地路由，因为接口和策略规则仍可能可见。不要在运行中的设备上用 `ip route` 删除路由；Android 与 VPN 服务会重新创建它们，并可能造成连接中断。

### 有 root 权限

在已 root 设备上，后端必须过滤真实数据源，而不能只处理 libc。上游 VPNHide 的内核后端用于覆盖 `ioctl`、netlink 及部分路由/procfs 向量；Zygisk 仍只是有条件的回退方案。不要同时安装 kmod 与 KPM，因为它们可能拦截同一批内核函数。VPNHide Next 声称还覆盖更广的 PMTU/MSS/qdisc/BPF，但这是外部声明，必须在具体内核上重新验证。

### 如何验证结果

```bash
adb shell ip -4 route show table all
adb shell ip -6 route show table all
adb shell ip rule show
```
比较接口、地址族、路由表和默认路由。由于 UID 与 fwmark 路由存在，shell 快照不足以确定某个应用实际使用的路径。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

手工删除默认路由会让设备完全失去网络。错误过滤路由转储还会与接口索引或 Java `LinkProperties` 产生不一致。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**混合。**已根据 `evaluateRoutes()`、规范化逻辑以及标准/VPN 接口列表核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NetworkInterfacePatterns.kt` — 接口名称规则](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- 外部第一方文档或官方项目：[Android VpnService.Builder routes](https://developer.android.com/reference/android/net/VpnService.Builder).
- 外部第一方文档或官方项目：[VPNHide route coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `host-route`, `route-vpn-interface`, `vpn-policy-rules-netlink`, `route-count`.

[返回原生检查参考](../)
