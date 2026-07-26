---
title: "主要网络接口枚举"
permalink: /help/zh-CN/native/interface-enumeration/
---

# 主要网络接口枚举

> **ID：** `INTERFACE_ENUMERATION`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 混合

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`NativeInterfaceProbe.collectInterfaces()` 通过原生 `getifaddrs()` 获取接口，按名称合并记录，并加入索引、MTU、flags、ARP 类型和地址。`evaluateInterfaces()` 始终输出接口总数和活动接口数汇总；随后把活动名称与 `tun*`、`tap*`、`wg*`、`ppp*`、`utun*`、`zt*`、`tailscale*`、`svpn*`、`gre*`、`l2tp*` 和 `he-ipv6*` 模式比较。

### 精确触发条件

只有 `isUp=true` 且规范化名称匹配 VPN 模式的接口，才会产生高置信度结果。接口列表为空会产生低置信度 review；普通汇总仅供参考。

## 结果含义

包含具体 VPN 风格名称的行，是 TUN、WireGuard 或 PPP 路径的强本地指标；不含具体名称的汇总不能证明任何结论，只用于比较不同扫描。

**该行如何影响报告：**同一 ID 既用于信息性汇总，也用于可疑输出；最终影响取决于具体详情和所走的检查分支。

## 限制与可能的误报

OEM 或企业网络接口名称可能恰好匹配模式。反向情况也存在：重命名后的隧道可能避开名称模式，但仍会被 TUN/TAP 类型、netlink、路由或 JVM/原生不一致发现。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

最可靠的无 root 方案，是不要在被测试的手机上创建 VPN 接口：把隧道移到路由器、旅行路由器、单独的网关手机或其他网络节点。`VpnService` 的按应用绕过只会改变所选应用使用的路由，但 `establish()` 仍会创建系统 VPN 接口，因此本地接口检查仍可能触发。不使用 TUN 的本地 HTTP/SOCKS 代理模式有时能消除这一特定向量，但会留下监听端口和代理设置，而且无法覆盖忽略代理的应用。

### 有 root 权限

实验室级隐藏通常需要系统 Java 层和一个原生后端。使用 VPNHide 时，应安装 APK，让 Vector/LSPosed 只作用于 `System Framework`，并在 kmod、KPM、Zygisk 中只选一个。对于可能直接使用系统调用或 netlink 的检查，优先选择 kmod/KPM：用户态 Zygisk Hook 可以被绕过，也会在进程中留下痕迹。请先阅读 [VPNHide 覆盖范围表](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)，并只从[官方发布页](https://github.com/okhsunrog/vpnhide/releases/latest)下载构建。VPNHide Next 声称覆盖更广，但也警告可能发生启动循环和内核崩溃，只能在测试设备上验证。

### 如何验证结果

```bash
adb shell ip -details link show
adb shell ip -br address show
adb shell cat /proc/net/dev
```
将名称、UP 状态、索引和 MTU 与 RKNHardering 详情对照。注意 shell UID 不是应用 UID；最终验证应先执行 `adb shell am force-stop com.notcvnt.rknhardering`，再重新启动应用。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

外部网关会改变整个网络路径。Root 或内核过滤可能导致断网、`getifaddrs()` 挂起，或在不兼容内核上出现启动循环。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**混合。**已根据 `evaluateInterfaces()`、`NetworkInterfacePatterns` 和 C++ 接口采集器核验。主信号由目录与检查器单元测试覆盖。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NetworkInterfacePatterns.kt` — 接口名称规则](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[getifaddrs(3)](https://man7.org/linux/man-pages/man3/getifaddrs.3.html).
- 外部第一方文档或官方项目：[Android VpnService](https://developer.android.com/reference/android/net/VpnService).
- 外部第一方文档或官方项目：[VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `tuntap-type`, `jvm-native-mismatch`, `getifaddrs-vpn`, `rtm-getlink-vpn`.

[返回原生检查参考](../)
