---
title: "Java `NetworkInterface` 与原生 `getifaddrs` 结果不一致"
permalink: /help/zh-CN/native/jvm-native-mismatch/
---

# Java `NetworkInterface` 与原生 `getifaddrs` 结果不一致

> **ID：** `JVM_NATIVE_MISMATCH`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 混合

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

检查器建立两个独立快照：C/C++ `getifaddrs()` 与 Java `NetworkInterface.getNetworkInterfaces()`。它比较名称集合、同一接口的索引和地址集合。VPN 风格名称只出现在其中一层时属于高置信度；普通索引或地址差异会产生中等置信度 review。

### 精确触发条件

高：VPN 风格接口只对原生代码或只对 JVM 可见。中：任何其他接口缺失、ifindex 不同，或双方非空地址集合不一致。

## 结果含义

这一信号更多表示隐藏不完整或 Hook 只作用于一个 API，而不只是表示 VPN 本身。因此，只覆盖 Java 而不覆盖原生层，或只覆盖 libc 而不覆盖框架层，都会形成 oracle。

**该行如何影响报告：**同一 ID 既用于信息性汇总，也用于可疑输出；最终影响取决于具体详情和所走的检查分支。

## 限制与可能的误报

两个快照按顺序采集，因此在网络切换、Wi-Fi/蜂窝交接、CLAT 变化或 IPv6 地址短暂变化时，可能出现真实竞态。应在稳定网络上重复测试。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

测试期间保持网络稳定，并避免在 Wi-Fi 与移动数据之间切换。若 VPN 仍在本机运行，普通无 root 软件无法让两个系统 API 一致地隐藏另一个应用的接口；外部网关可以消除根本原因。

### 有 root 权限

必须同时覆盖两层：`system_server` 中的框架过滤，以及原生/内核过滤。不要把 RKNHardering 自身加入 Xposed 作用域；这可能清理 Java 列表，却同时引入进程 Hook。修改后要验证名称、索引和地址，而不只是确认 `tun0` 消失。

### 如何验证结果

```bash
adb shell ip -o address show
adb shell ip -o link show
```
精确比较应使用 RKNHardering 内置详情，或编写同一进程内同时调用 `NetworkInterface` 与 JNI `getifaddrs()` 的测试 APK。Shell 命令无法完全复现应用命名空间。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

部分伪装比完全不伪装更显眼，因为它会制造可观察矛盾。不一致的内核 Hook 可能破坏网络库，并让枚举过程挂起。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**混合。**已根据 `evaluateJvmNativeMismatch()` 核验；VPN 接口仅一侧可见的分支为高置信度，索引/地址差异为中等置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NetworkInterfacePatterns.kt` — 接口名称规则](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- 已根据项目代码核验：[原生信号目录与检查器的单元测试](https://github.com/xtclovver/RKNHardering/tree/main/app/src/test/java/com/notcvnt/rknhardering).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Java NetworkInterface](https://developer.android.com/reference/java/net/NetworkInterface).
- 外部第一方文档或官方项目：[getifaddrs(3)](https://man7.org/linux/man-pages/man3/getifaddrs.3.html).
- 外部第一方文档或官方项目：[VPNHide architecture](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `interface-enumeration`, `getifaddrs-vpn`, `library-integrity`, `trim-oracle`.

[返回原生检查参考](../)
