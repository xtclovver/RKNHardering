---
title: "if_indextoname 与 RTM_GETLINK 的接口数量不一致"
permalink: /help/zh-CN/native/trim-oracle/
---

# if_indextoname 与 RTM_GETLINK 的接口数量不一致

> **ID：** `TRIM_ORACLE`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针分别统计索引 1 到 127 上成功的 `if_indextoname()` 调用次数（`bind_probe`），以及一次完整 `RTM_GETLINK` 转储中的 `RTM_NEWLINK` 消息数。两者不同就报告 `MISMATCH`。该 `kind` 为中等置信度待复核项。

### 精确触发条件

两种独立枚举完成后，`bindCount != rtmCount`。

## 结果含义

这通常表示过滤不完整：某个 API 隐藏了接口，而另一个 API 仍泄漏其索引或条目。也可能是接口索引超过 127、接口创建/删除时的竞态，或不完整的 netlink 转储。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

`bind_probe` 是历史名称；实现实际使用 `if_indextoname()`，而不是 `bind()`。127 的上限可能在接口索引较大的系统上造成误报。快照不是原子的，也不会重复确认。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有两组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。 重复检查数次。若不一致只在切换 Wi-Fi、移动数据或 VPN 时出现，则更可能是竞态，而不是持续的绕过迹象。

### 有 root 权限

实验室级隐藏通常需要系统 Java 层和一个原生后端。使用 VPNHide 时，应安装 APK，让 Vector/LSPosed 只作用于 `System Framework`，并在 kmod、KPM、Zygisk 中只选一个。对于可能直接使用系统调用或 netlink 的检查，优先选择 kmod 或 KPM：用户态 Zygisk Hook 可以被绕过，也会在目标进程中留下痕迹。请先阅读 [VPNHide 覆盖范围表](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)，并只从[官方发布页](https://github.com/okhsunrog/vpnhide/releases/latest)下载构建。VPNHide Next 声称覆盖更广，但也警告可能发生启动循环和内核崩溃，只能在专用测试设备上验证。 必须恢复所有路径的一致性。不要只通过截断转储隐藏 `RTM_NEWLINK`；`if_indextoname()`、`SIOCGIFNAME`、路由和地址必须呈现相容视图。

### 如何验证结果

```bash
adb shell 'ip -o link show | wc -l'
adb shell 'ip -o link show'
```
精确比较需要原生测试工具，在一次 `RTM_GETLINK` 转储后立即遍历 `if_indextoname(1..127)`。在稳定网络下至少重复五次。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

错误过滤多段 netlink 消息可能使转储循环永久阻塞，或破坏系统网络调用。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**中。**已根据双计数算法核验；该 `kind` 为中等置信度，不会设置 `detected`。文档同时记录了 127 上限与竞态条件。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`vpnhide_regression_probe.cpp` — 一致性与 oracle 探针](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/vpnhide_regression_probe.cpp).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[rtnetlink(7)](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).
- 外部第一方文档或官方项目：[if_nametoindex(3)](https://man7.org/linux/man-pages/man3/if_nametoindex.3.html).
- 外部第一方文档或官方项目：[VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `rtm-getlink-vpn`, `ifindexname-vpn`, `vpnhide`.

[返回原生检查参考](../)
