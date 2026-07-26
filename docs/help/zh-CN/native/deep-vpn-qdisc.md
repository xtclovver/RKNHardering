---
title: "保留的深度 qdisc 检测 ID"
permalink: /help/zh-CN/native/deep-vpn-qdisc/
---

# 保留的深度 qdisc 检测 ID

> **ID：** `DEEP_VPN_QDISC`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 为兼容性保留该 ID；2.10.0 中没有独立的信号生成器
> **在最终判定中的作用：** 目录项/兼容性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

信号目录中的 `fromDeepVpnKind("vpn_qdisc")` 映射会把该行归到 `DEEP_VPN_QDISC`，但当前 `nativeDetectVpnDetector()` 并未调用生成 `vpn_qdisc` 的函数。启用中的生成器只存在于旧版 `nativeDetectVpnAdvanced()` 路径，其行为记录在 `vpn-qdisc` 页面。

### 精确触发条件

当前深度检测流水线没有独立触发条件。只有未来 `nativeDetectVpnDetector()` 开始返回 `vpn_qdisc`，或原生桥接层发生变化时，这个 ID 才可能出现。

## 结果含义

通常只能从信号目录进入本页，运行时不会产生这个 ID 的结果。没有深度检测 ID，并不能证明 qdisc 状态或接口计数器已经被隐藏。

**该行如何影响报告：**该 ID 仍保留在信号目录和 UI 中，但 2.10.0 不会生成这一类型的独立阳性行；通常由更具体的相邻信号覆盖。

## 限制与可能的误报

旧版生成器中的 `qdisc` 命名同样不够准确：当前函数读取的是 `/proc/net/dev` 中 tun0/wg0 的 RX/TX 数值，而不是通过 rtnetlink TC 查询 qdisc 状态。两个页面都明确说明了这一差别。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

不要为一个未启用的 ID 修改任何设置。实际信号请参阅 `vpn-qdisc` 和 `proc-net-dev-vpn`。

### 有 root 权限

不要仅为了一个空的目录项安装内核模块。若要新增真正的 qdisc 检测，应先定义 `RTM_GETQDISC`/TC 的语义，并建立独立的误报模型。

### 如何验证结果

```bash
rg -n 'detectQdisc|nativeDetectVpnDetector|nativeDetectVpnAdvanced|"vpn_qdisc"' app/src/main/cpp/native_signs_probe.cpp app/src/main/java/com/notcvnt/rknhardering
```
确认该调用确实只缺失于整合后的深度检测函数。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

试图在全局隐藏流量控制状态，可能破坏整形、QoS 和 NetworkStack。在真正存在信号生成器之前，这里没有需要修复的内容。

### 回滚

如果你曾为实验接入该调用，只需撤销流水线与测试代码的改动；无需修改设备。

## 证据等级

**目录项/兼容性。**已根据 JNI 函数调用列表和信号目录映射核验；当前仅属于目录登记状态。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Linux traffic control netlink](https://man7.org/linux/man-pages/man8/tc.8.html).
- 外部第一方文档或官方项目：[VPNHide Next](https://github.com/soranerai/vpnhide_next).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `vpn-qdisc`, `proc-net-dev-vpn`, `route-count`.

[返回原生检查参考](../)
