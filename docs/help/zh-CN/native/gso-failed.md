---
title: "`setsockopt()` 未接受 `UDP_SEGMENT`"
permalink: /help/zh-CN/native/gso-failed/
---

# `setsockopt()` 未接受 `UDP_SEGMENT`

> **ID：** `GSO_FAILED`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针创建 UDP 套接字，并尝试执行 `setsockopt(IPPROTO_UDP, UDP_SEGMENT, 1200)`。失败时生成带 errno 的 `gso_failed`。检查器将其视为低置信度信息，因为缺少 GSO 并不被认为是 VPN 指标。

### 精确触发条件

配置 `UDP_SEGMENT` 时，内核或 libc 返回错误。

## 结果含义

这表示当前套接字、内核或环境不可使用 UDP GSO。结果取决于内核配置和 API 支持，而不仅取决于 VPN。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

判定逻辑不会区分 `ENOPROTOOPT`、`EINVAL`、`EPERM` 等不同原因。Android 内核和厂商 backport 差异很大；检查也没有覆盖物理接口路径。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有多组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。 记录 errno 和内核版本。不要仅因为某项内核功能不可用就修改 VPN。

### 有 root 权限

Root 模块可以改变这一指标，但为了追求某个特定数值进行调优，很容易破坏 TCP/UDP、DNS、通话或功耗表现。VPNHide Next 声称可过滤若干间接参数，但这些能力必须与基础接口隐藏分开测试。在获得干净基线和可用回滚路径之前，不要启用最大范围的内核 Hook。 不要仅为 `UDP_SEGMENT` 加载来源不明的内核模块。支持它需要兼容的内核和网络栈，不是设置一个 Magisk 属性即可获得。

### 如何验证结果

```bash
adb shell uname -a
adb shell zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_INET|CONFIG_UDP' | head -40
```
精确 errno 以 RKNHardering 详情为准。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

仅为 GSO 更换内核可能导致启动循环、模块不兼容和数据丢失。一个信息性信号不足以证明这种风险合理。

### 回滚

恢复原厂 boot/内核镜像，移除实验模块并重启。

## 证据等级

**低。**已根据 `UDP_SEGMENT=1200` 的失败分支核验；该结果仅供参考。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[Linux segmentation offloads](https://docs.kernel.org/networking/segmentation-offloads.html).
- 外部第一方文档或官方项目：[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `gso-send-failed`, `gso-ok`, `normal-pmtu`.

[返回原生检查参考](../)
