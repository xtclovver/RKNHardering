---
title: "本地连接上的低 TCP MSS"
permalink: /help/zh-CN/native/tcp-mss-low/
---

# 本地连接上的低 TCP MSS

> **ID：** `TCP_MSS_LOW`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针尝试连接 `127.0.0.1:443`。只有监听器接受连接时，它才读取 `TCP_INFO`，并在 `tcpi_snd_mss > 0 && < 500` 时生成 `tcp_mss_low`。旧版策略把该 `kind` 视为高置信度；本地没有监听器时函数会静默退出。

### 精确触发条件

成功连接 localhost:443，且发送 MSS 低于 500。

## 结果含义

在当前实现中，这是罕见且高度依赖上下文的信号。它更多取决于本地监听器和环回网络栈，而不是实际互联网 PMTU。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

500 的阈值极低，典型 VPN MTU 通常会产生远高于此的 MSS。443 端口关闭时检查根本不会运行；环回 `TCP_INFO` 也不能反映外部隧道路径。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有两组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。 确认 localhost:443 上运行的进程。若监听器不需要，应停止它；不要为了该探针修改系统 MTU。

### 有 root 权限

Root 模块可以改变这一指标，但为了追求某个特定数值进行调优，很容易破坏 TCP/UDP、DNS、通话或功耗表现。VPNHide Next 声称可过滤若干间接参数，但这些能力必须与基础接口隐藏分开测试。在获得干净基线和可用回滚流程之前，不要启用最大范围的内核 Hook。 可以通过用户态或内核 Hook 替换 `TCP_INFO`，但上游 VPNHide 并未声明覆盖这一旧版环回场景；VPNHide Next 声称支持 `TCP_INFO` 与 MSS 过滤。

### 如何验证结果

```bash
adb shell ss -ltn 2>/dev/null | grep '127.0.0.1:443'
adb shell ip link show
```
精确 MSS 测量需要在相同应用上下文中运行测试客户端。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

盲目降低或提高 MTU 可能造成分片、部分网站卡住和通话中断。

### 回滚

恢复原始 MTU 与 MSS 行为，并只停止测试用 localhost 监听器。

## 证据等级

**高。**已根据连接目标、`TCP_INFO` 和 `<500` 阈值核验；旧版 `kind` 为高置信度，但探针只有在存在监听器时才运行。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `pmtu-mss-combined`, `normal-pmtu`, `loopback-port-conflict`.

[返回原生检查参考](../)
