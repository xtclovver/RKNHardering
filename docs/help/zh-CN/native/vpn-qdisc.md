---
title: "历史上名为 qdisc 的 tun0/wg0 流量计数检查"
permalink: /help/zh-CN/native/vpn-qdisc/
---

# 历史上名为 qdisc 的 tun0/wg0 流量计数检查

> **ID：** `VPN_QDISC`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

尽管名称如此，`detectQdisc()` 并不查询 qdisc 状态。它读取 `/proc/net/dev`，解析 RX/TX 字节与数据包计数，并且只对精确名称 `tun0` 和 `wg0` 生成 `vpn_qdisc`。旧版策略把该行视为中等置信度 review。

### 精确触发条件

`/proc/net/dev` 中存在 `tun0` 或 `wg0`；流量计数可以为零。

## 结果含义

这是另一种 procfs 接口泄漏，而不是数据包调度器分析。当前深度检测流水线实际上没有独立的真实 qdisc 状态生成器。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

名称是历史遗留且可能误导。只检查两个接口名称，并且只有 procfs 可访问时才生效。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

最可靠的无 root 方案，是不要在被测试的手机上创建 VPN 接口：把隧道移到路由器、旅行路由器、单独的网关手机或其他网络节点。`VpnService` 的按应用绕过只会改变所选应用使用的路由，但 `establish()` 仍会创建系统 VPN 接口，因此本地接口检查仍可能触发。不使用 TUN 的本地 HTTP/SOCKS 代理模式有时能消除这一特定向量，但会留下监听端口和代理设置，而且无法覆盖忽略代理的应用。

### 有 root 权限

实验室级隐藏通常需要系统 Java 层和一个原生后端。使用 VPNHide 时，应安装 APK，让 Vector/LSPosed 只作用于 `System Framework`，并在 kmod、KPM、Zygisk 中只选一个。对于可能直接使用系统调用或 netlink 的检查，优先选择 kmod 或 KPM：用户态 Zygisk Hook 可以被绕过，也会在目标进程中留下痕迹。请先阅读 [VPNHide 覆盖范围表](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)，并只从[官方发布页](https://github.com/okhsunrog/vpnhide/releases/latest)下载构建。VPNHide Next 声称覆盖更广，但也警告可能发生启动循环和内核崩溃，只能在专用测试设备上验证。 `/proc/net/dev` 需要独立于 netlink 进行过滤。上游 VPNHide 并未声明其内核后端完整覆盖该文件；VPNHide Next 声称扩展了 proc/qdisc 层。

### 如何验证结果

```bash
adb shell cat /proc/net/dev 2>&1 | grep -E '(^|:)[[:space:]]*(tun0|wg0):'
adb shell tc qdisc show 2>/dev/null
```
第二条命令用于说明：真实 qdisc 状态属于另一套数据面。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

不要无必要地清零真实计数器或修改 qdisc 设置；这会影响 QoS 和延迟。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**中。**已根据 `/proc/net/dev` 解析器核验；本页明确纠正了历史名称造成的误解。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- 外部第一方文档或官方项目：[Linux traffic control](https://man7.org/linux/man-pages/man8/tc.8.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `proc-net-dev-vpn`, `deep-vpn-qdisc`.

[返回原生检查参考](../)
