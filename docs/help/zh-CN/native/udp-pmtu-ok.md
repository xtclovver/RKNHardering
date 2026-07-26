---
title: "成功通过 UDP 向 `127.0.0.1:53` 发送 1500 字节"
permalink: /help/zh-CN/native/udp-pmtu-ok/
---

# 成功通过 UDP 向 `127.0.0.1:53` 发送 1500 字节

> **ID：** `UDP_PMTU_OK`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 低

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针创建 UDP 套接字，并向环回 DNS 端口 53 执行一次带 1500 字节缓冲区的 `sendto()`。返回值大于 0 时生成 `udp_pmtu_ok`；不需要接收端或监听器。该行属于低置信度信息。

### 精确触发条件

内核在本地发送路径上接受了一个 1500 字节 UDP 数据报。

## 结果含义

成功只表示环回发送路径接受了该数据报，不会测量外部路由 PMTU、分片情况，也不会证明数据到达 DNS 服务。

**该行如何影响报告：**该行属于信息或诊断数据，适合用于比较多次扫描，但本身不能证明存在 VPN 或篡改。

## 限制与可能的误报

环回 MTU 通常远高于物理接口 MTU。UDP 发送成功不等于送达；“PMTU”标签夸大了这一结果的信息价值。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

对于诊断信号，起初不要尝试“修复”。先在同一设备、未启用 VPN 的状态下记录基线，再在相同网络、温度和负载条件下启用 VPN 重复测试。只有两组结果之间可重复的差异才具有分析价值；单个 MTU、时序或 GSO 数值不能作为证据。

### 有 root 权限

Root 模块可以改变这一指标，但为了追求某个特定数值进行调优，很容易破坏 TCP/UDP、DNS、通话或功耗表现。VPNHide Next 声称可过滤若干间接参数，但这些能力必须与基础接口隐藏分开测试。在获得干净基线和可用回滚流程之前，不要启用最大范围的内核 Hook。 不要仅为改变结果而阻断环回 UDP/53；这会产生 `udp-pmtu-fail`，并可能破坏本地 DNS。

### 如何验证结果

```bash
adb shell ip link show lo
adb shell 'cat /sys/class/net/lo/mtu 2>/dev/null'
```
正常内核上，无论是否存在监听器，都应接受这次发送。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

围绕环回 DNS 的防火墙或 SELinux 实验可能破坏应用的域名解析。

### 回滚

删除临时环回或防火墙规则，然后重启 netd、VPN 或设备。

## 证据等级

**低。**已根据固定的 1500 字节环回发送核验；仅供参考。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html).
- 外部第一方文档或官方项目：[ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `udp-pmtu-fail`, `normal-pmtu`, `backpressure`.

[返回原生检查参考](../)
