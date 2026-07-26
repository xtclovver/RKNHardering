---
title: "已启用 IPv4 转发"
permalink: /help/zh-CN/native/sysctl-forwarding/
---

# 已启用 IPv4 转发

> **ID：** `SYSCTL_FORWARDING`
> **类别：** 路由与网络栈
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针把 `/proc/sys/net/ipv4/ip_forward` 读取为整数。非零值会生成 `sysctl_forwarding|ip_forward=1`；旧版策略将其作为中等置信度的待复核项。

### 精确触发条件

`ip_forward != 0`。

## 结果含义

路由器、网络共享和基于 root 的 VPN 配置通常会启用转发，但 Android 也可能因热点或系统网络模式而启用它。因此这不是独立的 VPN 指标。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

探针只检查全局 IPv4 键，不检查 IPv6 转发或各接口行为。开启热点时，该值可能发生变化。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

关闭热点或 USB 网络共享后重新测试。普通应用无法修改该 sysctl。若设计本身需要转发，应把此复核项视为对系统状态的准确描述。

### 有 root 权限

不要盲目设置 `ip_forward=0`，这会破坏网络共享以及部分路由器/VPN 转发方案。测试时先记录原值，并只在备用设备上修改。

### 如何验证结果

```bash
adb shell cat /proc/sys/net/ipv4/ip_forward 2>&1
adb shell dumpsys connectivity | grep -i tether -A3 -B2
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

禁用转发会中断网络共享和某些基于 root 的 VPN 设计。

### 回滚

恢复保存的值，或重新启动网络共享/设备，让 Android 应用其正常设置。

## 证据等级

**中。**已根据 `detectSysctl()` 核验；该 `kind` 为中等置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[ip-sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `sysctl-rp-filter`, `route-table`.

[返回原生检查参考](../)
