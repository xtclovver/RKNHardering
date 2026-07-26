---
title: "原生系统调用/套接字探针不可用"
permalink: /help/zh-CN/native/syscall-unavailable/
---

# 原生系统调用/套接字探针不可用

> **ID：** `SYSCALL_UNAVAILABLE`
> **类别：** 服务状态信号
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 可用性

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

旧版检查器会汇总系统调用组中所有 `unavailable*` 行。当前生成器会输出 `unavailable|ip_recverr|denied` 或 `unavailable|ip_recverr|not_supported`。这些结果以 `SYSCALL_UNAVAILABLE` ID 显示为低置信度信息。

### 精确触发条件

由于 `EACCES`/`EPERM` 或 `ENOPROTOOPT`，探针无法启用 `IP_RECVERR`。

## 结果含义

不可用不表示系统干净，只表示该路径没有产生测量结果；相邻信号的待复核结果仍然有效。

**该行如何影响报告：**该信号表示探针无法执行。`unavailable` 绝不能解释为没有 VPN 的证据。

## 限制与可能的误报

这是聚合 ID，未来版本可能加入新的 unavailable 类型。若没有 errno 或上下文日志，当前详情不足以区分 SELinux 限制与内核缺少功能。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

保持 SELinux enforcing。记录结果是 `denied` 还是 `not_supported`，并一并保存设备型号、Android 版本和内核信息。不要仅为这项诊断获取 root。

### 有 root 权限

查看 AVC 日志与内核兼容性，但不要添加宽泛 allow 规则。测试时可在单独的最小 APK 中复现。

### 如何验证结果

```bash
adb logcat -d | grep -E 'avc: denied|IP_RECVERR' | tail -80
adb shell uname -a
```
shell 套接字中的可用性并不等同于应用域中的可用性。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

针对网络选项添加宽泛 sepolicy 规则会削弱沙箱。`unavailable` 比错误暴露权限更安全。

### 回滚

删除测试 sepolicy 规则或模块并重启。

## 证据等级

**可用性。**已根据 `unavailableSyscalls` 聚合逻辑和当前唯一生成器核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- 外部第一方文档或官方项目：[AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `ip-recverr`, `native-library`.

[返回原生检查参考](../)
