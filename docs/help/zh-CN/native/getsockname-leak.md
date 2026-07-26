---
title: "未绑定 UDP 套接字立即获得私有 IPv4 地址"
permalink: /help/zh-CN/native/getsockname-leak/
---

# 未绑定 UDP 套接字立即获得私有 IPv4 地址

> **ID：** `GETSOCKNAME_LEAK`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectGetsocknameLeak()` 创建 `AF_INET/SOCK_DGRAM` 套接字，在没有调用 `bind()` 或 `connect()` 的情况下立即执行 `getsockname()`。若地址不是 0.0.0.0，且位于 10/8、172.16/12 或 192.168/16，则生成包含该 IP 的 `getsockname_leak`。

### 精确触发条件

一个未连接、未绑定的 UDP 套接字在创建后立即具有非零私有 IPv4 地址。

## 结果含义

检查器把这视为异常套接字拦截或环境行为的高置信度指标，因为普通 Linux 套接字通常会保持 0.0.0.0，直到执行 bind 或 connect。私有 IP 本身不能证明它是 VPN 地址。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

“VPN IP 泄漏”这一标签比探针真正证明的内容更强。私有地址可能属于物理 Wi-Fi 或局域网。普通 Android 上通常不会出现该信号；若出现，应复现并调查 Hook 或虚拟化。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

先使用发行版 APK 在干净设备上重复测试。禁用无 root 虚拟化、LSPatch、VPN SDK 和网络沙箱。不要仅为该信号修改局域网地址。

### 有 root 权限

把 RKNHardering 排除在进程内 Zygisk/Xposed Hook 之外，并验证 libc/套接字完整性。不要把私有 IP 替换为公网 IP；在 bind/connect 之前，正确基线是 0.0.0.0。

### 如何验证结果

精确复现可构建一个最小原生测试：
```c
int fd = socket(AF_INET, SOCK_DGRAM, 0);
struct sockaddr_in a = {}; socklen_t n = sizeof(a);
getsockname(fd, (struct sockaddr *)&a, &n);
```
在 `bind/connect` 之前，预期地址为 `0.0.0.0`。`ss` 命令无法复现该探针。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

全局 Hook `getsockname()` 会破坏应用并可能造成网络泄漏。不要修改系统 libc。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**高。**已根据未调用 bind/connect 以及精确的私有地址范围核验；当前检查器将该 `kind` 归为高置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[getsockname(2)](https://man7.org/linux/man-pages/man2/getsockname.2.html).
- 外部第一方文档或官方项目：[ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `so-bindtodevice`, `library-integrity`, `hook-markers`.

[返回原生检查参考](../)
