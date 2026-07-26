---
title: "不依赖名称的 ARPHRD_TUNNEL/TUN-TAP 接口类型检查"
permalink: /help/zh-CN/native/tuntap-type/
---

# 不依赖名称的 ARPHRD_TUNNEL/TUN-TAP 接口类型检查

> **ID：** `TUNTAP_TYPE`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

主 `getifaddrs()` 快照完成后，检查器读取每个接口的类型，并与 `ARPHRD_TUNTAP = 65534` 比较。它专门选择类型为 65534、处于活动状态且名称不匹配已知 VPN 模式的接口，因此仅把 `tun0` 重命名为中性名称无法绕过。

### 精确触发条件

满足 `iface.isUp && iface.ifaceType == 65534 && !isVpnInterface(iface.name)` 时，会以高置信度设置 `detected=true`。

## 结果含义

中性名称与 TUN/TAP 类型组合在一起，会被视为强不一致。只重命名接口不足以通过该检查。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

某些驱动或 OEM 组件可能为合法虚拟接口使用非常规 ARP 硬件类型。应结合 `/sys/class/net/<iface>/type`、接口用途和活动路由进行判断。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

最可靠的无 root 方案，是不要在被测试的手机上创建 VPN 接口：把隧道移到路由器、旅行路由器、单独的网关手机或其他网络节点。`VpnService` 的按应用绕过只会改变所选应用使用的路由，但 `establish()` 仍会创建系统 VPN 接口，因此本地接口检查仍可能触发。不使用 TUN 的本地 HTTP/SOCKS 代理模式有时能消除这一特定向量，但会留下监听端口和代理设置，而且无法覆盖忽略代理的应用。 只改接口名称而不改变其类型没有作用。无 root 权限时，应用无法修改内核为另一个接口报告的类型。

### 有 root 权限

实验室级隐藏通常需要系统 Java 层和一个原生后端。使用 VPNHide 时，应安装 APK，让 Vector/LSPosed 只作用于 `System Framework`，并在 kmod、KPM、Zygisk 中只选一个。对于可能直接使用系统调用或 netlink 的检查，优先选择 kmod/KPM：用户态 Zygisk Hook 可以被绕过，也会在进程中留下痕迹。请先阅读 [VPNHide 覆盖范围表](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)，并只从[官方发布页](https://github.com/okhsunrog/vpnhide/releases/latest)下载构建。VPNHide Next 声称覆盖更广，但也警告可能发生启动循环和内核崩溃，只能在测试设备上验证。 后端必须隐藏接口本身，或在所有路径中一致替换接口类型；只过滤名称并不足够。

### 如何验证结果

```bash
adb shell 'for i in /sys/class/net/*; do printf "%s type=" "${i##*/}"; cat "$i/type" 2>/dev/null; done'
adb shell ip -details link show
```
根据详情定位接口，并确认其值是否为 `65534`。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

在内核中替换类型会影响网络栈，并可能使 VPN 失效。不要直接修改 sysfs 文件；它只是内核状态的表示，并非普通设置。

### 回滚

撤销最近一次修改：通过对应管理器禁用新增模块或规则，重启设备，然后重新进行基线扫描。不要在状态不明的情况下继续叠加新的 Hook。

## 证据等级

**高。**已直接根据 `NativeSignsChecker` 中的 `ARPHRD_TUNTAP` 条件核验。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NetworkInterfacePatterns.kt` — 接口名称规则](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/network/NetworkInterfacePatterns.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[netdevice(7)](https://man7.org/linux/man-pages/man7/netdevice.7.html).
- 外部第一方文档或官方项目：[Android VpnService](https://developer.android.com/reference/android/net/VpnService).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `interface-enumeration`, `sysclassnet-vpn`, `sysfs-vpn-leak`.

[返回原生检查参考](../)
