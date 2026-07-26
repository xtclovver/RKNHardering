---
title: "可通过 sysfs 与 proc/sys 访问的 VPN 接口"
permalink: /help/zh-CN/native/sysfs-vpn-leak/
---

# 可通过 sysfs 与 proc/sys 访问的 VPN 接口

> **ID：** `SYSFS_VPN_LEAK`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectSysfsLeak()` 不会枚举整个目录，而是针对固定名称 `tun0`、`tun1`、`utun0`、`wg0`、`ppp0` 和 `xfrm0` 调用 `stat()`。它检查 `/sys/class/net`、`/sys/devices/virtual/net`，以及 `/proc/sys/net/{ipv4,ipv6}/{conf,neigh}` 分支，并把所有存在的路径合并到一条 `sysfs_vpn_leak` 记录。

### 精确触发条件

36 个固定路径中至少有一个存在，并且应用进程可通过 `stat()` 访问。

## 结果含义

这直接确认了一个具有典型 VPN 名称的内核对象仍可通过网络文件系统视图看到。该行置信度高，但它确认的是接口名称，并不能证明 RKNHardering 的流量一定经过该接口。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

名称列表有意保持较窄。重命名接口可能在这里漏检，但仍可能被主匹配器、类型 65534、netlink、ifindex oracle 或路由检查发现。在启用 SELinux 的原生 Android 上，部分路径可能不可访问；没有这一行只表示当前路径未提供访问。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

最可靠的无 root 方案，是不要在被测试的手机上创建 VPN 接口：把隧道移到路由器、旅行路由器、单独的网关手机或其他网络节点。`VpnService` 的按应用绕过只会改变所选应用使用的路由，但 `establish()` 仍会创建系统 VPN 接口，因此本地接口检查仍可能触发。不使用 TUN 的本地 HTTP/SOCKS 代理模式有时能消除这一特定向量，但会留下监听端口和代理设置，而且无法覆盖忽略代理的应用。 清缓存、使用 Private Space 或配置按应用绕过，都不会从共享内核命名空间中删除 `/sys/class/net/<iface>`。外部网关是唯一能真正避免在手机上创建该对象的无 root 方案。

### 有 root 权限

实验室级隐藏通常需要系统 Java 层和一个原生后端。使用 VPNHide 时，应安装 APK，让 Vector/LSPosed 只作用于 `System Framework`，并在 kmod、KPM、Zygisk 中只选一个。对于可能直接使用系统调用或 netlink 的检查，优先选择 kmod 或 KPM：用户态 Zygisk Hook 可以被绕过，也会在目标进程中留下痕迹。请先阅读 [VPNHide 覆盖范围表](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)，并只从[官方发布页](https://github.com/okhsunrog/vpnhide/releases/latest)下载构建。VPNHide Next 声称覆盖更广，但也警告可能发生启动循环和内核崩溃，只能在专用测试设备上验证。 对此向量，后端必须一致过滤 lookup、`stat()` 和 `readdir()`，或者一致隐藏网络设备本身。上游 VPNHide 把 `/sys/class/net` 记录为通常由 SELinux 遮蔽的覆盖缺口；VPNHide Next 在最高级别声称提供文件系统级隐藏，但必须在具体 ROM 上验证。

### 如何验证结果

```bash
adb shell 'for b in /sys/class/net /sys/devices/virtual/net /proc/sys/net/ipv4/conf /proc/sys/net/ipv6/conf /proc/sys/net/ipv4/neigh /proc/sys/net/ipv6/neigh; do for n in tun0 tun1 utun0 wg0 ppp0 xfrm0; do [ -e "$b/$n" ] && echo "$b/$n"; done; done'
```
该命令以 shell UID 运行。评估目标 UID 时应以 RKNHardering 的详情为准；修改后请 `force-stop` 并重新启动应用。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

全局隐藏 `/sys` 或 `/proc/sys/net` 会破坏诊断，并可能影响系统服务。有缺陷的内核 Hook 可能造成启动循环或内核崩溃。

### 回滚

从 recovery 或安全模式禁用模块，恢复原始 boot 镜像并重启。不要把 SELinux permissive 当作“临时解决方案”长期保留。

## 证据等级

**高。**已根据 `detectSysfsLeak()` 中六个名称、两个 sysfs 基础路径和四个 proc/sys 基础路径核验；该 `kind` 被列入 `HIGH_CONFIDENCE`。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 外部第一方文档或官方项目：[Linux sysfs networking ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net).
- 外部第一方文档或官方项目：[AOSP SELinux](https://source.android.com/docs/security/features/selinux).
- 外部第一方文档或官方项目：[VPNHide coverage](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 外部第一方文档或官方项目：[VPNHide Next](https://github.com/soranerai/vpnhide_next).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `sysclassnet-vpn`, `getifaddrs-vpn`, `tuntap-type`, `ifindexname-vpn`.

[返回原生检查参考](../)
