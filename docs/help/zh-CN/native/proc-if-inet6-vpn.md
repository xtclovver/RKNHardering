---
title: "`/proc/net/if_inet6` 中的 VPN 接口"
permalink: /help/zh-CN/native/proc-if-inet6-vpn/
---

# `/proc/net/if_inet6` 中的 VPN 接口

> **ID：** `PROC_IF_INET6_VPN`
> **类别：** 网络接口
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 高

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

探针会检查 `/proc/net/if_inet6` 和 `/proc/self/net/if_inet6`。每一行被拆分为六个字段，第六个字段视为接口名称。它统计 `tun0`、`tun1`、`utun0`、`wg0`、`ppp0` 和 `xfrm0`；函数在找到第一个可访问且含匹配项的文件后停止。

### 精确触发条件

IPv6 接口表中出现一个或多个使用固定 VPN 接口名称的条目。

## 结果含义

某个 VPN 风格网络设备拥有 IPv6 地址，并可通过 procfs 看到。即使主要流量使用 IPv4，这仍是直接痕迹。

**该行如何影响报告：**该行会设置 `detected=true`，并被视为高置信度的本地指标。

## 限制与可能的误报

没有 IPv6 地址的接口不会出现在这里。procfs 是否可访问取决于 Android 版本和 SELinux 策略。名称列表较窄，同一接口拥有多个地址时会增加计数。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

最可靠的无 root 方案，是不要在被测试的手机上创建 VPN 接口：把隧道移到路由器、旅行路由器、单独的网关手机或其他网络节点。`VpnService` 的按应用绕过只会改变所选应用使用的路由，但 `establish()` 仍会创建系统 VPN 接口，因此本地接口检查仍可能触发。不使用 TUN 的本地 HTTP/SOCKS 代理模式有时能消除这一特定向量，但会留下监听端口和代理设置，而且无法覆盖忽略代理的应用。 在 VPN 内禁用 IPv6 可能消除这一特定行，但会降低连接能力，也无法通过 IPv4 或 netlink 隐藏该接口，因此不属于完整绕过。

### 有 root 权限

实验室级隐藏通常需要系统 Java 层和一个原生后端。使用 VPNHide 时，应安装 APK，让 Vector/LSPosed 只作用于 `System Framework`，并在 kmod、KPM、Zygisk 中只选一个。对于可能直接使用系统调用或 netlink 的检查，优先选择 kmod 或 KPM；用户态 Zygisk Hook 可以被绕过，也会在进程中留下痕迹。先查看 [VPNHide 覆盖范围表](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md)，并只从[官方发布页](https://github.com/okhsunrog/vpnhide/releases/latest)下载。VPNHide Next 声称覆盖更广，但也警告可能发生启动循环和内核崩溃，只能在专用测试设备上验证。在上游文档所记录的时间点，VPNHide 把 `/proc/net/if_inet6` 列为内核后端仍需 Zygisk 才能覆盖的缺口。不要只依据模块名称，应检查当前版本和具体后端。

### 如何验证结果

```bash
adb shell 'cat /proc/net/if_inet6 2>/dev/null || cat /proc/self/net/if_inet6 2>/dev/null'
adb shell 'ip -6 addr show'
```

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

全局禁用 IPv6 会破坏纯 IPv6 与 NAT64 网络、DNS64 以及部分移动网络连接。不要把它作为第一步。

### 回滚

恢复 VPN 和系统的 IPv6 设置，删除定向过滤规则并重启。分别测试移动数据和 Wi-Fi。

## 证据等级

**高。**已根据两个读取路径、解析字段 `[5]` 以及六个固定名称核验；该 `kind` 为高置信度。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`VpnNativeDetectorChecker.kt` — 深度 VPN 检测的判定与置信度](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/VpnNativeDetectorChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[/proc/net documentation](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- 外部第一方文档或官方项目：[VPNHide coverage gaps](https://github.com/okhsunrog/vpnhide/blob/main/docs/detection-vectors.md).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `proc-ipv6-route-vpn`, `getifaddrs-vpn`, `sysfs-vpn-leak`.

[返回原生检查参考](../)
