---
title: "连接到常见 VPN 端口的已建立 TCP 会话"
permalink: /help/zh-CN/native/established-vpn-socket/
---

# 连接到常见 VPN 端口的已建立 TCP 会话

> **ID：** `ESTABLISHED_VPN_SOCKET`
> **类别：** VPN 痕迹与套接字
> **RKNHardering 2.10.0 中的状态：** 已启用的检查
> **在最终判定中的作用：** 中

本页说明 RKNHardering 2.10.0 中的实际实现，并分别指出无需 root 权限即可采取的措施、需要 root 权限的措施，以及哪些缓解方法只能减少单个信号而无法隐藏整个 VPN。

## 检查内容与目的

`detectEstablishedVpn()` 读取 `/proc/net/tcp`，筛选状态 `01`（ESTABLISHED），且远端端口为 51820、1194、1195、443 或 8443 的记录。匹配时生成 `established_vpn`；旧版策略将其作为中等置信度待复核项。

### 精确触发条件

存在一个使用上述五个远端端口之一的已建立 IPv4 TCP 套接字。

## 结果含义

1194 和 1195 类似 OpenVPN 端口，但 443 和 8443 被普通 HTTPS 广泛使用，而 WireGuard 通常在 51820 上使用 UDP。因此该信号刻意不设为高置信度。

**该行如何影响报告：**该行本身不会直接得出最终判定，但会设置 `needsReview=true`，并加入中等置信度证据。

## 限制与可能的误报

检查不会把套接字关联到进程或 VPN 应用，不读取 tcp6，而且可能受到 SELinux 阻止。单纯按端口分类会产生大量误报。

必须把这一行与相邻信号一起评估。单个 API 返回干净结果，并不能同时覆盖 Java Binder、libc、原始 netlink/系统调用、procfs/sysfs、本地套接字以及服务器端指标。

## 针对该向量的建议

### 无 root 权限

修改前先检查远端 IP 和连接所有者。可以停止不需要的 VPN 或 API 进程，但不要封锁 443 端口。使用外部网关可把服务端套接字移出手机。

### 有 root 权限

不要过滤整个 `/proc/net/tcp`，也不要封锁 443。按 UID 隐藏需要正确的套接字/proc 策略，但很容易与 inet_diag 结果不一致。更好的做法是移除真实的本地 VPN 套接字。

### 如何验证结果

```bash
adb shell cat /proc/net/tcp 2>&1 | head -80
adb shell ss -tn 2>/dev/null | grep -E ':(51820|1194|1195|443|8443) '
```
应用的十六进制解析器检查远端端口。

完成任何修改后，请对 RKNHardering 和 VPN 客户端都执行 `force-stop`，重新启动两者并再次进行完整扫描。Zygisk、Xposed 和内核模块通常还需要重启设备。不要只比较这一行，也要检查相邻信号：不完整的 Hook 往往会造成不同 API 之间的结果不一致。

## 所需权限与风险

探针本身以普通应用权限运行，不会请求 root。下方 ADB 命令仅用于辅助定位：`adb shell` 使用不同的 UID，所能看到的内容可能比应用进程更多，也可能更少。决定性测试是在 `force-stop` 后重新运行应用内检查。

### 风险

封锁 443 会破坏绝大多数 HTTPS 流量。发布套接字表前请对 IP 地址进行脱敏。

### 回滚

删除对应的防火墙规则，并重新启动应用或连接。

## 证据等级

**中。**已根据状态判断与 `isVpnPort()` 核验；属于中等置信度待复核项。

第三方方案的状态不能自动套用到当前设备。模块开发者的声明只是初始假设；只有在特定 Android 版本、固件和内核上得到可重复的 RKNHardering 结果，才能视为确认。

## 来源与最后核验日期

- 已根据项目代码核验：[`native_signs_probe.cpp` — 原生探针实现](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/cpp/native_signs_probe.cpp).
- 已根据项目代码核验：[`NativeSignsChecker.kt` — 原生/旧版信号的主要判定逻辑](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/checker/NativeSignsChecker.kt).
- 已根据项目代码核验：[`NativeSignalId.kt` — 完整 ID 目录](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt).
- 已根据项目代码核验：[`NativeSignalCatalog.kt` — 类别、slug 与输出行映射](https://github.com/xtclovver/RKNHardering/blob/main/app/src/main/java/com/notcvnt/rknhardering/NativeSignalCatalog.kt).
- 外部第一方文档或官方项目：[tcp(7)](https://man7.org/linux/man-pages/man7/tcp.7.html).
- 外部第一方文档或官方项目：[/proc/pid/net](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html).
- 实现与链接最后核验日期：**2026 年 7 月 19 日**。

相关信号： `tcp-vpn-port`, `inet-diag-denied`, `host-route`.

[返回原生检查参考](../)
